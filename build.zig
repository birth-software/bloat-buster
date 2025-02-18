const std = @import("std");
const builtin = @import("builtin");

fn run_process_and_capture_stdout(b: *std.Build, argv: []const []const u8) ![]const u8 {
    const result = std.process.Child.run(.{
        .allocator = b.allocator,
        .argv = argv,
    }) catch |err| return err;
    switch (result.term) {
        .Exited => |exit_code| {
            if (exit_code != 0) {
                return error.SpawnError;
            }
        },
        else => return error.SpawnError,
    }

    return result.stdout;
}

fn file_find_in_path(allocator: std.mem.Allocator, file_name: []const u8, path_env: []const u8, extension: []const u8) ?[]const u8 {
    const path_env_separator = switch (builtin.os.tag) {
        .windows => ';',
        else => ':',
    };
    const path_separator = switch (builtin.os.tag) {
        .windows => '\\',
        else => '/',
    };
    var env_it = std.mem.splitScalar(u8, path_env, path_env_separator);
    const result: ?[]const u8 = while (env_it.next()) |dir_path| {
        const full_path = std.mem.concatWithSentinel(allocator, u8, &.{ dir_path, &[1]u8{path_separator}, file_name, extension }, 0) catch unreachable;
        const file = std.fs.cwd().openFile(full_path, .{}) catch continue;
        file.close();
        break full_path;
    } else null;
    return result;
}

fn executable_find_in_path(allocator: std.mem.Allocator, file_name: []const u8, path_env: []const u8) ?[]const u8 {
    const extension = switch (builtin.os.tag) {
        .windows => ".exe",
        else => "",
    };
    return file_find_in_path(allocator, file_name, path_env, extension);
}

const LLVM = struct {
    module: *std.Build.Module,

    fn setup(b: *std.Build, path: []const u8, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) !LLVM {
        var llvm_libs = std.ArrayList([]const u8).init(b.allocator);
        var flags = std.ArrayList([]const u8).init(b.allocator);
        const llvm_config_path = if (b.option([]const u8, "llvm_prefix", "LLVM prefix")) |llvm_prefix| blk: {
            const full_path = try std.mem.concat(b.allocator, u8, &.{ llvm_prefix, "/bin/llvm-config" });
            const f = std.fs.cwd().openFile(full_path, .{}) catch return error.llvm_not_found;
            f.close();
            break :blk full_path;
        } else executable_find_in_path(b.allocator, "llvm-config", path) orelse return error.llvm_not_found;
        const llvm_components_result = try run_process_and_capture_stdout(b, &.{ llvm_config_path, "--components" });
        var it = std.mem.splitScalar(u8, llvm_components_result, ' ');
        var args = std.ArrayList([]const u8).init(b.allocator);
        try args.append(llvm_config_path);
        try args.append("--libs");
        while (it.next()) |component| {
            try args.append(std.mem.trimRight(u8, component, "\n"));
        }
        const llvm_libs_result = try run_process_and_capture_stdout(b, args.items);
        it = std.mem.splitScalar(u8, llvm_libs_result, ' ');

        while (it.next()) |lib| {
            const llvm_lib = std.mem.trimLeft(u8, std.mem.trimRight(u8, lib, "\n"), "-l");
            try llvm_libs.append(llvm_lib);
        }

        const llvm_cxx_flags_result = try run_process_and_capture_stdout(b, &.{ llvm_config_path, "--cxxflags" });
        it = std.mem.splitScalar(u8, llvm_cxx_flags_result, ' ');
        while (it.next()) |flag| {
            const llvm_cxx_flag = std.mem.trimRight(u8, flag, "\n");
            try flags.append(llvm_cxx_flag);
        }

        const llvm_lib_dir = std.mem.trimRight(u8, try run_process_and_capture_stdout(b, &.{ llvm_config_path, "--libdir" }), "\n");

        if (optimize != .ReleaseSmall) {
            try flags.append("-g");
        }

        try flags.append("-fno-rtti");

        const llvm = b.createModule(.{
            .target = target,
            .optimize = optimize,
        });

        llvm.addLibraryPath(.{ .cwd_relative = llvm_lib_dir });

        llvm.addCSourceFiles(.{
            .files = &.{"src/llvm.cpp"},
            .flags = flags.items,
        });
        llvm.addIncludePath(.{ .cwd_relative = "/usr/bin/../lib64/gcc/x86_64-pc-linux-gnu/14.2.1/../../../../include/c++/14.2.1" });
        llvm.addIncludePath(.{ .cwd_relative = "/usr/bin/../lib64/gcc/x86_64-pc-linux-gnu/14.2.1/../../../../include/c++/14.2.1/x86_64-pc-linux-gnu" });

        llvm.addObjectFile(.{ .cwd_relative = "/usr/lib/libstdc++.so.6" });
        llvm.linkSystemLibrary("unwind", .{});
        llvm.linkSystemLibrary("z", .{});

        for (llvm_libs.items) |llvm_lib| {
            llvm.linkSystemLibrary(llvm_lib, .{});
        }

        return LLVM{
            .module = llvm,
        };
    }

    fn link(llvm: LLVM, target: *std.Build.Step.Compile) void {
        if (target.root_module != llvm.module) {
            target.root_module.addImport("llvm", llvm.module);
        }
    }
};

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const env = try std.process.getEnvMap(b.allocator);
    const path = env.get("PATH") orelse unreachable;

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const llvm = try LLVM.setup(b, path, target, optimize);

    const exe = b.addExecutable(.{
        .name = "bloat-buster",
        .root_module = exe_mod,
    });

    llvm.link(exe);

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const exe_unit_tests = b.addTest(.{
        .root_module = exe_mod,
    });
    llvm.link(exe_unit_tests);
    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_unit_tests.step);
}
