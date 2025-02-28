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

const CmakeBuildType = enum {
    Debug,
    RelWithDebInfo,
    MinSizeRel,
    Release,

    fn from_zig_build_type(o: std.builtin.OptimizeMode) CmakeBuildType {
        return switch (o) {
            .Debug => .Debug,
            .ReleaseSafe => .RelWithDebInfo,
            .ReleaseSmall => .MinSizeRel,
            .ReleaseFast => .Release,
        };
    }
};

const LLVM = struct {
    module: *std.Build.Module,

    fn setup(b: *std.Build, path: []const u8) !LLVM {
        var llvm_libs = std.ArrayList([]const u8).init(b.allocator);
        var flags = std.ArrayList([]const u8).init(b.allocator);
        const llvm_config_path = if (b.option([]const u8, "llvm_prefix", "LLVM prefix")) |llvm_prefix| blk: {
            const full_path = try std.mem.concat(b.allocator, u8, &.{ llvm_prefix, "/bin/llvm-config" });
            const f = std.fs.cwd().openFile(full_path, .{}) catch return error.llvm_not_found;
            f.close();
            break :blk full_path;
        } else if (system_llvm) executable_find_in_path(b.allocator, "llvm-config", path) orelse return error.llvm_not_found else blk: {
            const home_env = switch (@import("builtin").os.tag) {
                .windows => "USERPROFILE",
                else => "HOME",
            };
            const home_path = env.get(home_env) orelse unreachable;
            const download_dir = try std.mem.concat(b.allocator, u8, &.{ home_path, "/Downloads" });
            std.fs.makeDirAbsolute(download_dir) catch {};
            const llvm_base = try std.mem.concat(b.allocator, u8, &.{ "llvm-", @tagName(target.result.cpu.arch), "-", @tagName(target.result.os.tag), "-", @tagName(CmakeBuildType.from_zig_build_type(optimize)) });
            const base = try std.mem.concat(b.allocator, u8, &.{ download_dir, "/", llvm_base });
            const full_path = try std.mem.concat(b.allocator, u8, &.{ base, "/bin/llvm-config" });

            const f = std.fs.cwd().openFile(full_path, .{}) catch {
                const url = try std.mem.concat(b.allocator, u8, &.{ "https://github.com/birth-software/llvm/releases/download/v19.1.7/", llvm_base, ".7z" });
                var result = try std.process.Child.run(.{
                    .allocator = b.allocator,
                    .argv = &.{ "wget", "-P", download_dir, url },
                    .max_output_bytes = std.math.maxInt(usize),
                });
                var success = false;
                switch (result.term) {
                    .Exited => |exit_code| {
                        success = exit_code == 0;
                    },
                    else => {},
                }

                if (!success) {
                    std.debug.print("{s}\n{s}\n", .{ result.stdout, result.stderr });
                }

                if (success) {
                    const file_7z = try std.mem.concat(b.allocator, u8, &.{ base, ".7z" });
                    result = try std.process.Child.run(.{
                        .allocator = b.allocator,
                        .argv = &.{ "7z", "x", try std.mem.concat(b.allocator, u8, &.{ "-o", download_dir }), file_7z },
                        .max_output_bytes = std.math.maxInt(usize),
                    });
                    success = false;
                    switch (result.term) {
                        .Exited => |exit_code| {
                            success = exit_code == 0;
                        },
                        else => {},
                    }

                    if (!success) {
                        std.debug.print("{s}\n{s}\n", .{ result.stdout, result.stderr });
                    }

                    break :blk full_path;
                }

                return error.llvm_not_found;
            };

            f.close();
            break :blk full_path;
        };
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
            .sanitize_c = false,
        });

        llvm.addLibraryPath(.{ .cwd_relative = llvm_lib_dir });

        const a = std.fs.cwd().openDir("/usr/lib/x86_64-linux-gnu/", .{});
        if (a) |_| {
            var dir = a catch unreachable;
            dir.close();
            llvm.addLibraryPath(.{ .cwd_relative = "/usr/lib/x86_64-linux-gnu/" });
        } else |err| {
            err catch {};
        }

        llvm.addCSourceFiles(.{
            .files = &.{"src/llvm.cpp"},
            .flags = flags.items,
        });

        var dir = try std.fs.cwd().openDir("/usr/include/c++", .{
            .iterate = true,
        });
        var iterator = dir.iterate();
        const gcc_version = while (try iterator.next()) |entry| {
            if (entry.kind == .directory) {
                break entry.name;
            }
        } else return error.include_cpp_dir_not_found;
        dir.close();
        const general_cpp_include_dir = try std.mem.concat(b.allocator, u8, &.{ "/usr/include/c++/", gcc_version });
        llvm.addIncludePath(.{ .cwd_relative = general_cpp_include_dir });

        {
            const arch_cpp_include_dir = try std.mem.concat(b.allocator, u8, &.{ general_cpp_include_dir, "/x86_64-pc-linux-gnu" });
            const d2 = std.fs.cwd().openDir(arch_cpp_include_dir, .{});
            if (d2) |_| {
                var d = d2 catch unreachable;
                d.close();
                llvm.addIncludePath(.{ .cwd_relative = arch_cpp_include_dir });
            } else |err| err catch {};
        }

        {
            const arch_cpp_include_dir = try std.mem.concat(b.allocator, u8, &.{ "/usr/include/x86_64-linux-gnu/c++/", gcc_version });
            const d2 = std.fs.cwd().openDir(arch_cpp_include_dir, .{});
            if (d2) |_| {
                var d = d2 catch unreachable;
                d.close();
                llvm.addIncludePath(.{ .cwd_relative = arch_cpp_include_dir });
            } else |err| err catch {};
        }

        var found_libcpp = false;

        if (std.fs.cwd().openFile("/usr/lib/libstdc++.so.6", .{})) |file| {
            file.close();
            found_libcpp = true;
            llvm.addObjectFile(.{ .cwd_relative = "/usr/lib/libstdc++.so.6" });
        } else |err| {
            err catch {};
        }

        if (std.fs.cwd().openFile("/usr/lib/x86_64-linux-gnu/libstdc++.so.6", .{})) |file| {
            file.close();
            found_libcpp = true;
            llvm.addObjectFile(.{ .cwd_relative = "/usr/lib/x86_64-linux-gnu/libstdc++.so.6" });
        } else |err| {
            err catch {};
        }

        if (!found_libcpp) {
            return error.libcpp_not_found;
        }

        const needed_libraries: []const []const u8 = &.{ "unwind", "z", "zstd" };

        const lld_libs: []const []const u8 = &.{ "lldCommon", "lldCOFF", "lldELF", "lldMachO", "lldMinGW", "lldWasm" };

        for (needed_libraries) |lib| {
            llvm.linkSystemLibrary(lib, .{});
        }

        for (llvm_libs.items) |lib| {
            llvm.linkSystemLibrary(lib, .{});
        }

        for (lld_libs) |lib| {
            llvm.linkSystemLibrary(lib, .{});
        }

        return LLVM{
            .module = llvm,
        };
    }

    fn link(llvm: LLVM, compile: *std.Build.Step.Compile) void {
        if (compile.root_module != llvm.module) {
            compile.root_module.addImport("llvm", llvm.module);
        } else {
            // TODO: should we allow this case?
            unreachable;
        }
    }
};

fn debug_binary(b: *std.Build, exe: *std.Build.Step.Compile) *std.Build.Step.Run {
    const run_step = std.Build.Step.Run.create(b, b.fmt("debug {s}", .{exe.name}));
    run_step.addArg("gdb");
    run_step.addArg("-ex");
    run_step.addArg("r");
    if (b.args) |args| {
        run_step.addArg("--args");
        run_step.addArtifactArg(exe);
        run_step.addArgs(args);
    } else {
        run_step.addArtifactArg(exe);
    }

    return run_step;
}

var system_llvm: bool = undefined;
var target: std.Build.ResolvedTarget = undefined;
var optimize: std.builtin.OptimizeMode = undefined;
var env: std.process.EnvMap = undefined;

const BuildMode = enum {
    debug_none,
    debug_fast,
    debug_size,
    soft_optimize,
    optimize_for_speed,
    optimize_for_size,
    aggressively_optimize_for_speed,
    aggressively_optimize_for_size,
};

pub fn build(b: *std.Build) !void {
    env = try std.process.getEnvMap(b.allocator);
    target = b.standardTargetOptions(.{});
    optimize = b.standardOptimizeOption(.{});
    system_llvm = b.option(bool, "system_llvm", "Link against system LLVM libraries") orelse true;
    const path = env.get("PATH") orelse unreachable;

    const c_abi = b.addObject(.{
        .name = "c_abi",
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    c_abi.addCSourceFiles(.{
        .files = &.{"src/c_abi.c"},
        .flags = &.{"-g"},
    });

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .sanitize_c = false,
    });
    const configuration = b.addOptions();
    configuration.addOptionPath("c_abi_object_path", c_abi.getEmittedBin());
    exe_mod.addOptions("configuration", configuration);

    const llvm = try LLVM.setup(b, path);

    const exe = b.addExecutable(.{
        .name = "bloat-buster",
        .root_module = exe_mod,
        .link_libc = true,
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

    const debug_cmd = debug_binary(b, exe);
    const debug_step = b.step("debug", "Debug the app");
    debug_step.dependOn(&debug_cmd.step);

    const exe_unit_tests = b.addTest(.{
        .root_module = exe_mod,
    });
    exe_unit_tests.linkLibC();

    llvm.link(exe);

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_unit_tests.step);

    const debug_test_cmd = debug_binary(b, exe_unit_tests);
    const debug_test_step = b.step("debug_test", "Debug the tests");
    debug_test_step.dependOn(&debug_test_cmd.step);
}
