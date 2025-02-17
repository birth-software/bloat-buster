const std = @import("std");

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

pub fn build(b: *std.Build) !void {
    const ci = b.option(bool, "ci", "");
    _ = &ci;
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    var llvm_libs = std.ArrayList([]const u8).init(b.allocator);
    {
        const llvm_components_result = try run_process_and_capture_stdout(b, &.{ "llvm-config", "--components" });
        var it = std.mem.splitScalar(u8, llvm_components_result, ' ');
        var args = std.ArrayList([]const u8).init(b.allocator);
        try args.append("llvm-config");
        try args.append("--libs");
        while (it.next()) |component| {
            try args.append(std.mem.trim(u8, component, "\n"));
        }
        const llvm_libs_result = try run_process_and_capture_stdout(b, args.items);
        it = std.mem.splitScalar(u8, llvm_libs_result, ' ');

        while (it.next()) |component| {
            const llvm_lib = std.mem.trim(u8, std.mem.trim(u8, component, "\n"), "-l");
            try llvm_libs.append(llvm_lib);
        }
    }

    const exe = b.addExecutable(.{
        .name = "bloat-buster",
        .root_module = exe_mod,
    });
    exe.linkLibC();
    for (llvm_libs.items) |llvm_lib| {
        exe.linkSystemLibrary(llvm_lib);
    }

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
    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_unit_tests.step);
}
