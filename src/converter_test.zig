const lib = @import("lib.zig");
const assert = lib.assert;
const std = @import("std");

const converter = @import("converter.zig");
const BuildMode = converter.BuildMode;

fn invoke(name: []const u8) !void {
    if (!lib.GlobalState.initialized) {
        lib.GlobalState.initialize();
    }

    comptime assert(lib.is_test);
    const allocator = std.testing.allocator;

    inline for (@typeInfo(BuildMode).@"enum".fields) |f| {
        const build_mode = @field(BuildMode, f.name);
        inline for ([2]bool{ false, true }) |has_debug_info| {
            var tmp_dir = std.testing.tmpDir(.{});
            defer tmp_dir.cleanup();
            const base_path = lib.global.arena.join_string(&.{ ".zig-cache/tmp/", &tmp_dir.sub_path, "/", name });
            const executable_path = base_path;
            invoke_wrapper(.{
                .object_path = lib.global.arena.join_string(&.{ base_path, ".o" }),
                .executable_path = executable_path,
                .file_path = lib.global.arena.join_string(&.{ "tests/", name, ".bbb" }),
                .name = name,
            }, build_mode, has_debug_info);
            const run_result = std.process.Child.run(.{
                .allocator = allocator,
                .argv = &.{executable_path},
            }) catch |err| {
                std.debug.print("error: {}\n", .{err});
                const path = lib.global.arena.join_string(&.{ ".zig-cache/tmp/", &tmp_dir.sub_path });
                const r = try std.process.Child.run(.{
                    .allocator = allocator,
                    .argv = &.{ "/usr/bin/ls", "-lasR", path },
                    .max_output_bytes = std.math.maxInt(usize),
                });
                defer allocator.free(r.stdout);
                defer allocator.free(r.stderr);
                std.debug.print("ls {s} {s}\n", .{ path, r.stdout });
                return err;
            };
            const success = switch (run_result.term) {
                .Exited => |exit_code| exit_code == 0,
                else => false,
            };
            if (!success) {
                return error.executable_failed_to_run_successfully;
            }
        }
    }
}

const InvokeWrapper = struct {
    executable_path: [:0]const u8,
    object_path: [:0]const u8,
    file_path: [:0]const u8,
    name: []const u8,
};

// We invoke a function with comptime parameters so it's easily visible in CI stack traces
fn invoke_wrapper(options: InvokeWrapper, comptime build_mode: BuildMode, comptime has_debug_info: bool) void {
    return invoke_single(options, build_mode, has_debug_info);
}

fn invoke_single(options: InvokeWrapper, build_mode: BuildMode, has_debug_info: bool) void {
    const file_content = lib.file.read(lib.global.arena, options.file_path);

    converter.convert(.{
        .path = options.file_path,
        .content = file_content,
        .object = options.object_path,
        .executable = options.executable_path,
        .build_mode = build_mode,
        .name = options.name,
        .has_debug_info = has_debug_info,
    });
}

fn invsrc(src: std.builtin.SourceLocation) !void {
    try invoke(src.fn_name[std.mem.lastIndexOfScalar(u8, src.fn_name, '.').? + 1 ..]);
}

test "minimal" {
    try invsrc(@src());
}

test "constant_add" {
    try invsrc(@src());
}

test "constant_sub" {
    try invsrc(@src());
}

test "constant_mul" {
    try invsrc(@src());
}

test "constant_div" {
    try invsrc(@src());
}

test "constant_rem" {
    try invsrc(@src());
}

test "constant_shift_left" {
    try invsrc(@src());
}

test "constant_shift_right" {
    try invsrc(@src());
}

test "constant_and" {
    try invsrc(@src());
}

test "constant_or" {
    try invsrc(@src());
}

test "constant_xor" {
    try invsrc(@src());
}

test "minimal_stack" {
    try invsrc(@src());
}

test "stack_add" {
    try invsrc(@src());
}

test "stack_sub" {
    try invsrc(@src());
}

test "global" {
    try invsrc(@src());
}
