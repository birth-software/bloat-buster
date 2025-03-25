const lib = @import("lib.zig");
const Arena = lib.Arena;
const assert = lib.assert;
const std = @import("std");
const configuration = @import("configuration");

const converter = @import("converter.zig");
const BuildMode = converter.BuildMode;

fn invoke(name: []const u8) !void {
    if (!lib.GlobalState.initialized) {
        lib.GlobalState.initialize();
    }

    comptime assert(lib.is_test);
    const allocator = std.testing.allocator;
    const arena = lib.global.arena;
    const arena_position = arena.position;
    defer arena.restore(arena_position);

    const c_abi_object_path = arena.duplicate_string(configuration.c_abi_object_path);
    const file_path = arena.join_string(&.{ "tests/", name, ".bbb" });

    inline for (@typeInfo(BuildMode).@"enum".fields) |f| {
        const build_mode = @field(BuildMode, f.name);
        inline for ([2]bool{ true, false }) |has_debug_info| {
            // Bootstrap
            {
                var tmp_dir = std.testing.tmpDir(.{});
                defer tmp_dir.cleanup();
                const base_path = arena.join_string(&.{ ".zig-cache/tmp/", &tmp_dir.sub_path, "/", name });
                const executable_path = base_path;
                const directory_path = arena.join_string(&.{ ".zig-cache/tmp/", &tmp_dir.sub_path });
                const object_path = arena.join_string(&.{ base_path, ".o" });
                try unit_test(arena, allocator, .{
                    .object_paths = if (lib.string.equal(name, "c_abi")) &.{ object_path, c_abi_object_path } else &.{object_path},
                    .executable_path = executable_path,
                    .file_path = file_path,
                    .name = name,
                    .directory_path = directory_path,
                    .build_mode = build_mode,
                    .has_debug_info = has_debug_info,
                    .self_hosted_path = null,
                    .run = true,
                });
            }

            // Self-hosted
            {
                var tmp_dir = std.testing.tmpDir(.{});
                defer tmp_dir.cleanup();
                const base_path = arena.join_string(&.{ ".zig-cache/tmp/", &tmp_dir.sub_path, "/", name });
                const executable_path = base_path;
                const directory_path = arena.join_string(&.{ ".zig-cache/tmp/", &tmp_dir.sub_path });
                const object_path = arena.join_string(&.{ base_path, ".o" });
                try unit_test(arena, allocator, .{
                    .object_paths = if (lib.string.equal(name, "c_abi")) &.{ object_path, c_abi_object_path } else &.{object_path},
                    .executable_path = executable_path,
                    .file_path = file_path,
                    .name = name,
                    .directory_path = directory_path,
                    .build_mode = build_mode,
                    .has_debug_info = has_debug_info,
                    .self_hosted_path = arena.join_string(&.{ "bb-cache/", compiler_basename(arena, build_mode, has_debug_info) }),
                    .run = true,
                });
            }
        }
    }
}

fn compiler_basename(arena: *Arena, build_mode: BuildMode, has_debug_info: bool) [:0]const u8 {
    return arena.join_string(&.{ "compiler_", @tagName(build_mode), if (has_debug_info) "_di" else "_nodi" });
}

var compiler_compiled = false;
fn compile_the_compiler() !void {
    if (!compiler_compiled) {
        defer compiler_compiled = true;

        if (!lib.GlobalState.initialized) {
            lib.GlobalState.initialize();
        }

        comptime assert(lib.is_test);
        const allocator = std.testing.allocator;
        const arena = lib.global.arena;
        const arena_position = arena.position;
        defer arena.restore(arena_position);

        inline for (@typeInfo(BuildMode).@"enum".fields) |f| {
            const build_mode = @field(BuildMode, f.name);
            inline for ([2]bool{ false, true }) |has_debug_info| {
                var tmp_dir = std.testing.tmpDir(.{});
                defer tmp_dir.cleanup();
                const base_path = arena.join_string(&.{ "bb-cache/", compiler_basename(arena, build_mode, has_debug_info) });
                const executable_path = base_path;
                const directory_path = "bb-cache";
                const object_path = arena.join_string(&.{ base_path, ".o" });

                try unit_test(arena, allocator, .{
                    .object_paths = &.{object_path},
                    .executable_path = executable_path,
                    .file_path = arena.join_string(&.{"src/compiler.bbb"}),
                    .name = "compiler",
                    .directory_path = directory_path,
                    .build_mode = build_mode,
                    .has_debug_info = has_debug_info,
                    .self_hosted_path = null,
                    .run = false,
                });
            }
        }
    }
}

const InvokeWrapper = struct {
    executable_path: [:0]const u8,
    object_paths: []const [:0]const u8,
    file_path: [:0]const u8,
    name: []const u8,
    build_mode: BuildMode,
    has_debug_info: bool,
    directory_path: [:0]const u8,
    self_hosted_path: ?[]const u8,
    run: bool,
};

fn unit_test(arena: *Arena, allocator: std.mem.Allocator, options: InvokeWrapper) anyerror!void {
    const position = arena.position;
    defer arena.restore(position);

    const file_content = lib.file.read(arena, options.file_path);

    if (options.self_hosted_path) |self_hosted_path| {
        try compile_the_compiler();
        const argv = [_][]const u8{
            self_hosted_path,
            options.file_path,
        };
        const run_result = try std.process.Child.run(.{
            .allocator = allocator,
            .argv = &argv,
        });
        const success = switch (run_result.term) {
            .Exited => |exit_code| exit_code == 0,
            else => false,
        };
        if (!success) {
            std.debug.print("{s}\n{}\n{}\n", .{ argv, run_result, options });
            return error.compiler_failed_to_run_successfully;
        }
    } else {
        converter.convert(arena, .{
            .path = options.file_path,
            .content = file_content,
            .objects = options.object_paths,
            .executable = options.executable_path,
            .build_mode = options.build_mode,
            .name = options.name,
            .has_debug_info = options.has_debug_info,
            .target = converter.Target.get_native(),
        });

        if (options.run) {
            const argv = [_][]const u8{options.executable_path};
            const run_result = std.process.Child.run(.{
                .allocator = allocator,
                .argv = &argv,
            }) catch |err| {
                std.debug.print("error: {}\n", .{err});
                const r = try std.process.Child.run(.{
                    .allocator = allocator,
                    .argv = &.{ "/usr/bin/ls", "-lasR", options.directory_path },
                    .max_output_bytes = std.math.maxInt(usize),
                });
                defer allocator.free(r.stdout);
                defer allocator.free(r.stderr);
                std.debug.print("ls {s} {s}\n", .{ options.directory_path, r.stdout });
                return err;
            };

            const success = switch (run_result.term) {
                .Exited => |exit_code| exit_code == 0,
                else => false,
            };
            if (!success) {
                std.debug.print("{s} {}\n{}\n", .{ argv, run_result, options });
                return error.executable_failed_to_run_successfully;
            }
        }
    }
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

test "simple_branch" {
    try invsrc(@src());
}

test "basic_call" {
    try invsrc(@src());
}

test "struct" {
    try invsrc(@src());
}

test "extend" {
    try invsrc(@src());
}

test "bits" {
    try invsrc(@src());
}

test "basic_array" {
    try invsrc(@src());
}

test "extern" {
    try invsrc(@src());
}

test "pointer" {
    try invsrc(@src());
}

test "if_no_else" {
    try invsrc(@src());
}

test "comments" {
    try invsrc(@src());
}

test "local_type_inference" {
    try invsrc(@src());
}

test "if_no_else_void" {
    try invsrc(@src());
}

test "c_abi0" {
    try invsrc(@src());
}

test "c_abi1" {
    try invsrc(@src());
}

test "return_u64_u64" {
    try invsrc(@src());
}

test "struct_u64_u64" {
    try invsrc(@src());
}

test "ret_c_bool" {
    try invsrc(@src());
}

test "c_split_struct_ints" {
    try invsrc(@src());
}

test "c_ret_struct_array" {
    try invsrc(@src());
}

test "function_pointer" {
    try invsrc(@src());
}

test "c_struct_with_array" {
    try invsrc(@src());
}

test "indirect" {
    try invsrc(@src());
}

test "indirect_struct" {
    try invsrc(@src());
}

test "u1_return" {
    try invsrc(@src());
}

test "small_struct_ints" {
    try invsrc(@src());
}

test "c_med_struct_ints" {
    try invsrc(@src());
}

test "c_abi" {
    try invsrc(@src());
}

test "basic_varargs" {
    try invsrc(@src());
}

test "struct_varargs" {
    try invsrc(@src());
}

test "indirect_varargs" {
    try invsrc(@src());
}

test "varargs" {
    try invsrc(@src());
}

test "byte_size" {
    try invsrc(@src());
}

test "bits_no_backing_type" {
    try invsrc(@src());
}

test "basic_enum" {
    try invsrc(@src());
}

test "return_type_builtin" {
    try invsrc(@src());
}

test "bits_zero" {
    try invsrc(@src());
}

test "struct_zero" {
    try invsrc(@src());
}

test "select" {
    try invsrc(@src());
}

test "bits_return_u1" {
    try invsrc(@src());
}

test "integer_max" {
    try invsrc(@src());
}

test "unreachable" {
    try invsrc(@src());
}

test "pointer_cast" {
    try invsrc(@src());
}

test "struct_assignment" {
    try invsrc(@src());
}

test "global_struct" {
    try invsrc(@src());
}

test "basic_slice" {
    try invsrc(@src());
}

test "basic_string" {
    try invsrc(@src());
}

test "argv" {
    try invsrc(@src());
}

test "basic_while" {
    try invsrc(@src());
}
