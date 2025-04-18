const lib = @import("lib.zig");
const configuration = @import("configuration");
const os = lib.os;
const llvm = @import("LLVM.zig");
const Arena = lib.Arena;

const compiler = @import("bootstrap.zig");
const BuildMode = compiler.BuildMode;

test {
    _ = lib;
    _ = llvm;
    _ = compiler;
}

fn fail() noreturn {
    lib.libc.exit(1);
}

const Command = enum {
    @"test",
    compile,
};

const Compile = struct {
    relative_file_path: [:0]const u8,
    build_mode: BuildMode,
    has_debug_info: bool,
    silent: bool,
};

fn compile_file(arena: *Arena, compile: Compile) compiler.Options {
    const relative_file_path = compile.relative_file_path;
    if (relative_file_path.len < 5) {
        fail();
    }

    const extension_start = lib.string.last_character(relative_file_path, '.') orelse fail();
    if (!lib.string.equal(relative_file_path[extension_start..], ".bbb")) {
        fail();
    }

    const separator_index = lib.string.last_character(relative_file_path, '/') orelse 0;
    const base_start = separator_index + @intFromBool(separator_index != 0 or relative_file_path[separator_index] == '/');
    const base_name = relative_file_path[base_start..extension_start];

    const is_compiler = lib.string.equal(relative_file_path, "src/compiler.bbb");
    const output_path_dir = arena.join_string(&.{
        base_cache_dir,
        if (is_compiler) "/compiler/" else "/",
        @tagName(compile.build_mode),
        "_",
        if (compile.has_debug_info) "di" else "nodi",
    });

    os.make_directory(base_cache_dir);
    if (is_compiler) {
        os.make_directory(base_cache_dir ++ "/compiler");
    }

    os.make_directory(output_path_dir);

    const output_path_base = arena.join_string(&.{
        output_path_dir,
        "/",
        base_name,
    });

    const output_object_path = arena.join_string(&.{ output_path_base, ".o" });
    const output_executable_path = output_path_base;

    const file_content = lib.file.read(arena, relative_file_path);
    const file_path = os.absolute_path(arena, relative_file_path);
    const c_abi_object_path = arena.duplicate_string(configuration.c_abi_object_path);

    const convert_options = compiler.Options{
        .executable = output_executable_path,
        .objects = if (lib.string.equal(base_name, "c_abi")) &.{ output_object_path, c_abi_object_path } else &.{output_object_path},
        .name = base_name,
        .build_mode = compile.build_mode,
        .content = file_content,
        .path = file_path,
        .has_debug_info = compile.has_debug_info,
        .target = compiler.Target.get_native(),
        .silent = compile.silent,
    };

    compiler.compile(arena, convert_options);

    return convert_options;
}

const base_cache_dir = "bb-cache";

pub const panic = lib.panic_struct;
pub const std_options = lib.std_options;
pub const main = lib.main;

pub fn entry_point(arguments: []const [*:0]const u8, environment: [*:null]const ?[*:0]const u8) void {
    lib.GlobalState.initialize();
    const arena = lib.global.arena;

    if (arguments.len < 2) {
        lib.print_string("error: Not enough arguments\n");
        fail();
    }

    const command = lib.string.to_enum(Command, lib.cstring.to_slice(arguments[1])) orelse fail();

    switch (command) {
        .compile => {
            if (arguments.len < 3) {
                lib.libc.exit(1);
            }

            var build_mode = compiler.BuildMode.debug_none;
            var has_debug_info = true;

            if (arguments.len >= 4) {
                const build_mode_string = lib.cstring.to_slice(arguments[3]);
                build_mode = lib.string.to_enum(compiler.BuildMode, build_mode_string) orelse lib.libc.exit(1);
            }

            if (arguments.len >= 5) {
                const has_debug_info_string = lib.cstring.to_slice(arguments[4]);
                has_debug_info = if (lib.string.equal(has_debug_info_string, "true")) true else if (lib.string.equal(has_debug_info_string, "false")) false else lib.libc.exit(1);
            }

            const relative_file_path = lib.cstring.to_slice(arguments[2]);
            _ = compile_file(arena, .{
                .relative_file_path = relative_file_path,
                .build_mode = build_mode,
                .has_debug_info = has_debug_info,
                .silent = false,
            });
        },
        .@"test" => {
            if (arguments.len != 2) {
                fail();
            }

            const stop_at_failure = true;

            var build_modes: [@typeInfo(BuildMode).@"enum".fields.len]BuildMode = undefined;
            inline for (@typeInfo(BuildMode).@"enum".fields, 0..) |field, field_index| {
                const build_mode = @field(BuildMode, field.name);
                build_modes[field_index] = build_mode;
            }

            for (names) |name| {
                for (build_modes) |build_mode| {
                    for ([2]bool{ true, false }) |has_debug_info| {
                        const position = arena.position;
                        defer arena.restore(position);

                        const relative_file_path = arena.join_string(&.{ "tests/", name, ".bbb" });
                        const compile_result = compile_file(arena, .{
                            .relative_file_path = relative_file_path,
                            .build_mode = build_mode,
                            .has_debug_info = has_debug_info,
                            .silent = true,
                        });

                        const result = lib.os.run_child_process(arena, &.{compile_result.executable}, environment, .{
                            .stdout = .inherit,
                            .stderr = .inherit,
                            .null_file_descriptor = null,
                        });

                        if (!result.is_successful()) {
                            lib.print_string("[BOOTSTRAP] Failed to run test ");
                            lib.print_string(name);
                            lib.print_string(" with build mode ");
                            lib.print_string(@tagName(build_mode));
                            lib.print_string("\n");

                            if (stop_at_failure) {
                                lib.libc.exit(1);
                            }
                        }
                    }
                }
            }

            const relative_file_path = arena.join_string(&.{"src/compiler.bbb"});
            for (build_modes) |build_mode| {
                for ([2]bool{ true, false }) |has_debug_info| {
                    const position = arena.position;
                    defer arena.restore(position);

                    const compile_result = compile_file(arena, .{
                        .relative_file_path = relative_file_path,
                        .build_mode = build_mode,
                        .has_debug_info = has_debug_info,
                        .silent = true,
                    });

                    for (names[0..1]) |name| {
                        for (build_modes) |self_hosted_build_mode| {
                            for ([2]bool{ true, false }) |self_hosted_has_debug_info| {
                                const self_hosted_relative_file_path = arena.join_string(&.{ "tests/", name, ".bbb" });
                                // TODO: investigar corrupcion de memoria en compile_result.executable porque compile_file borra la memoria
                                const result = lib.os.run_child_process(arena, &.{ compile_result.executable, "compile", self_hosted_relative_file_path, @tagName(self_hosted_build_mode), if (self_hosted_has_debug_info) "true" else "false" }, environment, .{
                                    .stdout = .inherit,
                                    .stderr = .inherit,
                                    .null_file_descriptor = null,
                                });

                                if (!result.is_successful()) {
                                    lib.print_string("[SELF-HOSTED] Failed to compile ");
                                    lib.print_string(name);
                                    lib.print_string(" with build mode ");
                                    lib.print_string(@tagName(build_mode));
                                    lib.print_string(" and debug info ");
                                    lib.print_string(if (has_debug_info) "on" else "off");
                                    lib.print_string(", with self-hosted build mode ");
                                    lib.print_string(@tagName(self_hosted_build_mode));
                                    lib.print_string(" and self-hosted debug info ");
                                    lib.print_string(if (self_hosted_has_debug_info) "on" else "off");
                                    lib.print_string("\n");

                                    if (stop_at_failure) {
                                        lib.libc.exit(1);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
    }
}

const names = &[_][]const u8{
    "minimal",
    "comments",
    "constant_add",
    "constant_and",
    "constant_div",
    "constant_mul",
    "constant_rem",
    "constant_or",
    "constant_sub",
    "constant_xor",
    "constant_shift_left",
    "constant_shift_right",
    "minimal_stack",
    "minimal_stack_arithmetic",
    "minimal_stack_arithmetic2",
    "minimal_stack_arithmetic3",
    "extend",
    "stack_negation",
    "stack_add",
    "stack_sub",
    "integer_max",
    "integer_hex",
    "basic_pointer",
    "basic_call",
    "pointer",
    "pointer_cast",
    "u1_return",
    "local_type_inference",
    "global",
    "function_pointer",
    "extern",
    "byte_size",
    "basic_branch",
    "basic_array",
    "basic_enum",
    "argv",
    "assignment_operators",
    "basic_enum",
    "basic_slice",
    "basic_string",
    "basic_varargs",
    "basic_while",
    "not_pointer",
    "bits",
    "bits_no_backing_type",
    "bits_return_u1",
    "bits_zero",
    "comparison",
    "global_struct",
    "if_no_else",
    "if_no_else_void",
    "indirect",
    "indirect_struct",
    "indirect_varargs",
    "ret_c_bool",
    "return_type_builtin",
    "return_u64_u64",
    "select",
    "slice",
    "small_struct_ints",
    "struct_assignment",
    "struct",
    "struct_u64_u64",
    "struct_varargs",
    "struct_zero",
    "unreachable",
    "varargs",
    "c_abi0",
    "c_abi1",
    "c_med_struct_ints",
    "c_ret_struct_array",
    "c_split_struct_ints",
    "c_string_to_slice",
    "c_struct_with_array",
    "c_function_pointer",
    "c_abi",
    "string_to_enum",
    "abi_enum_bool",
    "empty_if",
    "else_if",
    "else_if_complicated",
    "shortcircuiting_if",
    "field_access_left_assign",
};
