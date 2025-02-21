const lib = @import("lib.zig");
const assert = lib.assert;
const os = lib.os;
const Arena = lib.Arena;
const llvm = @import("LLVM.zig");
const configuration = @import("configuration");

const LexerResult = struct {
    token: Token,
    offset: u32,
    character_count: u32,
};

const Token = enum {};

const left_bracket = '[';
const right_bracket = ']';
const left_brace = '{';
const right_brace = '}';
const left_parenthesis = '(';
const right_parenthesis = ')';

fn is_identifier_start_ch(ch: u8) bool {
    return (ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or ch == '_';
}

fn is_decimal_ch(ch: u8) bool {
    return ch >= '0' and ch <= '9';
}

fn is_identifier_ch(ch: u8) bool {
    return is_identifier_start_ch(ch) or is_decimal_ch(ch);
}

fn string_to_enum(comptime E: type, string: []const u8) ?E {
    inline for (@typeInfo(E).@"enum".fields) |e| {
        if (lib.string.equal(e.name, string)) {
            return @field(E, e.name);
        }
    } else return null;
}

const GlobalKeyword = enum {
    @"export",
    @"extern",
};

const GlobalKind = enum {
    @"fn",
    foo,
};

const FunctionKeyword = enum {
    cc,
    foo,
};

const CallingConvention = enum {
    unknown,
    c,
};

const Converter = struct {
    content: []const u8,
    offset: usize,

    fn report_error(noalias converter: *Converter) noreturn {
        @branchHint(.cold);
        _ = converter;
        lib.os.abort();
    }

    fn skip_space(noalias converter: *Converter) void {
        while (converter.offset < converter.content.len and is_space(converter.content[converter.offset])) {
            converter.offset += 1;
        }
    }

    pub fn parse_type(noalias converter: *Converter, noalias thread: *llvm.Thread, noalias module_builder: *llvm.ModuleBuilder) *llvm.Type {
        _ = module_builder;
        const identifier = converter.parse_identifier();
        var integer_type = identifier.len > 1 and identifier[0] == 's' or identifier[0] == 'u';
        if (integer_type) {
            for (identifier[1..]) |ch| {
                integer_type = integer_type and is_decimal_ch(ch);
            }
        }

        if (integer_type) {
            const bit_count = lib.parse.integer_decimal(identifier[1..]);
            const llvm_int_type = switch (bit_count) {
                // TODO: consider u1?
                0 => converter.report_error(),
                8 => thread.i8.type,
                16 => thread.i16.type,
                32 => thread.i32.type,
                64 => thread.i64.type,
                else => converter.report_error(),
            };
            const llvm_type = llvm_int_type.to_type();
            return llvm_type;
        } else {
            os.abort();
        }
    }

    pub fn parse_identifier(noalias converter: *Converter) []const u8 {
        const start = converter.offset;

        if (is_identifier_start_ch(converter.content[start])) {
            converter.offset += 1;

            while (converter.offset < converter.content.len) {
                if (is_identifier_ch(converter.content[converter.offset])) {
                    converter.offset += 1;
                } else {
                    break;
                }
            }
        }

        if (converter.offset - start == 0) {
            converter.report_error();
        }

        return converter.content[start..converter.offset];
    }

    fn consume_character_if_match(noalias converter: *Converter, expected_ch: u8) bool {
        var is_ch = false;
        if (converter.offset < converter.content.len) {
            const ch = converter.content[converter.offset];
            is_ch = expected_ch == ch;
            converter.offset += @intFromBool(is_ch);
        }

        return is_ch;
    }

    fn expect_or_consume(noalias converter: *Converter, expected_ch: u8, is_required: bool) bool {
        if (is_required) {
            converter.expect_character(expected_ch);
            return true;
        } else {
            return converter.consume_character_if_match(expected_ch);
        }
    }

    fn parse_integer(noalias converter: *Converter, expected_type: *llvm.Type) *llvm.Value {
        const start = converter.offset;
        const integer_start_ch = converter.content[start];
        assert(!is_space(integer_start_ch));
        assert(is_decimal_ch(integer_start_ch));

        switch (integer_start_ch) {
            '0' => {
                converter.offset += 1;

                switch (converter.content[converter.offset]) {
                    'x' => {
                        // TODO: parse hexadecimal
                        converter.report_error();
                    },
                    'o' => {
                        // TODO: parse octal
                        converter.report_error();
                    },
                    'b' => {
                        // TODO: parse binary
                        converter.report_error();
                    },
                    '0'...'9' => {
                        converter.report_error();
                    },
                    // Zero literal
                    else => {
                        const integer_type = expected_type.to_integer();
                        const sign_extend = false;
                        const integer_value = integer_type.get_constant(0, @intFromBool(sign_extend));
                        return integer_value.to_value();
                    },
                }
            },
            // TODO: decimal number
            '1'...'9' => converter.report_error(),
            else => unreachable,
        }
    }

    fn expect_character(noalias converter: *Converter, expected_ch: u8) void {
        if (!converter.consume_character_if_match(expected_ch)) {
            converter.report_error();
        }
    }

    fn parse_block(noalias converter: *Converter, thread: *llvm.Thread, module_builder: *llvm.ModuleBuilder, function_builder: *llvm.FunctionBuilder) void {
        _ = thread;
        converter.skip_space();

        converter.expect_character(left_brace);

        while (true) {
            converter.skip_space();

            if (converter.offset == converter.content.len) {
                break;
            }

            if (converter.content[converter.offset] == right_brace) {
                break;
            }

            const statement_start_ch = converter.content[converter.offset];
            if (is_identifier_start_ch(statement_start_ch)) {
                const statement_start_identifier = converter.parse_identifier();

                if (string_to_enum(StatementStartKeyword, statement_start_identifier)) |statement_start_keyword| {
                    switch (statement_start_keyword) {
                        .@"return" => {
                            const return_value = converter.parse_value(function_builder.function.get_type().get_return_type());
                            module_builder.builder.create_ret(return_value);
                        },
                        else => unreachable,
                    }

                    const require_semicolon = switch (statement_start_keyword) {
                        .@"return" => true,
                        else => converter.report_error(),
                    };

                    _ = converter.expect_or_consume(';', require_semicolon);
                } else {
                    converter.report_error();
                }
            } else {
                converter.report_error();
            }
        }

        converter.expect_character(right_brace);
    }

    fn parse_value(noalias converter: *Converter, expected_type: *llvm.Type) *llvm.Value {
        converter.skip_space();

        const start = converter.offset;
        const value_start_ch = converter.content[start];
        if (is_identifier_start_ch(value_start_ch)) {
            converter.report_error();
        } else if (is_decimal_ch(value_start_ch)) {
            const value = converter.parse_integer(expected_type);
            return value;
        } else {
            converter.report_error();
        }
    }
};

fn is_space(ch: u8) bool {
    return ((@intFromBool(ch == ' ') | @intFromBool(ch == '\n')) | ((@intFromBool(ch == '\t') | @intFromBool(ch == '\r')))) != 0;
}

const StatementStartKeyword = enum {
    @"return",
    foooooooooo,
};

pub const BuildMode = enum {
    debug_none,
    debug_fast,
    debug_size,
    soft_optimize,
    optimize_for_speed,
    optimize_for_size,
    aggressively_optimize_for_speed,
    aggressively_optimize_for_size,

    fn to_llvm_ir(build_mode: BuildMode) llvm.OptimizationLevel {
        return switch (build_mode) {
            .debug_none => unreachable,
            .debug_fast, .debug_size => .O0,
            .soft_optimize => .O1,
            .optimize_for_speed => .O2,
            .optimize_for_size => .Os,
            .aggressively_optimize_for_speed => .O3,
            .aggressively_optimize_for_size => .Oz,
        };
    }

    fn to_llvm_machine(build_mode: BuildMode) llvm.CodeGenerationOptimizationLevel {
        return switch (build_mode) {
            .debug_none => .none,
            .debug_fast, .debug_size => .none,
            .soft_optimize => .less,
            .optimize_for_speed => .default,
            .optimize_for_size => .default,
            .aggressively_optimize_for_speed => .aggressive,
            .aggressively_optimize_for_size => .aggressive,
        };
    }
};

const ConvertOptions = struct {
    content: []const u8,
    path: [:0]const u8,
    object: [:0]const u8,
    executable: [:0]const u8,
    build_mode: BuildMode,
    name: []const u8,
};
pub noinline fn convert(options: ConvertOptions) void {
    var converter = Converter{
        .content = options.content,
        .offset = 0,
    };

    const thread = llvm.default_initialize();
    var module_builder_memory = llvm.ModuleBuilder.initialize(thread, options.name);
    const module_builder = &module_builder_memory;

    while (true) {
        converter.skip_space();

        if (converter.offset == converter.content.len) {
            break;
        }

        var is_export = false;

        if (converter.content[converter.offset] == left_bracket) {
            converter.offset += 1;

            while (converter.offset < converter.content.len) {
                const global_keyword_string = converter.parse_identifier();

                const global_keyword = string_to_enum(GlobalKeyword, global_keyword_string) orelse converter.report_error();
                switch (global_keyword) {
                    .@"export" => is_export = true,
                    else => converter.report_error(),
                }

                switch (converter.content[converter.offset]) {
                    right_bracket => break,
                    else => converter.report_error(),
                }
            }

            converter.expect_character(right_bracket);

            converter.skip_space();
        }

        const global_name = converter.parse_identifier();

        converter.skip_space();

        converter.expect_character('=');

        converter.skip_space();

        const global_kind_string = converter.parse_identifier();

        converter.skip_space();

        const global_kind = string_to_enum(GlobalKind, global_kind_string) orelse converter.report_error();

        switch (global_kind) {
            .@"fn" => {
                var calling_convention = CallingConvention.unknown;

                if (converter.consume_character_if_match(left_bracket)) {
                    while (converter.offset < converter.content.len) {
                        const function_identifier = converter.parse_identifier();

                        const function_keyword = string_to_enum(FunctionKeyword, function_identifier) orelse converter.report_error();

                        converter.skip_space();

                        switch (function_keyword) {
                            .cc => {
                                converter.expect_character(left_parenthesis);

                                converter.skip_space();

                                const calling_convention_string = converter.parse_identifier();

                                calling_convention = string_to_enum(CallingConvention, calling_convention_string) orelse converter.report_error();

                                converter.skip_space();

                                converter.expect_character(right_parenthesis);
                            },
                            else => converter.report_error(),
                        }

                        converter.skip_space();

                        switch (converter.content[converter.offset]) {
                            right_bracket => break,
                            else => converter.report_error(),
                        }
                    }

                    converter.expect_character(right_bracket);
                }

                converter.skip_space();

                converter.expect_character(left_parenthesis);

                while (converter.offset < converter.content.len and converter.content[converter.offset] != right_parenthesis) {
                    // TODO: arguments
                    converter.report_error();
                }

                converter.expect_character(right_parenthesis);

                converter.skip_space();

                const return_type = converter.parse_type(thread, module_builder);
                const function_type = llvm.Type.Function.get(return_type, &.{}, false);

                const function = module_builder.module.create_function(.{
                    .name = global_name,
                    .linkage = switch (is_export) {
                        true => .ExternalLinkage,
                        false => .InternalLinkage,
                    },
                    .type = function_type,
                });

                const entry_block = thread.context.create_basic_block("entry", function);
                module_builder.builder.position_at_end(entry_block);

                var function_builder = llvm.FunctionBuilder{
                    .function = function,
                    .current_basic_block = entry_block,
                };

                converter.parse_block(thread, module_builder, &function_builder);

                if (lib.optimization_mode == .Debug) {
                    const verify_result = function.verify();
                    if (!verify_result.success) {
                        os.abort();
                    }
                }
            },
            else => converter.report_error(),
        }
    }

    if (lib.optimization_mode == .Debug) {
        const verify_result = module_builder.module.verify();
        if (!verify_result.success) {
            os.abort();
        }

        if (!lib.is_test) {
            const module_string = module_builder.module.to_string();
            lib.print_string_stderr(module_string);
        }
    }

    var error_message: llvm.String = undefined;
    const target_machine = llvm.Target.Machine.create(.{
        .target_options = llvm.Target.Options.default(),
        .cpu_triple = llvm.String.from_slice(llvm.global.host_triple),
        .cpu_model = llvm.String.from_slice(llvm.global.host_cpu_model),
        .cpu_features = llvm.String.from_slice(llvm.global.host_cpu_features),
        .optimization_level = options.build_mode.to_llvm_machine(),
        .relocation_model = .default,
        .code_model = .none,
        .jit = false,
    }, &error_message) orelse {
        os.abort();
    };

    const object_generate_result = llvm.object_generate(module_builder.module, target_machine, .{
        .optimize_when_possible = @intFromBool(@intFromEnum(options.build_mode) > @intFromEnum(BuildMode.soft_optimize)),
        .debug_info = configuration.has_debug_info,
        .optimization_level = if (options.build_mode != .debug_none) options.build_mode.to_llvm_ir() else null,
        .path = options.object,
    });

    switch (object_generate_result) {
        .success => {
            const result = llvm.link(lib.global.arena, .{
                .output_path = options.executable,
                .objects = &.{options.object},
            });

            switch (result.success) {
                true => {},
                false => os.abort(),
            }
        },
        else => os.abort(),
    }
}

fn get_test_build_mode() BuildMode {
    return @enumFromInt(@intFromEnum(configuration.test_build_mode));
}

test "minimal" {
    invoke("minimal", get_test_build_mode());
}

pub fn invoke(name: []const u8, build_mode: BuildMode) void {
    const std = @import("std");
    if (!lib.GlobalState.initialized) {
        lib.GlobalState.initialize();
    }
    var tmp_dir = if (lib.is_test) std.testing.tmpDir(.{}) else {};
    defer {
        if (lib.is_test) {
            tmp_dir.cleanup();
        }
    }

    const object_path = lib.global.arena.join_string(if (lib.is_test) &.{ ".zig-cache/tmp/", &tmp_dir.sub_path, "/", name, ".o" } else &.{ name, ".o" });
    const executable_path = lib.global.arena.join_string(if (lib.is_test) &.{ ".zig-cache/tmp/", &tmp_dir.sub_path, "/", name, ".o" } else &.{name});
    const file_path = lib.global.arena.join_string(&.{ "tests/", name, ".bbb" });
    const file_content = lib.file.read(lib.global.arena, file_path);

    convert(.{
        .path = file_path,
        .content = file_content,
        .object = object_path,
        .executable = executable_path,
        .build_mode = build_mode,
        .name = name,
    });
}
