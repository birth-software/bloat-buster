const lib = @import("lib.zig");
const assert = lib.assert;
const os = lib.os;
const Arena = lib.Arena;
const llvm = @import("LLVM.zig");

test {
    _ = @import("converter_test.zig");
}

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

const Variable = struct {
    name: []const u8,
    storage: *llvm.Value,
    type: Type,
};

const VariableArray = struct {
    buffer: [64]Variable = undefined,
    count: u32 = 0,

    pub fn get(variables: *VariableArray) []Variable {
        return variables.buffer[0..variables.count];
    }

    pub fn add(variables: *VariableArray) *Variable {
        const result = &variables.buffer[variables.count];
        variables.count += 1;
        return result;
    }

    pub fn find(variables: *VariableArray, name: []const u8) ?*Variable {
        for (variables.get()) |*variable| {
            if (lib.string.equal(variable.name, name)) {
                return variable;
            }
        } else {
            return null;
        }
    }
};

const ModuleBuilder = struct {
    handle: *llvm.Module,
    di_builder: ?*llvm.DI.Builder,
    global_scope: *llvm.DI.Scope,
    file: *llvm.DI.File,
    integer_types: [8]*llvm.DI.Type,
    globals: VariableArray = .{},
};

pub const FunctionBuilder = struct {
    handle: *llvm.Function,
    current_basic_block: *llvm.BasicBlock,
    current_scope: *llvm.DI.Scope,
    return_type: Type,
    locals: VariableArray = .{},
};

const Type = packed struct(u64) {
    llvm: u48,
    signedness: bool,
    reserved: u15 = 0,

    pub fn new(llvm_type: *llvm.Type, signedness: bool) Type {
        return .{
            .llvm = @intCast(@intFromPtr(llvm_type)),
            .signedness = signedness,
        };
    }

    pub fn get(t: Type) *llvm.Type {
        return @ptrFromInt(t.llvm);
    }

    pub fn to_debug_type(ty: Type, module: *ModuleBuilder) *llvm.DI.Type {
        if (ty.get().is_integer()) {
            const integer_type = ty.get().to_integer();
            const bit_count = integer_type.get_bit_count();
            const index = (@ctz(bit_count) - 3) + (@as(u8, 4) * @intFromBool(ty.signedness));
            return module.integer_types[index];
        } else {
            os.abort();
        }
    }
};

const Converter = struct {
    content: []const u8,
    offset: usize,
    line_offset: usize,
    line_character_offset: usize,

    fn get_line(converter: *const Converter) u32 {
        return @intCast(converter.line_offset + 1);
    }

    fn get_column(converter: *const Converter) u32 {
        return @intCast(converter.offset - converter.line_character_offset + 1);
    }

    fn report_error(noalias converter: *Converter) noreturn {
        @branchHint(.cold);
        _ = converter;
        lib.os.abort();
    }

    fn skip_space(noalias converter: *Converter) void {
        while (converter.offset < converter.content.len and is_space(converter.content[converter.offset])) {
            converter.line_offset += @intFromBool(converter.content[converter.offset] == '\n');
            converter.line_character_offset = if (converter.content[converter.offset] == '\n') converter.offset else converter.line_character_offset;
            converter.offset += 1;
        }
    }

    pub fn parse_type(noalias converter: *Converter, noalias thread: *llvm.Thread) Type {
        const identifier = converter.parse_identifier();
        var integer_type = identifier.len > 1 and identifier[0] == 's' or identifier[0] == 'u';
        if (integer_type) {
            for (identifier[1..]) |ch| {
                integer_type = integer_type and is_decimal_ch(ch);
            }
        }

        if (integer_type) {
            const signedness = switch (identifier[0]) {
                's' => true,
                'u' => false,
                else => unreachable,
            };
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
            return Type.new(llvm_type, signedness);
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

    fn parse_decimal(noalias converter: *Converter) u64 {
        var value: u64 = 0;
        while (true) {
            const ch = converter.content[converter.offset];
            if (!is_decimal_ch(ch)) {
                break;
            }

            converter.offset += 1;
            value = lib.parse.accumulate_decimal(value, ch);
        }

        return value;
    }

    fn parse_integer(noalias converter: *Converter, expected_type: Type, sign: bool) *llvm.Value {
        const start = converter.offset;
        const integer_start_ch = converter.content[start];
        assert(!is_space(integer_start_ch));
        assert(is_decimal_ch(integer_start_ch));

        const value: u64 = switch (integer_start_ch) {
            '0' => blk: {
                converter.offset += 1;

                const next_ch = converter.content[converter.offset];
                break :blk switch (sign) {
                    false => switch (next_ch) {
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
                        else => 0,
                    },
                    true => switch (next_ch) {
                        'x', 'o', 'b', '0' => converter.report_error(),
                        '1'...'9' => @bitCast(-@as(i64, @intCast(converter.parse_decimal()))),
                        else => unreachable,
                    },
                };
            },
            '1'...'9' => switch (sign) {
                true => @bitCast(-@as(i64, @intCast(converter.parse_decimal()))),
                false => converter.parse_decimal(),
            },
            else => unreachable,
        };

        const integer_type = expected_type.get().to_integer();
        const integer_value = integer_type.get_constant(value, @intFromBool(expected_type.signedness));
        return integer_value.to_value();
    }

    fn expect_character(noalias converter: *Converter, expected_ch: u8) void {
        if (!converter.consume_character_if_match(expected_ch)) {
            converter.report_error();
        }
    }

    fn parse_block(noalias converter: *Converter, noalias thread: *llvm.Thread, noalias module: *ModuleBuilder, noalias function: *FunctionBuilder) void {
        converter.skip_space();

        const block_line = converter.get_line();
        const block_column = converter.get_column();

        const current_scope = function.current_scope;
        defer function.current_scope = current_scope;

        if (module.di_builder) |di_builder| {
            const lexical_block = di_builder.create_lexical_block(current_scope, module.file, block_line, block_column);
            function.current_scope = lexical_block.to_scope();
        }

        converter.expect_character(left_brace);

        const local_offset = function.locals.count;
        defer function.locals.count = local_offset;

        while (true) {
            converter.skip_space();

            if (converter.offset == converter.content.len) {
                break;
            }

            if (converter.content[converter.offset] == right_brace) {
                break;
            }

            var require_semicolon = true;

            const line = converter.get_line();
            const column = converter.get_column();

            var statement_debug_location: *llvm.DI.Location = undefined;
            if (module.di_builder) |_| {
                const inlined_at: ?*llvm.DI.Metadata = null; // TODO
                statement_debug_location = llvm.DI.create_debug_location(thread.context, line, column, function.current_scope, inlined_at);
                thread.builder.set_current_debug_location(statement_debug_location);
            }

            const statement_start_ch = converter.content[converter.offset];
            if (statement_start_ch == '>') {
                converter.offset += 1;

                converter.skip_space();

                const local_name = converter.parse_identifier();

                converter.skip_space();

                if (converter.consume_character_if_match(':')) {
                    converter.skip_space();

                    const local_type = converter.parse_type(thread);

                    converter.skip_space();

                    converter.expect_character('=');

                    converter.skip_space();

                    if (module.di_builder) |_| {
                        thread.builder.clear_current_debug_location();
                    }
                    const alloca = thread.builder.create_alloca(local_type.get(), local_name);

                    const value = converter.parse_value(thread, module, function, local_type);

                    if (module.di_builder) |di_builder| {
                        thread.builder.set_current_debug_location(statement_debug_location);
                        const debug_type = local_type.to_debug_type(module);
                        const always_preserve = true;
                        // TODO:
                        const alignment = 0;
                        const flags = llvm.DI.Flags{};
                        const local_variable = di_builder.create_auto_variable(function.current_scope, local_name, module.file, line, debug_type, always_preserve, flags, alignment);
                        const inlined_at: ?*llvm.DI.Metadata = null; // TODO
                        const debug_location = llvm.DI.create_debug_location(thread.context, line, column, function.current_scope, inlined_at);
                        _ = di_builder.insert_declare_record_at_end(alloca, local_variable, di_builder.null_expression(), debug_location, function.current_basic_block);
                        thread.builder.set_current_debug_location(statement_debug_location);
                    }
                    _ = thread.builder.create_store(value, alloca);

                    const local = function.locals.add();
                    local.* = .{
                        .name = local_name,
                        .storage = alloca,
                        .type = local_type,
                    };
                } else {
                    converter.report_error();
                }
            } else if (is_identifier_start_ch(statement_start_ch)) {
                const statement_start_identifier = converter.parse_identifier();

                if (string_to_enum(StatementStartKeyword, statement_start_identifier)) |statement_start_keyword| {
                    switch (statement_start_keyword) {
                        .@"return" => {
                            const return_value = converter.parse_value(thread, module, function, function.return_type);
                            thread.builder.create_ret(return_value);
                        },
                        .@"if" => {
                            const taken_block = thread.context.create_basic_block("", function.handle);
                            const not_taken_block = thread.context.create_basic_block("", function.handle);

                            converter.skip_space();

                            converter.expect_character(left_parenthesis);
                            converter.skip_space();

                            const condition = converter.parse_value(thread, module, function, null);

                            converter.skip_space();
                            converter.expect_character(right_parenthesis);

                            _ = thread.builder.create_conditional_branch(condition, taken_block, not_taken_block);
                            thread.builder.position_at_end(taken_block);

                            converter.parse_block(thread, module, function);

                            const is_first_block_terminated = function.current_basic_block.get_terminator() != null;
                            if (!is_first_block_terminated) {
                                @trap();
                            }

                            converter.skip_space();

                            var is_else = false;
                            if (is_identifier_start_ch(converter.content[converter.offset])) {
                                const identifier = converter.parse_identifier();
                                is_else = lib.string.equal(identifier, "else");
                                if (!is_else) {
                                    converter.offset -= identifier.len;
                                }
                            }

                            var is_second_block_terminated = false;
                            if (is_else) {
                                thread.builder.position_at_end(not_taken_block);
                                converter.parse_block(thread, module, function);
                                is_second_block_terminated = function.current_basic_block.get_terminator() != null;
                            } else {
                                @trap();
                            }

                            if (!(is_first_block_terminated and is_second_block_terminated)) {
                                @trap();
                            }

                            require_semicolon = false;
                        },
                    }
                } else {
                    converter.report_error();
                }
            } else {
                converter.report_error();
            }

            converter.skip_space();

            if (require_semicolon) {
                converter.expect_character(';');
            }
        }

        converter.expect_character(right_brace);
    }

    const ExpressionState = enum {
        none,
        add,
        sub,
        mul,
        udiv,
        sdiv,
        urem,
        srem,
        shl,
        ashr,
        lshr,
        @"and",
        @"or",
        xor,
        icmp_ne,

        pub fn to_int_predicate(expression_state: ExpressionState) llvm.IntPredicate {
            return switch (expression_state) {
                .icmp_ne => .ne,
                else => unreachable,
            };
        }
    };

    fn parse_value(noalias converter: *Converter, noalias thread: *llvm.Thread, noalias module: *ModuleBuilder, noalias function: ?*FunctionBuilder, maybe_expected_type: ?Type) *llvm.Value {
        converter.skip_space();

        var value_state = ExpressionState.none;
        var previous_value: *llvm.Value = undefined;
        var iterations: usize = 0;
        var iterative_expected_type: ?Type = maybe_expected_type;

        const value = while (true) : (iterations += 1) {
            if (iterations == 1 and iterative_expected_type == null) {
                iterative_expected_type = Type.new(previous_value.get_type(), false);
            }

            const current_value = switch (converter.content[converter.offset] == left_parenthesis) {
                true => os.abort(),
                false => converter.parse_single_value(thread, module, function, iterative_expected_type),
            };

            converter.skip_space();

            const left = previous_value;
            const right = current_value;

            previous_value = switch (value_state) {
                .none => current_value,
                .sub => thread.builder.create_sub(left, right),
                .add => thread.builder.create_add(left, right),
                .mul => thread.builder.create_mul(left, right),
                .sdiv => thread.builder.create_sdiv(left, right),
                .udiv => thread.builder.create_udiv(left, right),
                .srem => thread.builder.create_srem(left, right),
                .urem => thread.builder.create_urem(left, right),
                .shl => thread.builder.create_shl(left, right),
                .ashr => thread.builder.create_ashr(left, right),
                .lshr => thread.builder.create_lshr(left, right),
                .@"and" => thread.builder.create_and(left, right),
                .@"or" => thread.builder.create_or(left, right),
                .xor => thread.builder.create_xor(left, right),
                .icmp_ne => |icmp| thread.builder.create_compare(icmp.to_int_predicate(), left, right),
            };

            const ch = converter.content[converter.offset];
            value_state = switch (ch) {
                ';', right_parenthesis => break previous_value,
                '-' => blk: {
                    converter.offset += 1;
                    break :blk .sub;
                },
                '+' => blk: {
                    converter.offset += 1;
                    break :blk .add;
                },
                '*' => blk: {
                    converter.offset += 1;
                    break :blk .mul;
                },
                '/' => blk: {
                    converter.offset += 1;
                    break :blk switch (iterative_expected_type.?.signedness) {
                        true => .sdiv,
                        false => .udiv,
                    };
                },
                '%' => blk: {
                    converter.offset += 1;
                    switch (iterative_expected_type.?.signedness) {
                        true => break :blk .srem,
                        false => break :blk .urem,
                    }
                },
                '<' => blk: {
                    converter.offset += 1;

                    break :blk switch (converter.content[converter.offset]) {
                        '<' => b: {
                            converter.offset += 1;
                            break :b .shl;
                        },
                        else => os.abort(),
                    };
                },
                '>' => blk: {
                    converter.offset += 1;

                    break :blk switch (converter.content[converter.offset]) {
                        '>' => b: {
                            converter.offset += 1;
                            break :b switch (iterative_expected_type.?.signedness) {
                                true => .ashr,
                                false => .lshr,
                            };
                        },
                        else => os.abort(),
                    };
                },
                '&' => blk: {
                    converter.offset += 1;
                    break :blk .@"and";
                },
                '|' => blk: {
                    converter.offset += 1;
                    break :blk .@"or";
                },
                '^' => blk: {
                    converter.offset += 1;
                    break :blk .xor;
                },
                '!' => blk: {
                    converter.offset += 1;
                    break :blk switch (converter.content[converter.offset]) {
                        '=' => b: {
                            converter.offset += 1;
                            break :b .icmp_ne;
                        },
                        else => os.abort(),
                    };
                },
                else => os.abort(),
            };

            converter.skip_space();
        };

        return value;
    }

    const Prefix = enum {
        none,
        negative,
    };

    fn parse_single_value(noalias converter: *Converter, noalias thread: *llvm.Thread, noalias module: *ModuleBuilder, noalias maybe_function: ?*FunctionBuilder, expected_type: ?Type) *llvm.Value {
        converter.skip_space();

        if (maybe_function) |function| {
            if (module.di_builder) |_| {
                const line = converter.get_line();
                const column = converter.get_column();
                const inlined_at: ?*llvm.DI.Metadata = null; // TODO
                const debug_location = llvm.DI.create_debug_location(thread.context, line, column, function.current_scope, inlined_at);
                thread.builder.set_current_debug_location(debug_location);
            }
        }

        const prefix_offset = converter.offset;
        const prefix_ch = converter.content[prefix_offset];
        const prefix: Prefix = switch (prefix_ch) {
            'a'...'z', 'A'...'Z', '_', '0'...'9' => .none,
            '-' => blk: {
                converter.offset += 1;

                // TODO: should we skip space here?
                converter.skip_space();
                break :blk .negative;
            },
            else => os.abort(),
        };

        const value_offset = converter.offset;
        const value_start_ch = converter.content[value_offset];
        const value = switch (value_start_ch) {
            'a'...'z', 'A'...'Z', '_' => b: {
                if (maybe_function) |function| {
                    const identifier = converter.parse_identifier();
                    const variable = blk: {
                        if (function.locals.find(identifier)) |local| {
                            break :blk local;
                        } else if (module.globals.find(identifier)) |global| {
                            break :blk global;
                        } else {
                            converter.report_error();
                        }
                    };
                    break :b thread.builder.create_load(variable.type.get(), variable.storage);
                } else {
                    converter.report_error();
                }
            },
            '0'...'9' => converter.parse_integer(expected_type.?, prefix == .negative),
            else => os.abort(),
        };

        return value;
    }
};

fn is_space(ch: u8) bool {
    return ((@intFromBool(ch == ' ') | @intFromBool(ch == '\n')) | ((@intFromBool(ch == '\t') | @intFromBool(ch == '\r')))) != 0;
}

const StatementStartKeyword = enum {
    @"return",
    @"if",
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

    fn is_optimized(build_mode: BuildMode) bool {
        return @intFromEnum(build_mode) >= @intFromEnum(BuildMode.soft_optimize);
    }

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
    has_debug_info: bool,
};

pub noinline fn convert(options: ConvertOptions) void {
    var converter = Converter{
        .content = options.content,
        .offset = 0,
        .line_offset = 0,
        .line_character_offset = 0,
    };

    const thread = llvm.default_initialize();

    const m = thread.context.create_module(options.name);
    var module = ModuleBuilder{
        .handle = m,
        .di_builder = if (options.has_debug_info) m.create_di_builder() else null,
        .global_scope = undefined,
        .file = undefined,
        .integer_types = undefined,
    };

    if (module.di_builder) |di_builder| {
        var directory: []const u8 = undefined;
        var file_name: []const u8 = undefined;
        if (lib.string.last_character(options.path, '/')) |index| {
            directory = options.path[0..index];
            file_name = options.path[index + 1 ..];
        } else {
            os.abort();
        }
        const file = di_builder.create_file(file_name, directory);
        const compile_unit = di_builder.create_compile_unit(file, options.build_mode.is_optimized());
        module.global_scope = compile_unit.to_scope();
        module.file = file;

        for ([2]bool{ false, true }) |sign| {
            for (0..4) |i| {
                var name_buffer = [3]u8{ if (sign) 's' else 'u', 0, 0 };
                const bit_count = @as(u64, 1) << @intCast(3 + i);
                switch (bit_count) {
                    8 => name_buffer[1] = '8',
                    16 => {
                        name_buffer[1] = '1';
                        name_buffer[2] = '6';
                    },
                    32 => {
                        name_buffer[1] = '3';
                        name_buffer[2] = '2';
                    },
                    64 => {
                        name_buffer[1] = '6';
                        name_buffer[2] = '4';
                    },
                    else => unreachable,
                }
                const name_length = @as(usize, 2) + @intFromBool(bit_count > 9);
                const name = name_buffer[0..name_length];
                const dwarf_type: llvm.Dwarf.Type = if (bit_count == 8 and !sign) .unsigned_char else if (sign) .signed else .unsigned;
                module.integer_types[i + @as(usize, 4) * @intFromBool(sign)] = di_builder.create_basic_type(name, bit_count, dwarf_type, .{});
            }
        }
    }

    while (true) {
        converter.skip_space();

        if (converter.offset == converter.content.len) {
            break;
        }

        var is_export = false;

        const global_line = converter.get_line();
        const global_column = converter.get_column();
        _ = global_column;

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

        var global_type: ?Type = null;
        if (converter.consume_character_if_match(':')) {
            converter.skip_space();

            global_type = converter.parse_type(thread);

            converter.skip_space();
        }

        converter.expect_character('=');

        converter.skip_space();

        if (is_identifier_start_ch(converter.content[converter.offset])) {
            const global_string = converter.parse_identifier();
            converter.skip_space();

            if (string_to_enum(GlobalKind, global_string)) |global_kind| {
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

                        const return_type = converter.parse_type(thread);
                        const function_type = llvm.Type.Function.get(return_type.get(), &.{}, false);

                        const handle = module.handle.create_function(.{
                            .name = global_name,
                            .linkage = switch (is_export) {
                                true => .ExternalLinkage,
                                false => .InternalLinkage,
                            },
                            .type = function_type,
                        });

                        const entry_block = thread.context.create_basic_block("entry", handle);
                        thread.builder.position_at_end(entry_block);

                        var function = FunctionBuilder{
                            .handle = handle,
                            .current_basic_block = entry_block,
                            .return_type = return_type,
                            .current_scope = undefined,
                        };

                        if (module.di_builder) |di_builder| {
                            const debug_return_type = return_type.to_debug_type(&module);
                            const subroutine_type = di_builder.create_subroutine_type(module.file, &.{debug_return_type}, .{});
                            const linkage_name = global_name;
                            const scope_line: u32 = @intCast(converter.line_offset + 1);
                            const local_to_unit = !is_export;
                            const flags = llvm.DI.Flags{};
                            const is_definition = true;
                            const subprogram = di_builder.create_function(module.global_scope, global_name, linkage_name, module.file, global_line, subroutine_type, local_to_unit, is_definition, scope_line, flags, options.build_mode.is_optimized());
                            handle.set_subprogram(subprogram);

                            function.current_scope = @ptrCast(subprogram);
                        }

                        converter.parse_block(thread, &module, &function);

                        if (module.di_builder) |di_builder| {
                            di_builder.finalize_subprogram(handle.get_subprogram());
                        }

                        if (lib.optimization_mode == .Debug and module.di_builder == null) {
                            const verify_result = handle.verify();
                            if (!verify_result.success) {
                                os.abort();
                            }
                        }
                    },
                    else => converter.report_error(),
                }
            } else {
                converter.report_error();
            }
        } else {
            if (global_type) |expected_type| {
                const value = converter.parse_value(thread, &module, null, expected_type);
                const global_variable = module.handle.create_global_variable(.{
                    .linkage = switch (is_export) {
                        true => .ExternalLinkage,
                        false => .InternalLinkage,
                    },
                    .name = global_name,
                    .initial_value = value.to_constant(),
                    .type = expected_type.get(),
                });

                const global = module.globals.add();
                global.* = .{
                    .name = global_name,
                    .storage = global_variable.to_value(),
                    .type = expected_type,
                };

                converter.skip_space();

                converter.expect_character(';');

                if (module.di_builder) |di_builder| {
                    const debug_type = expected_type.to_debug_type(&module);
                    const linkage_name = global_name;
                    const local_to_unit = is_export; // TODO: extern
                    const alignment = 0; // TODO
                    const global_variable_expression = di_builder.create_global_variable(module.global_scope, global_name, linkage_name, module.file, global_line, debug_type, local_to_unit, di_builder.null_expression(), alignment);
                    global_variable.add_debug_info(global_variable_expression);
                }
            } else {
                converter.report_error();
            }
        }
    }

    if (module.di_builder) |di_builder| {
        di_builder.finalize();
    }

    if (lib.optimization_mode == .Debug) {
        const verify_result = module.handle.verify();
        if (!verify_result.success) {
            lib.print_string(module.handle.to_string());
            lib.print_string("============================\n");
            lib.print_string(verify_result.error_message orelse unreachable);
            os.abort();
        }

        if (!lib.is_test) {
            const module_string = module.handle.to_string();
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

    const object_generate_result = llvm.object_generate(module.handle, target_machine, .{
        .optimize_when_possible = @intFromBool(@intFromEnum(options.build_mode) > @intFromEnum(BuildMode.soft_optimize)),
        .debug_info = options.has_debug_info,
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
