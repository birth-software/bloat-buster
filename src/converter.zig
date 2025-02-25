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
    @"struct",
    bits,
};

const FunctionKeyword = enum {
    cc,
    foo,
};

const CallingConvention = enum {
    unknown,
    c,

    pub fn to_llvm(calling_convention: CallingConvention) llvm.CallingConvention {
        return switch (calling_convention) {
            .unknown => .fast,
            .c => .c,
        };
    }
};

const Module = struct {
    llvm: LLVM,
    globals: Variable.Array = .{},
    types: Type.Array = .{},
    values: Value.Array = .{},
    current_function: ?*Variable = null,
    debug_tag: c_uint = 0,

    const LLVM = struct {
        context: *llvm.Context,
        handle: *llvm.Module,
        builder: *llvm.Builder,
        di_builder: ?*llvm.DI.Builder = null,
        global_scope: *llvm.DI.Scope,
        file: *llvm.DI.File,
    };

    pub fn get_type(module: *Module, index: usize) *Type {
        assert(index < module.types.count);
        const result = &module.types.buffer[index];
        return result;
    }

    pub fn integer_type(module: *Module, bit_count: u32, sign: bool) *Type {
        switch (bit_count) {
            1...64 => {
                const index = @as(usize, @intFromBool(sign)) * 64 + bit_count;
                const result = module.get_type(index);
                assert(result.bb == .integer);
                assert(result.bb.integer.bit_count == bit_count);
                assert(result.bb.integer.signed == sign);
                return result;
            },
            128 => @trap(),
            else => @trap(),
        }
    }

    pub fn void_type(module: *Module) *Type {
        const index = 8;
        const result = module.get_type(index);
        assert(result.bb == .void);
        return result;
    }

    pub fn initialize(arena: *Arena, options: ConvertOptions) *Module {
        const context = llvm.Context.create();
        const handle = context.create_module(options.name);

        var maybe_di_builder: ?*llvm.DI.Builder = null;
        var global_scope: *llvm.DI.Scope = undefined;
        var file: *llvm.DI.File = undefined;

        if (options.has_debug_info) {
            const di_builder = handle.create_di_builder();
            maybe_di_builder = di_builder;
            var directory: []const u8 = undefined;
            var file_name: []const u8 = undefined;
            if (lib.string.last_character(options.path, '/')) |index| {
                directory = options.path[0..index];
                file_name = options.path[index + 1 ..];
            } else {
                os.abort();
            }
            file = di_builder.create_file(file_name, directory);
            const compile_unit = di_builder.create_compile_unit(file, options.build_mode.is_optimized());
            global_scope = compile_unit.to_scope();
        }

        const module = arena.allocate_one(Module);
        module.* = .{
            .llvm = .{
                .global_scope = global_scope,
                .file = file,
                .handle = handle,
                .context = context,
                .builder = context.create_builder(),
            },
        };

        var llvm_integer_types: [64]*llvm.Type = undefined;

        for (1..64 + 1) |bit_count| {
            llvm_integer_types[bit_count - 1] = context.get_integer_type(@intCast(bit_count)).to_type();
        }

        const llvm_i128 = context.get_integer_type(128).to_type();

        _ = module.types.add(.{
            .name = "void",
            .llvm = .{
                .handle = context.get_void_type(),
                .debug = if (maybe_di_builder) |di_builder| di_builder.create_basic_type("void", 0, .void, .{}) else undefined,
            },
            .bb = .void,
        });

        for ([2]bool{ false, true }) |sign| {
            for (1..64 + 1) |bit_count| {
                var name_buffer = [3]u8{ if (sign) 's' else 'u', 0, 0 };
                var digit_buffer = [2]u8{ 0, 0 };

                var it = bit_count;
                var i: usize = 0;
                while (it != 0) : (i += 1) {
                    const digit: u8 = @intCast((it % 10) + '0');
                    digit_buffer[i] = digit;
                    it = it / 10;
                }

                name_buffer[1] = digit_buffer[1];
                name_buffer[2] = digit_buffer[0];

                const name_length = @as(usize, 2) + @intFromBool(bit_count > 9);

                const name = arena.duplicate_string(name_buffer[0..name_length]);
                _ = module.types.add(.{
                    .name = name,
                    .bb = .{
                        .integer = .{
                            .bit_count = @intCast(bit_count),
                            .signed = sign,
                        },
                    },
                    .llvm = .{
                        .handle = llvm_integer_types[bit_count - 1],
                        .debug = if (maybe_di_builder) |di_builder| blk: {
                            const dwarf_type: llvm.Dwarf.Type = if (bit_count == 8 and !sign) .unsigned_char else if (sign) .signed else .unsigned;
                            break :blk di_builder.create_basic_type(name, bit_count, dwarf_type, .{});
                        } else undefined,
                    },
                });
            }
        }

        for ([2]bool{ false, true }) |sign| {
            const name = if (sign) "s128" else "u128";
            _ = module.types.add(.{
                .name = name,
                .bb = .{
                    .integer = .{
                        .bit_count = 128,
                        .signed = sign,
                    },
                },
                .llvm = .{
                    .handle = llvm_i128,
                    .debug = if (maybe_di_builder) |di_builder| blk: {
                        const dwarf_type: llvm.Dwarf.Type = if (sign) .signed else .unsigned;
                        break :blk di_builder.create_basic_type(name, 128, dwarf_type, .{});
                    } else undefined,
                },
            });
        }

        return module;
    }
};

pub const Function = struct {
    current_basic_block: *llvm.BasicBlock,
    current_scope: *llvm.DI.Scope,
    locals: Variable.Array = .{},
    arguments: Variable.Array = .{},
    calling_convention: CallingConvention,
};

pub const Value = struct {
    bb: union(enum) {
        function: Function,
        local,
        global,
        argument,
        instruction,
        constant_integer,
        struct_initialization,
        bits_initialization,
    },
    type: *Type,
    llvm: *llvm.Value,

    const Array = struct {
        buffer: [64]Value = undefined,
        count: usize = 0,

        pub fn add(values: *Array) *Value {
            const result = &values.buffer[values.count];
            values.count += 1;
            return result;
        }
    };
};

const Field = struct {
    name: []const u8,
    type: *Type,
    bit_offset: usize,
    byte_offset: usize,
};

const FunctionType = struct {
    semantic_argument_types: []const *Type,
    semantic_return_type: *Type,
    calling_convention: CallingConvention,
};

const StructType = struct {
    fields: []const Field,
    bit_size: u64,
    byte_size: u64,
    bit_alignment: u64,
    byte_alignment: u64,
};

const Bits = struct {
    fields: []const Field,
    backing_type: *Type,
};

pub const Type = struct {
    bb: BB,
    llvm: LLVM,
    name: ?[]const u8,

    pub const BB = union(enum) {
        void,
        forward_declaration,
        integer: struct {
            bit_count: u32,
            signed: bool,
        },
        @"struct": StructType,
        bits: Bits,
        function: FunctionType,
    };

    pub fn get_bit_size(ty: *const Type) u64 {
        return switch (ty.bb) {
            .integer => |integer| integer.bit_count,
            .@"struct" => |struct_type| struct_type.bit_size,
            .bits => |bits| bits.backing_type.get_bit_size(),
            .void, .forward_declaration, .function => unreachable,
        };
    }

    pub fn get_byte_size(ty: *const Type) u64 {
        return switch (ty.bb) {
            .integer => |integer| @divExact(@max(8, lib.next_power_of_two(integer.bit_count)), 8),
            .@"struct" => |struct_type| struct_type.byte_size,
            .bits => |bits| bits.backing_type.get_byte_size(),
            .void, .forward_declaration, .function => unreachable,
        };
    }

    pub fn get_bit_alignment(ty: *const Type) u64 {
        return switch (ty.bb) {
            .integer => |integer| integer.bit_count,
            .@"struct" => |struct_type| struct_type.bit_alignment,
            .bits => |bits| bits.backing_type.get_bit_alignment(),
            .void, .forward_declaration, .function => unreachable,
        };
    }

    pub fn get_byte_alignment(ty: *const Type) u64 {
        return switch (ty.bb) {
            .integer => |integer| @divExact(@max(8, lib.next_power_of_two(integer.bit_count)), 8),
            .@"struct" => |struct_type| struct_type.byte_alignment,
            .bits => |bits| bits.backing_type.get_byte_alignment(),
            .void, .forward_declaration, .function => unreachable,
        };
    }

    const Array = struct {
        buffer: [1024]Type = undefined,
        count: usize = 0,

        pub fn get(types: *Array) []Type {
            return types.buffer[0..types.count];
        }

        pub fn find(types: *Array, name: []const u8) ?*Type {
            for (types.get()) |*ty| {
                if (ty.name) |type_name| {
                    if (lib.string.equal(type_name, name)) {
                        return ty;
                    }
                }
            } else {
                return null;
            }
        }

        fn add(types: *Array, ty: Type) *Type {
            const result = &types.buffer[types.count];
            types.count += 1;
            result.* = ty;
            return result;
        }
    };

    pub const LLVM = struct {
        handle: *llvm.Type,
        debug: *llvm.DI.Type,
    };
};

pub const Variable = struct {
    value: *Value,
    name: []const u8,

    const Array = struct {
        buffer: [64]Variable = undefined,
        count: u32 = 0,

        pub fn get(variables: *Array) []Variable {
            return variables.buffer[0..variables.count];
        }

        pub fn add(variables: *Array) *Variable {
            const result = &variables.buffer[variables.count];
            variables.count += 1;
            return result;
        }

        pub fn add_many(variables: *Array, count: u32) []Variable {
            const result = variables.buffer[variables.count .. variables.count + count];
            variables.count += count;
            return result;
        }

        pub fn find(variables: *Array, name: []const u8) ?*Variable {
            for (variables.get()) |*variable| {
                if (lib.string.equal(variable.name, name)) {
                    return variable;
                }
            } else {
                return null;
            }
        }
    };
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

    pub fn parse_type(noalias converter: *Converter, noalias module: *Module) *Type {
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
            const bit_count: u32 = @intCast(lib.parse.integer_decimal(identifier[1..]));
            const ty = module.integer_type(bit_count, signedness);
            return ty;
        } else {
            const ty = module.types.find(identifier) orelse @trap();
            return ty;
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

    fn parse_integer(noalias converter: *Converter, noalias module: *Module, expected_type: *Type, sign: bool) *Value {
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

        const integer_type = expected_type.llvm.handle.to_integer();
        const llvm_integer_value = integer_type.get_constant(value, @intFromBool(expected_type.bb.integer.signed));
        const integer_value = module.values.add();
        integer_value.* = .{
            .llvm = llvm_integer_value.to_value(),
            .type = expected_type,
            .bb = .constant_integer,
        };
        return integer_value;
    }

    fn expect_character(noalias converter: *Converter, expected_ch: u8) void {
        if (!converter.consume_character_if_match(expected_ch)) {
            converter.report_error();
        }
    }

    fn parse_block(noalias converter: *Converter, noalias module: *Module) void {
        converter.skip_space();

        const current_function_global = module.current_function orelse unreachable;
        const current_function = &current_function_global.value.bb.function;
        const block_line = converter.get_line();
        const block_column = converter.get_column();

        const current_scope = current_function.current_scope;
        defer current_function.current_scope = current_scope;

        if (module.llvm.di_builder) |di_builder| {
            const lexical_block = di_builder.create_lexical_block(current_scope, module.llvm.file, block_line, block_column);
            current_function.current_scope = lexical_block.to_scope();
        }

        converter.expect_character(left_brace);

        const local_offset = current_function.locals.count;
        defer current_function.locals.count = local_offset;

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
            if (module.llvm.di_builder) |_| {
                const inlined_at: ?*llvm.DI.Metadata = null; // TODO
                statement_debug_location = llvm.DI.create_debug_location(module.llvm.context, line, column, current_function.current_scope, inlined_at);
                module.llvm.builder.set_current_debug_location(statement_debug_location);
            }

            const statement_start_ch = converter.content[converter.offset];
            if (statement_start_ch == '>') {
                converter.offset += 1;

                converter.skip_space();

                const local_name = converter.parse_identifier();

                converter.skip_space();

                if (converter.consume_character_if_match(':')) {
                    converter.skip_space();

                    const local_type = converter.parse_type(module);

                    converter.skip_space();

                    converter.expect_character('=');

                    converter.skip_space();

                    if (module.llvm.di_builder) |_| {
                        module.llvm.builder.clear_current_debug_location();
                    }

                    const local_storage = module.values.add();
                    local_storage.* = .{
                        .llvm = module.llvm.builder.create_alloca(local_type.llvm.handle, local_name),
                        .type = local_type,
                        .bb = .local,
                    };

                    const value = converter.parse_value(module, local_type);

                    if (module.llvm.di_builder) |di_builder| {
                        module.llvm.builder.set_current_debug_location(statement_debug_location);
                        const debug_type = local_type.llvm.debug;
                        const always_preserve = true;
                        // TODO:
                        const alignment = 0;
                        const flags = llvm.DI.Flags{};
                        const local_variable = di_builder.create_auto_variable(current_function.current_scope, local_name, module.llvm.file, line, debug_type, always_preserve, flags, alignment);
                        const inlined_at: ?*llvm.DI.Metadata = null; // TODO
                        const debug_location = llvm.DI.create_debug_location(module.llvm.context, line, column, current_function.current_scope, inlined_at);
                        _ = di_builder.insert_declare_record_at_end(local_storage.llvm, local_variable, di_builder.null_expression(), debug_location, current_function.current_basic_block);
                        module.llvm.builder.set_current_debug_location(statement_debug_location);
                    }
                    _ = module.llvm.builder.create_store(value.llvm, local_storage.llvm);

                    const local = current_function.locals.add();
                    local.* = .{
                        .name = local_name,
                        .value = local_storage,
                    };
                } else {
                    converter.report_error();
                }
            } else if (is_identifier_start_ch(statement_start_ch)) {
                const statement_start_identifier = converter.parse_identifier();

                if (string_to_enum(StatementStartKeyword, statement_start_identifier)) |statement_start_keyword| {
                    switch (statement_start_keyword) {
                        .@"return" => {
                            const return_value = converter.parse_value(module, current_function_global.value.type.bb.function.semantic_return_type);
                            module.llvm.builder.create_ret(return_value.llvm);
                        },
                        .@"if" => {
                            const taken_block = module.llvm.context.create_basic_block("", current_function_global.value.llvm.to_function());
                            const not_taken_block = module.llvm.context.create_basic_block("", current_function_global.value.llvm.to_function());

                            converter.skip_space();

                            converter.expect_character(left_parenthesis);
                            converter.skip_space();

                            const condition = converter.parse_value(module, null);

                            converter.skip_space();
                            converter.expect_character(right_parenthesis);

                            _ = module.llvm.builder.create_conditional_branch(condition.llvm, taken_block, not_taken_block);
                            module.llvm.builder.position_at_end(taken_block);

                            converter.parse_block(module);

                            const is_first_block_terminated = current_function.current_basic_block.get_terminator() != null;
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
                                module.llvm.builder.position_at_end(not_taken_block);
                                converter.parse_block(module);
                                is_second_block_terminated = current_function.current_basic_block.get_terminator() != null;
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
                    converter.skip_space();

                    if (converter.consume_character_if_match(left_parenthesis)) {
                        // This is a call
                        const variable = if (current_function.locals.find(statement_start_identifier)) |local| local else if (module.globals.find(statement_start_identifier)) |global| global else {
                            converter.report_error();
                        };
                        const call = module.llvm.builder.create_call(variable.value.type.llvm.handle.to_function(), variable.value.llvm, &.{});
                        _ = call;
                        @trap();
                    } else {
                        converter.report_error();
                    }
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

    fn parse_value(noalias converter: *Converter, noalias module: *Module, maybe_expected_type: ?*Type) *Value {
        converter.skip_space();

        var value_state = ExpressionState.none;
        var previous_value: ?*Value = null;
        var iterations: usize = 0;
        var iterative_expected_type = maybe_expected_type;

        const value: *Value = while (true) : (iterations += 1) {
            if (iterations == 1 and iterative_expected_type == null) {
                iterative_expected_type = previous_value.?.type;
            }

            const current_value = switch (converter.consume_character_if_match(left_parenthesis)) {
                true => blk: {
                    const r = converter.parse_value(module, iterative_expected_type);
                    converter.skip_space();
                    converter.expect_character(right_parenthesis);
                    break :blk r;
                },
                false => converter.parse_single_value(module, iterative_expected_type),
            };

            converter.skip_space();

            const left = previous_value;
            const right = current_value;
            const next_ty = if (previous_value) |pv| pv.type else current_value.type;
            // _ = left;
            // _ = right;

            const llvm_value = switch (value_state) {
                .none => current_value.llvm,
                .sub => module.llvm.builder.create_sub(left.?.llvm, right.llvm),
                .add => module.llvm.builder.create_add(left.?.llvm, right.llvm),
                .mul => module.llvm.builder.create_mul(left.?.llvm, right.llvm),
                .sdiv => module.llvm.builder.create_sdiv(left.?.llvm, right.llvm),
                .udiv => module.llvm.builder.create_udiv(left.?.llvm, right.llvm),
                .srem => module.llvm.builder.create_srem(left.?.llvm, right.llvm),
                .urem => module.llvm.builder.create_urem(left.?.llvm, right.llvm),
                .shl => module.llvm.builder.create_shl(left.?.llvm, right.llvm),
                .ashr => module.llvm.builder.create_ashr(left.?.llvm, right.llvm),
                .lshr => module.llvm.builder.create_lshr(left.?.llvm, right.llvm),
                .@"and" => module.llvm.builder.create_and(left.?.llvm, right.llvm),
                .@"or" => module.llvm.builder.create_or(left.?.llvm, right.llvm),
                .xor => module.llvm.builder.create_xor(left.?.llvm, right.llvm),
                .icmp_ne => |icmp| module.llvm.builder.create_compare(icmp.to_int_predicate(), left.?.llvm, right.llvm),
            };

            previous_value = module.values.add();
            previous_value.?.* = .{
                .llvm = llvm_value,
                .type = next_ty,
                .bb = .instruction,
            };

            const ch = converter.content[converter.offset];
            value_state = switch (ch) {
                ',', ';', right_parenthesis => break previous_value.?,
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
                    const ty = iterative_expected_type orelse unreachable;
                    break :blk switch (ty.bb) {
                        .integer => |int| switch (int.signed) {
                            true => .sdiv,
                            false => .udiv,
                        },
                        else => unreachable,
                    };
                },
                '%' => blk: {
                    converter.offset += 1;
                    const ty = iterative_expected_type orelse unreachable;
                    break :blk switch (ty.bb) {
                        .integer => |int| switch (int.signed) {
                            true => .srem,
                            false => .urem,
                        },
                        else => unreachable,
                    };
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
                            const ty = iterative_expected_type orelse unreachable;
                            break :b switch (ty.bb) {
                                .integer => |int| switch (int.signed) {
                                    true => .ashr,
                                    false => .lshr,
                                },
                                else => unreachable,
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

    const Intrinsic = enum {
        extend,
        foo,
    };

    fn parse_intrinsic(noalias converter: *Converter, noalias module: *Module, expected_type: ?*Type) *Value {
        converter.expect_character('#');
        converter.skip_space();
        const intrinsic_name = converter.parse_identifier();
        const intrinsic_keyword = string_to_enum(Intrinsic, intrinsic_name) orelse converter.report_error();
        converter.skip_space();

        converter.expect_character(left_parenthesis);

        converter.skip_space();

        switch (intrinsic_keyword) {
            .extend => {
                const source_value = converter.parse_value(module, null);
                converter.skip_space();
                converter.expect_character(right_parenthesis);
                const source_type = source_value.type;
                const destination_type = expected_type orelse converter.report_error();
                if (source_type.get_bit_size() >= destination_type.get_bit_size()) {
                    converter.report_error();
                }

                const extension_instruction = switch (source_type.bb.integer.signed) {
                    true => module.llvm.builder.create_sign_extend(source_value.llvm, destination_type.llvm.handle),
                    false => module.llvm.builder.create_zero_extend(source_value.llvm, destination_type.llvm.handle),
                };
                const value = module.values.add();
                value.* = .{
                    .llvm = extension_instruction,
                    .type = destination_type,
                    .bb = .instruction,
                };

                return value;
            },
            else => unreachable,
        }
    }

    fn parse_single_value(noalias converter: *Converter, noalias module: *Module, expected_type: ?*Type) *Value {
        converter.skip_space();

        if (module.current_function) |function| {
            if (module.llvm.di_builder) |_| {
                const line = converter.get_line();
                const column = converter.get_column();
                const inlined_at: ?*llvm.DI.Metadata = null; // TODO
                const debug_location = llvm.DI.create_debug_location(module.llvm.context, line, column, function.value.bb.function.current_scope, inlined_at);
                module.llvm.builder.set_current_debug_location(debug_location);
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
            left_brace => {
                converter.offset += 1;

                converter.skip_space();

                const ty = expected_type orelse converter.report_error();
                const must_be_constant = module.current_function == null;

                switch (ty.bb) {
                    .@"struct" => |*struct_type| {
                        var field_count: usize = 0;

                        var llvm_value = switch (must_be_constant) {
                            true => @trap(),
                            false => ty.llvm.handle.get_poison(),
                        };

                        while (converter.consume_character_if_match('.')) : (field_count += 1) {
                            converter.skip_space();

                            const field_name = converter.parse_identifier();
                            const field_index: u32 = for (struct_type.fields, 0..) |*field, field_index| {
                                if (lib.string.equal(field.name, field_name)) {
                                    break @intCast(field_index);
                                }
                            } else converter.report_error();

                            const field = struct_type.fields[field_index];

                            converter.skip_space();

                            converter.expect_character('=');

                            converter.skip_space();

                            const field_value = converter.parse_value(module, field.type);

                            if (must_be_constant) {
                                if (field_index != field_count) {
                                    converter.report_error();
                                }
                                @trap();
                            } else {
                                llvm_value = module.llvm.builder.create_insert_value(llvm_value, field_value.llvm, field_index);
                            }

                            converter.skip_space();

                            _ = converter.consume_character_if_match(',');

                            converter.skip_space();
                        }

                        if (field_count != struct_type.fields.len) {
                            // expect: 'zero' keyword
                            @trap();
                        }

                        converter.expect_character(right_brace);

                        const value = module.values.add();
                        value.* = .{
                            .llvm = llvm_value,
                            .type = ty,
                            .bb = .struct_initialization,
                        };

                        return value;
                    },
                    .bits => |*bits| {
                        var field_count: usize = 0;

                        var llvm_value = bits.backing_type.llvm.handle.to_integer().get_constant(0, @intFromBool(false)).to_value();

                        while (converter.consume_character_if_match('.')) : (field_count += 1) {
                            converter.skip_space();

                            const field_name = converter.parse_identifier();
                            const field_index: u32 = for (bits.fields, 0..) |*field, field_index| {
                                if (lib.string.equal(field.name, field_name)) {
                                    break @intCast(field_index);
                                }
                            } else converter.report_error();

                            const field = bits.fields[field_index];

                            converter.skip_space();

                            converter.expect_character('=');

                            converter.skip_space();

                            const field_value = converter.parse_value(module, field.type);

                            const extended_field_value = module.llvm.builder.create_zero_extend(field_value.llvm, bits.backing_type.llvm.handle);
                            const shifted_value = module.llvm.builder.create_shl(extended_field_value, bits.backing_type.llvm.handle.to_integer().get_constant(field.bit_offset, @intFromBool(false)).to_value());
                            const or_value = module.llvm.builder.create_or(llvm_value, shifted_value);
                            llvm_value = or_value;

                            converter.skip_space();

                            _ = converter.consume_character_if_match(',');

                            converter.skip_space();
                        }

                        if (field_count != bits.fields.len) {
                            // expect: 'zero' keyword
                            @trap();
                        }

                        converter.expect_character(right_brace);

                        const value = module.values.add();
                        value.* = .{
                            .llvm = llvm_value,
                            .type = ty,
                            .bb = .bits_initialization,
                        };

                        return value;
                    },
                    else => converter.report_error(),
                }

                @trap();
            },
            '#' => return converter.parse_intrinsic(module, expected_type),
            else => os.abort(),
        };

        const value_offset = converter.offset;
        const value_start_ch = converter.content[value_offset];
        const value = switch (value_start_ch) {
            'a'...'z', 'A'...'Z', '_' => b: {
                if (module.current_function) |current_function| {
                    const identifier = converter.parse_identifier();
                    const variable = blk: {
                        if (current_function.value.bb.function.locals.find(identifier)) |local| {
                            break :blk local;
                        } else if (current_function.value.bb.function.arguments.find(identifier)) |argument| {
                            break :blk argument;
                        } else if (module.globals.find(identifier)) |global| {
                            break :blk global;
                        } else {
                            converter.report_error();
                        }
                    };

                    converter.skip_space();

                    if (converter.consume_character_if_match(left_parenthesis)) {
                        var llvm_arguments: [64]*llvm.Value = undefined;
                        var argument_count: usize = 0;
                        while (true) : (argument_count += 1) {
                            converter.skip_space();

                            if (converter.consume_character_if_match(right_parenthesis)) {
                                break;
                            }

                            switch (variable.value.type.bb.function.calling_convention) {
                                .c => {
                                    @trap();
                                },
                                .unknown => {
                                    const argument_value = converter.parse_value(module, variable.value.type.bb.function.semantic_argument_types[argument_count]);
                                    llvm_arguments[argument_count] = argument_value.llvm;
                                },
                            }
                        }

                        const llvm_argument_values = llvm_arguments[0..argument_count];
                        const llvm_call = module.llvm.builder.create_call(variable.value.type.llvm.handle.to_function(), variable.value.llvm, llvm_argument_values);
                        llvm_call.to_instruction().set_calling_convention(variable.value.llvm.get_calling_convention());
                        const call = module.values.add();
                        call.* = .{
                            .llvm = llvm_call,
                            .type = variable.value.type,
                            .bb = .instruction,
                        };
                        break :b call;
                    } else if (converter.consume_character_if_match('.')) {
                        converter.skip_space();

                        switch (variable.value.type.bb) {
                            .@"struct" => |*struct_type| {
                                const field_name = converter.parse_identifier();
                                const field_index: u32 = for (struct_type.fields, 0..) |field, field_index| {
                                    if (lib.string.equal(field.name, field_name)) {
                                        break @intCast(field_index);
                                    }
                                } else converter.report_error();
                                const field = struct_type.fields[field_index];
                                const gep = module.llvm.builder.create_struct_gep(variable.value.type.llvm.handle.to_struct(), variable.value.llvm, field_index);
                                const load = module.values.add();
                                load.* = .{
                                    .llvm = module.llvm.builder.create_load(field.type.llvm.handle, gep),
                                    .type = field.type,
                                    .bb = .instruction,
                                };
                                break :b load;
                            },
                            .bits => |*bits| {
                                const field_name = converter.parse_identifier();
                                const field_index: u32 = for (bits.fields, 0..) |field, field_index| {
                                    if (lib.string.equal(field.name, field_name)) {
                                        break @intCast(field_index);
                                    }
                                } else converter.report_error();
                                const field = bits.fields[field_index];

                                const bitfield_load = module.llvm.builder.create_load(bits.backing_type.llvm.handle, variable.value.llvm);
                                const bitfield_shifted = module.llvm.builder.create_lshr(bitfield_load, bits.backing_type.llvm.handle.to_integer().get_constant(field.bit_offset, @intFromBool(false)).to_value());
                                const bitfield_masked = module.llvm.builder.create_and(bitfield_shifted, bits.backing_type.llvm.handle.to_integer().get_constant((@as(u64, 1) << @intCast(field.type.get_bit_size())) - 1, @intFromBool(false)).to_value());

                                const value = module.values.add();
                                value.* = .{
                                    .type = bits.backing_type,
                                    .llvm = bitfield_masked,
                                    .bb = .instruction,
                                };

                                break :b value;
                            },
                            else => @trap(),
                        }
                    } else {
                        const load = module.values.add();
                        load.* = .{
                            .llvm = module.llvm.builder.create_load(variable.value.type.llvm.handle, variable.value.llvm),
                            .type = variable.value.type,
                            .bb = .instruction,
                        };
                        break :b load;
                    }
                } else {
                    converter.report_error();
                }
            },
            '0'...'9' => converter.parse_integer(module, expected_type.?, prefix == .negative),
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
    executable: [:0]const u8,
    build_mode: BuildMode,
    name: []const u8,
    has_debug_info: bool,
    objects: []const [:0]const u8,
};

pub noinline fn convert(options: ConvertOptions) void {
    var converter = Converter{
        .content = options.content,
        .offset = 0,
        .line_offset = 0,
        .line_character_offset = 0,
    };

    llvm.default_initialize();

    const module = Module.initialize(lib.global.arena, options);

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

        if (module.types.find(global_name) != null) @trap();
        if (module.globals.find(global_name) != null) @trap();

        converter.skip_space();

        var global_type: ?*Type = null;
        if (converter.consume_character_if_match(':')) {
            converter.skip_space();

            global_type = converter.parse_type(module);

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

                        const Argument = struct {
                            name: []const u8,
                            type: *Type,
                            line: u32,
                            column: u32,
                        };
                        var argument_buffer: [64]Argument = undefined;
                        var argument_count: u32 = 0;

                        while (converter.offset < converter.content.len and converter.content[converter.offset] != right_parenthesis) : (argument_count += 1) {
                            converter.skip_space();

                            const argument_line = converter.get_line();
                            const argument_column = converter.get_column();

                            const argument_name = converter.parse_identifier();

                            converter.skip_space();

                            converter.expect_character(':');

                            converter.skip_space();

                            const argument_type = converter.parse_type(module);

                            converter.skip_space();

                            _ = converter.consume_character_if_match(',');

                            argument_buffer[argument_count] = .{
                                .name = argument_name,
                                .type = argument_type,
                                .line = argument_line,
                                .column = argument_column,
                            };
                        }

                        converter.expect_character(right_parenthesis);

                        converter.skip_space();

                        const return_type = converter.parse_type(module);
                        const linkage_name = global_name;

                        var argument_type_buffer: [argument_buffer.len]*llvm.Type = undefined;
                        var debug_argument_type_buffer: [argument_buffer.len + 1]*llvm.DI.Type = undefined;

                        const arguments = argument_buffer[0..argument_count];
                        const argument_types = argument_type_buffer[0..argument_count];
                        const debug_argument_types = debug_argument_type_buffer[0 .. argument_count + 1];

                        debug_argument_types[0] = return_type.llvm.debug;

                        if (argument_count > 0) {
                            switch (calling_convention) {
                                .unknown => {
                                    for (arguments, argument_types, debug_argument_types[1..]) |*argument, *argument_type, *debug_argument_type| {
                                        argument_type.* = argument.type.llvm.handle;
                                        debug_argument_type.* = argument.type.llvm.debug;
                                        if (module.llvm.di_builder) |_| {
                                            assert(@intFromPtr(argument.type.llvm.debug) != 0xaaaa_aaaa_aaaa_aaaa);
                                        }
                                    }
                                },
                                // TODO: C calling convention
                                .c => @trap(),
                            }
                        }

                        const llvm_function_type = llvm.Type.Function.get(return_type.llvm.handle, argument_types, false);
                        const llvm_handle = module.llvm.handle.create_function(.{
                            .name = global_name,
                            .linkage = switch (is_export) {
                                true => .ExternalLinkage,
                                false => .InternalLinkage,
                            },
                            .type = llvm_function_type,
                        });
                        llvm_handle.set_calling_convention(calling_convention.to_llvm());

                        const entry_block = module.llvm.context.create_basic_block("entry", llvm_handle);
                        module.llvm.builder.position_at_end(entry_block);

                        const global = module.globals.add();

                        var subroutine_type: *llvm.DI.Type.Subroutine = undefined;
                        const current_scope: *llvm.DI.Scope = if (module.llvm.di_builder) |di_builder| blk: {
                            const subroutine_type_flags = llvm.DI.Flags{};
                            subroutine_type = di_builder.create_subroutine_type(module.llvm.file, debug_argument_types, subroutine_type_flags);
                            const scope_line: u32 = @intCast(converter.line_offset + 1);
                            const local_to_unit = !is_export;
                            const flags = llvm.DI.Flags{};
                            const is_definition = true;
                            const subprogram = di_builder.create_function(module.llvm.global_scope, global_name, linkage_name, module.llvm.file, global_line, subroutine_type, local_to_unit, is_definition, scope_line, flags, options.build_mode.is_optimized());
                            llvm_handle.set_subprogram(subprogram);

                            break :blk @ptrCast(subprogram);
                        } else undefined;

                        const function_type = module.types.add(.{
                            .name = null,
                            .llvm = .{
                                .handle = llvm_function_type.to_type(),
                                .debug = subroutine_type.to_type(),
                            },
                            .bb = .{
                                .function = .{
                                    .calling_convention = calling_convention,
                                    .semantic_return_type = return_type,
                                    .semantic_argument_types = blk: {
                                        const semantic_argument_types = lib.global.arena.allocate(*Type, argument_count);
                                        for (arguments, semantic_argument_types) |argument, *argument_type| {
                                            argument_type.* = argument.type;
                                        }

                                        break :blk semantic_argument_types;
                                    },
                                },
                            },
                        });

                        const value = module.values.add();
                        value.* = .{
                            .llvm = llvm_handle.to_value(),
                            .type = function_type,
                            .bb = .{
                                .function = .{
                                    .current_basic_block = entry_block,
                                    .calling_convention = calling_convention,
                                    .current_scope = current_scope,
                                },
                            },
                        };

                        global.* = .{
                            .value = value,
                            .name = global_name,
                        };

                        module.current_function = global;
                        defer module.current_function = null;

                        const argument_variables = global.value.bb.function.arguments.add_many(argument_count);

                        for (argument_variables, arguments) |*argument_variable, *argument| {
                            const argument_alloca = module.llvm.builder.create_alloca(argument.type.llvm.handle, argument.name);
                            const argument_value = module.values.add();
                            argument_value.* = .{
                                .llvm = argument_alloca,
                                .type = argument.type,
                                .bb = .argument,
                            };
                            argument_variable.* = .{
                                .value = argument_value,
                                .name = argument.name,
                            };
                        }

                        var llvm_argument_buffer: [argument_buffer.len]*llvm.Argument = undefined;
                        llvm_handle.get_arguments(&llvm_argument_buffer);
                        const llvm_arguments = llvm_argument_buffer[0..argument_count];

                        if (argument_count > 0) {
                            switch (calling_convention) {
                                .unknown => {
                                    for (argument_variables, llvm_arguments) |*argument_variable, llvm_argument| {
                                        _ = module.llvm.builder.create_store(llvm_argument.to_value(), argument_variable.value.llvm);
                                    }
                                },
                                .c => @trap(),
                            }

                            if (module.llvm.di_builder) |di_builder| {
                                for (argument_variables, arguments, 0..) |argument_variable, argument, argument_number| {
                                    const always_preserve = true;
                                    const flags = llvm.DI.Flags{};
                                    const parameter_variable = di_builder.create_parameter_variable(global.value.bb.function.current_scope, argument_variable.name, @intCast(argument_number + 1), module.llvm.file, argument.line, argument.type.llvm.debug, always_preserve, flags);
                                    const inlined_at: ?*llvm.DI.Metadata = null; // TODO
                                    const debug_location = llvm.DI.create_debug_location(module.llvm.context, argument.line, argument.column, global.value.bb.function.current_scope, inlined_at);
                                    _ = di_builder.insert_declare_record_at_end(argument_variable.value.llvm, parameter_variable, di_builder.null_expression(), debug_location, global.value.bb.function.current_basic_block);
                                }
                            }
                        }

                        converter.parse_block(module);

                        if (module.llvm.di_builder) |di_builder| {
                            di_builder.finalize_subprogram(llvm_handle.get_subprogram());
                        }

                        if (lib.optimization_mode == .Debug and module.llvm.di_builder == null) {
                            const verify_result = llvm_handle.verify();
                            if (!verify_result.success) {
                                os.abort();
                            }
                        }
                    },
                    .@"struct" => {
                        converter.skip_space();

                        converter.expect_character(left_brace);

                        if (module.types.find(global_name) != null) {
                            @trap();
                        }

                        const llvm_struct_type = module.llvm.context.create_forward_declared_struct_type(global_name);
                        const struct_type = module.types.add(.{
                            .name = global_name,
                            .bb = .forward_declaration,
                            .llvm = .{
                                .handle = llvm_struct_type.to_type(),
                                .debug = if (module.llvm.di_builder) |di_builder| blk: {
                                    const r = di_builder.create_replaceable_composite_type(module.debug_tag, global_name, module.llvm.global_scope, module.llvm.file, global_line);
                                    module.debug_tag += 1;
                                    break :blk r.to_type();
                                } else undefined,
                            },
                        });

                        var field_buffer: [256]Field = undefined;
                        var llvm_field_type_buffer: [field_buffer.len]*llvm.Type = undefined;
                        var llvm_debug_member_type_buffer: [field_buffer.len]*llvm.DI.Type.Derived = undefined;
                        var field_count: usize = 0;
                        var byte_offset: u64 = 0;
                        var byte_alignment: u64 = 1;
                        var bit_alignment: u64 = 1;

                        while (true) {
                            converter.skip_space();

                            if (converter.consume_character_if_match(right_brace)) {
                                break;
                            }

                            const field_line = converter.get_line();
                            const field_name = converter.parse_identifier();

                            converter.skip_space();

                            converter.expect_character(':');

                            converter.skip_space();

                            const field_type = converter.parse_type(module);

                            const field_bit_offset = byte_offset * 8;
                            const field_byte_offset = byte_offset;
                            const field_bit_size = field_type.get_bit_size();
                            const field_byte_size = field_type.get_byte_size();
                            const field_byte_alignment = field_type.get_byte_alignment();
                            const field_bit_alignment = field_type.get_bit_alignment();
                            field_buffer[field_count] = .{
                                .byte_offset = field_byte_offset,
                                .bit_offset = field_bit_offset,
                                .type = field_type,
                                .name = field_name,
                            };
                            llvm_field_type_buffer[field_count] = field_type.llvm.handle;

                            if (module.llvm.di_builder) |di_builder| {
                                const member_type = di_builder.create_member_type(module.llvm.global_scope, field_name, module.llvm.file, field_line, field_bit_size, @intCast(field_bit_alignment), field_bit_offset, .{}, field_type.llvm.debug);
                                llvm_debug_member_type_buffer[field_count] = member_type;
                            }

                            byte_alignment = @max(byte_alignment, field_byte_alignment);
                            bit_alignment = @max(bit_alignment, field_bit_alignment);
                            byte_offset += field_byte_size;

                            field_count += 1;

                            converter.skip_space();

                            switch (converter.content[converter.offset]) {
                                ',' => converter.offset += 1,
                                else => {},
                            }
                        }

                        converter.skip_space();

                        _ = converter.consume_character_if_match(';');

                        const byte_size = byte_offset;
                        const bit_size = byte_size * 8;

                        const fields = lib.global.arena.allocate(Field, field_count);
                        @memcpy(fields, field_buffer[0..field_count]);

                        const element_types = llvm_field_type_buffer[0..field_count];
                        llvm_struct_type.set_body(element_types);

                        if (module.llvm.di_builder) |di_builder| {
                            const member_types = llvm_debug_member_type_buffer[0..field_count];
                            const debug_struct_type = di_builder.create_struct_type(module.llvm.global_scope, global_name, module.llvm.file, global_line, bit_size, @intCast(bit_alignment), .{}, member_types);
                            const forward_declared: *llvm.DI.Type.Composite = @ptrCast(struct_type.llvm.debug);
                            forward_declared.replace_all_uses_with(debug_struct_type);
                            struct_type.llvm.debug = debug_struct_type.to_type();
                        }

                        struct_type.bb = .{
                            .@"struct" = .{
                                .bit_size = byte_size * 8,
                                .byte_size = byte_size,
                                .bit_alignment = bit_alignment,
                                .byte_alignment = byte_alignment,
                                .fields = fields,
                            },
                        };
                    },
                    .bits => {
                        // TODO: allow implicit backing type?
                        const backing_type = converter.parse_type(module);
                        if (backing_type.bb != .integer) {
                            converter.report_error();
                        }

                        if (backing_type.get_bit_size() > 64) {
                            converter.report_error();
                        }

                        converter.skip_space();

                        converter.expect_character(left_brace);

                        var field_buffer: [128]Field = undefined;
                        var llvm_debug_field_buffer: [128]*llvm.DI.Type.Derived = undefined;
                        var field_count: usize = 0;

                        var field_bit_offset: u64 = 0;

                        while (true) : (field_count += 1) {
                            converter.skip_space();

                            if (converter.consume_character_if_match(right_brace)) {
                                break;
                            }

                            const field_line = converter.get_line();

                            const field_name = converter.parse_identifier();

                            converter.skip_space();

                            converter.expect_character(':');

                            converter.skip_space();

                            const field_type = converter.parse_type(module);

                            field_buffer[field_count] = .{
                                .name = field_name,
                                .type = field_type,
                                .bit_offset = field_bit_offset,
                                .byte_offset = 0,
                            };

                            const field_bit_size = field_type.get_bit_size();
                            field_bit_offset += field_bit_size;

                            if (module.llvm.di_builder) |di_builder| {
                                const member_type = di_builder.create_bit_field_member_type(module.llvm.global_scope, field_name, module.llvm.file, field_line, field_bit_size, field_bit_offset, 0, .{}, backing_type.llvm.debug);
                                llvm_debug_field_buffer[field_count] = member_type;
                            }

                            converter.skip_space();

                            _ = converter.consume_character_if_match(',');
                        }

                        _ = converter.consume_character_if_match(';');

                        const fields = lib.global.arena.allocate(Field, field_count);
                        @memcpy(fields, field_buffer[0..field_count]);

                        const bit_size = backing_type.get_bit_size();
                        const bit_alignment = backing_type.get_bit_alignment();

                        const debug_member_types = llvm_debug_field_buffer[0..field_count];

                        _ = module.types.add(.{
                            .name = global_name,
                            .llvm = .{
                                .handle = backing_type.llvm.handle,
                                .debug = if (module.llvm.di_builder) |di_builder| di_builder.create_struct_type(module.llvm.global_scope, global_name, module.llvm.file, global_line, bit_size, @intCast(bit_alignment), .{}, debug_member_types).to_type() else undefined,
                            },
                            .bb = .{
                                .bits = .{
                                    .fields = fields,
                                    .backing_type = backing_type,
                                },
                            },
                        });
                    },
                }
            } else {
                converter.report_error();
            }
        } else {
            if (global_type) |expected_type| {
                const value = converter.parse_value(module, expected_type);

                converter.skip_space();

                converter.expect_character(';');

                const global_variable = module.llvm.handle.create_global_variable(.{
                    .linkage = switch (is_export) {
                        true => .ExternalLinkage,
                        false => .InternalLinkage,
                    },
                    .name = global_name,
                    .initial_value = value.llvm.to_constant(),
                    .type = expected_type.llvm.handle,
                });

                if (module.llvm.di_builder) |di_builder| {
                    const linkage_name = global_name;
                    const local_to_unit = is_export; // TODO: extern
                    const alignment = 0; // TODO
                    const global_variable_expression = di_builder.create_global_variable(module.llvm.global_scope, global_name, linkage_name, module.llvm.file, global_line, expected_type.llvm.debug, local_to_unit, di_builder.null_expression(), alignment);
                    global_variable.add_debug_info(global_variable_expression);
                }

                const global_value = module.values.add();
                global_value.* = .{
                    .llvm = global_variable.to_value(),
                    .type = expected_type,
                    .bb = .global,
                };

                const global = module.globals.add();
                global.* = .{
                    .name = global_name,
                    .value = global_value,
                };
            } else {
                converter.report_error();
            }
        }
    }

    if (module.llvm.di_builder) |di_builder| {
        di_builder.finalize();
    }

    if (lib.optimization_mode == .Debug) {
        const verify_result = module.llvm.handle.verify();
        if (!verify_result.success) {
            lib.print_string(module.llvm.handle.to_string());
            lib.print_string("============================\n");
            lib.print_string(verify_result.error_message orelse unreachable);
            os.abort();
        }

        if (!lib.is_test) {
            const module_string = module.llvm.handle.to_string();
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

    const object_generate_result = llvm.object_generate(module.llvm.handle, target_machine, .{
        .optimize_when_possible = @intFromBool(@intFromEnum(options.build_mode) > @intFromEnum(BuildMode.soft_optimize)),
        .debug_info = options.has_debug_info,
        .optimization_level = if (options.build_mode != .debug_none) options.build_mode.to_llvm_ir() else null,
        .path = options.objects[0],
    });

    switch (object_generate_result) {
        .success => {
            const result = llvm.link(lib.global.arena, .{
                .output_path = options.executable,
                .objects = options.objects,
            });

            switch (result.success) {
                true => {},
                false => os.abort(),
            }
        },
        else => os.abort(),
    }
}
