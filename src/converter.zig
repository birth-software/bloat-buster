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

fn array_type_name(element_count: u64, noalias array: *ArrayType) [:0]const u8 {
    var buffer: [256]u8 = undefined;
    var i: usize = 0;
    buffer[i] = left_bracket;
    i += 1;
    i += lib.string_format.integer_decimal(buffer[i..], element_count);
    buffer[i] = right_bracket;
    i += 1;
    const element_name = array.element_type.name.?;
    @memcpy(buffer[i..][0..element_name.len], element_name);
    i += element_name.len;
    return lib.global.arena.duplicate_string(buffer[0..i]);
}

fn array_type_llvm(noalias module: *Module, noalias array: *ArrayType) Type.LLVM {
    const element_count = array.element_count.?;
    return .{
        .handle = array.element_type.llvm.handle.get_array_type(element_count).to_type(),
        .debug = if (module.llvm.di_builder) |di_builder| di_builder.create_array_type(element_count, @intCast(array.element_type.get_bit_alignment()), array.element_type.llvm.debug, &.{}).to_type() else undefined,
    };
}

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
    void_type: *Type = undefined,
    noreturn_type: *Type = undefined,

    const LLVM = struct {
        context: *llvm.Context,
        handle: *llvm.Module,
        builder: *llvm.Builder,
        di_builder: ?*llvm.DI.Builder = null,
        global_scope: *llvm.DI.Scope,
        file: *llvm.DI.File,
    };

    pub fn get_infer_or_ignore_value(module: *Module) *Value {
        return &module.values.buffer[0];
    }

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

        module.void_type = module.types.add(.{
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

        module.noreturn_type = module.types.add(.{
            .name = "noreturn",
            .llvm = .{
                .handle = context.get_void_type(),
                .debug = if (maybe_di_builder) |di_builder| di_builder.create_basic_type("noreturn", 0, .void, .{ .no_return = true }) else undefined,
            },
            .bb = .noreturn,
        });

        const infer_or_ignore_value = module.values.add();
        infer_or_ignore_value.* = .{
            .llvm = undefined,
            .bb = .infer_or_ignore,
            .type = undefined,
        };

        return module;
    }
};

pub const Function = struct {
    current_basic_block: *llvm.BasicBlock,
    current_scope: *llvm.DI.Scope,
    locals: Variable.Array = .{},
    arguments: Variable.Array = .{},
};

pub const ConstantInteger = struct {
    value: u64,
    signed: bool,
};

pub const Value = struct {
    bb: union(enum) {
        function: Function,
        local,
        global,
        argument,
        instruction,
        struct_initialization,
        bits_initialization,
        infer_or_ignore,
        constant_integer: ConstantInteger,
        constant_array,
        external_function,
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

    pub fn is_constant(value: *Value) bool {
        return switch (value.bb) {
            .constant_integer => true,
            else => @trap(),
        };
    }
};

const Field = struct {
    name: []const u8,
    type: *Type,
    bit_offset: usize,
    byte_offset: usize,
};

const FunctionType = struct {
    return_type_abi: Abi.Information,
    semantic_return_type: *Type,
    semantic_argument_types: [*]const *Type,
    argument_type_abis: [*]const Abi.Information,
    abi_argument_types: [*]const *Type,
    semantic_argument_count: u32,
    abi_argument_count: u32,
    calling_convention: CallingConvention,

    fn get_semantic_argument_types(function_type: *const FunctionType) []const *Type {
        return function_type.semantic_argument_types[0..function_type.semantic_argument_count];
    }

    fn get_argument_type_abis(function_type: *const FunctionType) []const Abi.Information {
        return function_type.argument_type_abis[0..function_type.semantic_argument_count];
    }

    fn get_abi_argument_types(function_type: *const FunctionType) []const *Type {
        return function_type.abi_argument_types[0..function_type.abi_argument_count];
    }
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

pub const ArrayType = struct {
    element_count: ?usize,
    element_type: *Type,
};

pub const Type = struct {
    bb: BB,
    llvm: LLVM,
    name: ?[]const u8,

    pub const BB = union(enum) {
        void,
        noreturn,
        forward_declaration,
        integer: struct {
            bit_count: u32,
            signed: bool,
        },
        @"struct": StructType,
        bits: Bits,
        function: FunctionType,
        array: ArrayType,
    };

    pub fn is_aggregate(ty: *const Type) bool {
        return switch (ty.bb) {
            .@"struct" => true,
            else => false,
        };
    }

    pub fn get_bit_size(ty: *const Type) u64 {
        return switch (ty.bb) {
            .integer => |integer| integer.bit_count,
            .@"struct" => |struct_type| struct_type.bit_size,
            .bits => |bits| bits.backing_type.get_bit_size(),
            .void, .forward_declaration, .function, .noreturn => unreachable,
            .array => |*array| array.element_type.get_bit_size() * array.element_count.?,
        };
    }

    pub fn get_byte_size(ty: *const Type) u64 {
        return switch (ty.bb) {
            .integer => |integer| @divExact(@max(8, lib.next_power_of_two(integer.bit_count)), 8),
            .@"struct" => |struct_type| struct_type.byte_size,
            .bits => |bits| bits.backing_type.get_byte_size(),
            .void, .forward_declaration, .function, .noreturn => unreachable,
            .array => |*array| array.element_type.get_byte_size() * array.element_count.?,
        };
    }

    pub fn get_bit_alignment(ty: *const Type) u64 {
        return switch (ty.bb) {
            .integer => |integer| integer.bit_count,
            .@"struct" => |struct_type| struct_type.bit_alignment,
            .bits => |bits| bits.backing_type.get_bit_alignment(),
            .void, .forward_declaration, .function, .noreturn => unreachable,
            .array => |*array| array.element_type.get_bit_alignment(),
        };
    }

    pub fn get_byte_alignment(ty: *const Type) u64 {
        return switch (ty.bb) {
            .integer => |integer| @divExact(@max(8, lib.next_power_of_two(integer.bit_count)), 8),
            .@"struct" => |struct_type| struct_type.byte_alignment,
            .bits => |bits| bits.backing_type.get_byte_alignment(),
            .void, .forward_declaration, .function, .noreturn => unreachable,
            .array => |*array| array.element_type.get_byte_alignment(),
        };
    }

    const Array = struct {
        buffer: [1024]Type = undefined,
        count: usize = 0,

        const buffer_size = 1024;

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
        switch (converter.content[converter.offset]) {
            'a'...'z', 'A'...'Z', '_' => {
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
                } else if (lib.string.equal(identifier, "noreturn")) {
                    return module.noreturn_type;
                } else {
                    const ty = module.types.find(identifier) orelse @trap();
                    return ty;
                }
            },
            left_bracket => {
                converter.offset += 1;

                converter.skip_space();

                const length_expression = converter.parse_value(module, module.integer_type(64, false));
                converter.skip_space();
                converter.expect_character(right_bracket);

                const element_type = converter.parse_type(module);

                if (length_expression.bb == .infer_or_ignore) {
                    const ty = module.types.add(.{
                        .name = undefined,
                        .llvm = undefined,
                        .bb = .{
                            .array = .{
                                .element_count = null,
                                .element_type = element_type,
                            },
                        },
                    });
                    return ty;
                } else {
                    const ty = module.types.add(.{
                        .name = undefined,
                        .llvm = undefined,
                        .bb = .{
                            .array = .{
                                .element_count = length_expression.bb.constant_integer.value,
                                .element_type = element_type,
                            },
                        },
                    });
                    return ty;
                }
            },
            else => @trap(),
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

        const absolute_value: u64 = switch (integer_start_ch) {
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
                        '1'...'9' => converter.parse_decimal(),
                        else => unreachable,
                    },
                };
            },
            '1'...'9' => converter.parse_decimal(),
            else => unreachable,
        };

        const value: u64 = switch (sign) {
            true => @bitCast(-@as(i64, @intCast(absolute_value))),
            false => absolute_value,
        };

        const integer_type = expected_type.llvm.handle.to_integer();
        const llvm_integer_value = integer_type.get_constant(value, @intFromBool(expected_type.bb.integer.signed));
        const integer_value = module.values.add();
        integer_value.* = .{
            .llvm = llvm_integer_value.to_value(),
            .type = expected_type,
            .bb = .{
                .constant_integer = .{
                    .value = absolute_value,
                    .signed = sign,
                },
            },
        };
        return integer_value;
    }

    fn expect_character(noalias converter: *Converter, expected_ch: u8) void {
        if (!converter.consume_character_if_match(expected_ch)) {
            converter.report_error();
        }
    }

    fn parse_call(noalias converter: *Converter, noalias module: *Module, callable: *Value) *Value {
        var llvm_abi_argument_value_buffer: [64]*llvm.Value = undefined;
        const function_type = callable.type;
        const calling_convention = function_type.bb.function.calling_convention;
        _ = calling_convention;
        const llvm_indirect_return_value: ?*Value = switch (function_type.bb.function.return_type_abi.kind) {
            .indirect => @trap(),
            else => null,
        };

        var semantic_argument_count: usize = 0;
        var abi_argument_count: usize = 0;
        const function_semantic_argument_count = function_type.bb.function.semantic_argument_count;

        while (true) : (semantic_argument_count += 1) {
            converter.skip_space();

            if (converter.consume_character_if_match(right_parenthesis)) {
                break;
            }

            const semantic_argument_index = semantic_argument_count;
            if (semantic_argument_index >= function_semantic_argument_count) {
                converter.report_error();
            }

            const semantic_argument_value = converter.parse_value(module, function_type.bb.function.semantic_argument_types[semantic_argument_index]);

            const argument_abi = function_type.bb.function.argument_type_abis[semantic_argument_index];

            switch (argument_abi.kind) {
                .direct => {
                    llvm_abi_argument_value_buffer[abi_argument_count] = semantic_argument_value.llvm;
                    abi_argument_count += 1;
                },
                else => @trap(),
            }
        }

        assert(abi_argument_count == function_type.bb.function.abi_argument_count);

        const llvm_abi_argument_values = llvm_abi_argument_value_buffer[0..abi_argument_count];
        const llvm_call = module.llvm.builder.create_call(callable.type.llvm.handle.to_function(), callable.llvm, llvm_abi_argument_values);
        llvm_call.to_instruction().set_calling_convention(callable.llvm.get_calling_convention());

        if (llvm_indirect_return_value) |indirect_value| {
            _ = indirect_value;
            @trap();
        } else {
            const call = module.values.add();
            call.* = .{
                .llvm = llvm_call,
                .type = function_type.bb.function.semantic_return_type,
                .bb = .instruction,
            };
            return call;
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

                    const value = converter.parse_value(module, local_type);

                    const local_storage = module.values.add();
                    local_storage.* = .{
                        .llvm = module.llvm.builder.create_alloca(local_type.llvm.handle, local_name),
                        .type = local_type,
                        .bb = .local,
                    };

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
                        const return_value = converter.parse_call(module, variable.value);
                        const is_noreturn = return_value.type.bb == .noreturn;
                        const is_valid = return_value.type.bb == .void or is_noreturn;
                        if (!is_valid) {
                            converter.report_error();
                        }

                        if (is_noreturn) {
                            _ = module.llvm.builder.create_unreachable();
                        }
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

            switch (value_state) {
                .none => previous_value = current_value,
                else => {
                    previous_value = module.values.add();
                    previous_value.?.* = .{
                        .llvm = llvm_value,
                        .type = next_ty,
                        .bb = .instruction,
                    };
                },
            }

            const ch = converter.content[converter.offset];
            value_state = switch (ch) {
                ',', ';', right_parenthesis, right_bracket => break previous_value.?,
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
        const must_be_constant = module.current_function == null;
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
            left_bracket => {
                converter.offset += 1;

                const ty = expected_type orelse converter.report_error();
                switch (ty.bb) {
                    .array => |*array| {
                        var element_count: usize = 0;
                        var element_buffer: [64]*llvm.Value = undefined;

                        var elements_are_constant = true;

                        while (true) : (element_count += 1) {
                            converter.skip_space();

                            if (converter.consume_character_if_match(right_bracket)) {
                                break;
                            }

                            const element_value = converter.parse_value(module, array.element_type);
                            elements_are_constant = elements_are_constant and element_value.is_constant();
                            element_buffer[element_count] = element_value.llvm;

                            converter.skip_space();

                            _ = converter.consume_character_if_match(',');
                        }

                        if (array.element_count) |ec| {
                            _ = ec;
                            @trap();
                        } else {
                            array.element_count = element_count;
                            ty.llvm = array_type_llvm(module, array);
                            ty.name = array_type_name(element_count, array);
                        }

                        const array_elements = element_buffer[0..element_count];
                        if (elements_are_constant) {
                            const array_constant = array.element_type.llvm.handle.get_constant_array(@ptrCast(array_elements));
                            const value = module.values.add();
                            value.* = .{
                                .llvm = array_constant.to_value(),
                                .type = ty,
                                .bb = .constant_array,
                            };
                            return value;
                        } else {
                            @trap();
                        }

                        @trap();
                    },
                    else => @trap(),
                }
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
                    if (lib.string.equal(identifier, "_")) {
                        return module.get_infer_or_ignore_value();
                    } else {
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
                            const call = converter.parse_call(module, variable.value);
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
                        } else if (converter.consume_character_if_match(left_bracket)) {
                            converter.skip_space();

                            const index_type = module.integer_type(64, false);
                            const llvm_index_type = module.integer_type(64, false).llvm.handle.to_integer();
                            const zero_index = llvm_index_type.get_constant(0, @intFromBool(false)).to_value();
                            const index = converter.parse_value(module, index_type);

                            converter.skip_space();
                            converter.expect_character(right_bracket);

                            const gep = module.llvm.builder.create_gep(variable.value.type.llvm.handle, variable.value.llvm, &.{ zero_index, index.llvm });
                            const load = module.values.add();
                            const load_type = variable.value.type.bb.array.element_type;
                            load.* = .{
                                .llvm = module.llvm.builder.create_load(load_type.llvm.handle, gep),
                                .type = load_type,
                                .bb = .instruction,
                            };
                            break :b load;
                        } else {
                            const load = module.values.add();
                            load.* = .{
                                .llvm = module.llvm.builder.create_load(variable.value.type.llvm.handle, variable.value.llvm),
                                .type = variable.value.type,
                                .bb = .instruction,
                            };
                            break :b load;
                        }
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

const CPUArchitecture = enum {
    x86_64,
};
const OperatingSystem = enum {
    linux,
};
pub const Target = struct {
    cpu: CPUArchitecture,
    os: OperatingSystem,

    pub fn get_native() Target {
        const builtin = @import("builtin");
        return Target{
            .cpu = switch (builtin.cpu.arch) {
                .x86_64 => .x86_64,
                else => @compileError("CPU not supported"),
            },
            .os = switch (builtin.os.tag) {
                .linux => .linux,
                else => @compileError("OS not supported"),
            },
        };
    }
};

pub const Abi = struct {
    const Kind = union(enum) {
        ignore,
        direct,
        direct_pair: [2]*Type,
        direct_coerce: *Type,
        direct_coerce_int,
        direct_split_struct_i32,
        expand_coerce,
        indirect: struct {
            type: *Type,
            alignment: u32,
        },
        expand,
    };

    const Attributes = struct {
        by_reg: bool = false,
        zero_extend: bool = false,
        sign_extend: bool = false,
        realign: bool = false,
        by_value: bool = false,
    };

    const Information = struct {
        kind: Kind,
        indices: [2]u16 = .{ 0, 0 },
        attributes: Abi.Attributes = .{},
    };

    pub const SystemV = struct {
        pub const RegisterCount = struct {
            gpr: u32,
            sse: u32,
        };
        pub const Class = enum {
            none,
            memory,
            integer,
            sse,
            sseup,

            fn merge(accumulator: Class, field: Class) Class {
                assert(accumulator != .memory);
                if (accumulator == field) {
                    return accumulator;
                } else {
                    var a = accumulator;
                    var f = field;
                    if (@intFromEnum(accumulator) > @intFromEnum(field)) {
                        a = field;
                        f = accumulator;
                    }

                    return switch (a) {
                        .none => f,
                        .memory => .memory,
                        .integer => .integer,
                        .sse, .sseup => .sse,
                    };
                }
            }
        };

        fn classify(ty: *Type, base_offset: u64) [2]Class {
            var result: [2]Class = undefined;
            const is_memory = base_offset >= 8;
            const current_index = @intFromBool(is_memory);
            const not_current_index = @intFromBool(!is_memory);
            assert(current_index != not_current_index);
            result[current_index] = .memory;
            result[not_current_index] = .none;

            switch (ty.bb) {
                .void, .noreturn => result[current_index] = .none,
                .bits => result[current_index] = .integer,
                .integer => result[current_index] = .integer, // TODO: weird cases
                //     const integer_index = ty.get_integer_index();
                //     switch (integer_index) {
                //         8 - 1,
                //         16 - 1,
                //         32 - 1,
                //         64 - 1,
                //         64 + 8 - 1,
                //         64 + 16 - 1,
                //         64 + 32 - 1,
                //         64 + 64 - 1,
                //         => result[current_index] = .integer,
                //         else => unreachable,
                //     }
                // },
                // .typed_pointer => result[current_index] = .integer,
                .@"struct" => |struct_type| {
                    if (struct_type.byte_size <= 64) {
                        const has_variable_array = false;
                        if (!has_variable_array) {
                            // const struct_type = ty.get_payload(.@"struct");
                            result[current_index] = .none;
                            const is_union = false;
                            var member_offset: u32 = 0;
                            for (struct_type.fields) |field| {
                                const offset = base_offset + member_offset;
                                const member_size = field.type.get_byte_size();
                                const member_alignment = field.type.get_byte_alignment();
                                member_offset = @intCast(lib.align_forward_u64(member_offset + member_size, ty.get_byte_alignment()));
                                const native_vector_size = 16;
                                if (ty.get_byte_size() > 16 and ((!is_union and ty.get_byte_size() != member_size) or ty.get_byte_size() > native_vector_size)) {
                                    result[0] = .memory;
                                    const r = classify_post_merge(ty.get_byte_size(), result);
                                    return r;
                                }

                                if (offset % member_alignment != 0) {
                                    result[0] = .memory;
                                    const r = classify_post_merge(ty.get_byte_size(), result);
                                    return r;
                                }

                                const member_classes = classify(field.type, offset);
                                for (&result, member_classes) |*r, m| {
                                    const merge_result = r.merge(m);
                                    r.* = merge_result;
                                }

                                if (result[0] == .memory or result[1] == .memory) break;
                            }

                            const final = classify_post_merge(ty.get_byte_size(), result);
                            result = final;
                        }
                    }
                },
                .array => |*array_type| {
                    if (ty.get_byte_size() <= 64) {
                        if (base_offset % ty.get_byte_alignment() == 0) {
                            result[current_index] = .none;

                            const vector_size = 16;
                            if (ty.get_byte_size() > 16 and (ty.get_byte_size() != array_type.element_type.get_byte_size() or ty.get_byte_size() > vector_size)) {
                                unreachable;
                            } else {
                                var offset = base_offset;

                                for (0..array_type.element_count.?) |_| {
                                    const element_classes = classify(array_type.element_type, offset);
                                    offset += array_type.element_type.get_byte_size();
                                    const merge_result = [2]Class{ result[0].merge(element_classes[0]), result[1].merge(element_classes[1]) };
                                    result = merge_result;
                                    if (result[0] == .memory or result[1] == .memory) {
                                        break;
                                    }
                                }

                                const final_result = classify_post_merge(ty.get_byte_size(), result);
                                assert(final_result[1] != .sseup or final_result[0] != .sse);
                                result = final_result;
                            }
                        }
                    }
                },
                else => |t| @panic(@tagName(t)),
            }

            return result;
        }

        fn classify_post_merge(size: u64, classes: [2]Class) [2]Class {
            if (classes[1] == .memory) {
                return .{ .memory, .memory };
            } else if (size > 16 and (classes[0] != .sse or classes[1] != .sseup)) {
                return .{ .memory, classes[1] };
            } else if (classes[1] == .sseup and classes[0] != .sse and classes[0] != .sseup) {
                return .{ classes[0], .sse };
            } else {
                return classes;
            }
        }

        fn get_int_type_at_offset(ty: *Type, offset: u32, source_type: *Type, source_offset: u32) *Type {
            switch (ty.bb) {
                .bits => {
                    @trap();
                    // const bitfield = ty.get_payload(.bitfield);
                    // return get_int_type_at_offset(bitfield.backing_type, offset, if (source_type == ty) bitfield.backing_type else source_type, source_offset);
                },
                .integer => |integer_type| {
                    switch (integer_type.bit_count) {
                        64 => return ty,
                        32, 16, 8 => {
                            if (offset != 0) unreachable;
                            const start = source_offset + ty.get_byte_size();
                            const end = source_offset + 8;
                            if (contains_no_user_data(source_type, start, end)) {
                                return ty;
                            }
                        },
                        else => unreachable,
                    }
                },
                // .typed_pointer => return if (offset == 0) ty else unreachable,
                .@"struct" => {
                    if (get_member_at_offset(ty, offset)) |field| {
                        return get_int_type_at_offset(field.type, @intCast(offset - field.byte_offset), source_type, source_offset);
                    }
                    unreachable;
                },
                .array => {
                    @trap();
                    // const array_type = ty.get_payload(.array);
                    // const element_type = array_type.descriptor.element_type;
                    // const element_size = element_type.size;
                    // const element_offset = (offset / element_size) * element_size;
                    // return get_int_type_at_offset(element_type, @intCast(offset - element_offset), source_type, source_offset);
                },
                else => |t| @panic(@tagName(t)),
            }

            if (source_type.get_byte_size() - source_offset > 8) {
                @trap();
                // return &instance.threads[ty.sema.thread].integers[63].type;
            } else {
                // const byte_count =  source_type.size - source_offset;
                // const bit_count = byte_count * 8;
                // return &instance.threads[ty.sema.thread].integers[bit_count - 1].type;
                @trap();
            }

            unreachable;
        }

        fn get_member_at_offset(ty: *Type, offset: u32) ?*Field {
            if (ty.get_byte_size() <= offset) {
                return null;
            }

            var offset_it: u32 = 0;
            var last_match: ?*Field = null;

            _ = &offset_it;
            _ = &last_match;

            @trap();

            // const struct_type = ty.get_payload(.@"struct");
            // for (struct_type.fields) |field| {
            //     if (offset_it > offset) {
            //         break;
            //     }
            //
            //     last_match = field;
            //     offset_it = @intCast(lib.align_forward(offset_it + field.type.size, ty.alignment));
            // }
            //
            // assert(last_match != null);
            // return last_match;
        }

        fn contains_no_user_data(ty: *Type, start: u64, end: u64) bool {
            if (ty.get_byte_size() <= start) {
                return true;
            }

            switch (ty.bb) {
                .@"struct" => |*struct_type| {
                    var offset: u64 = 0;

                    for (struct_type.fields) |field| {
                        if (offset >= end) break;
                        const field_start = if (offset < start) start - offset else 0;
                        if (!contains_no_user_data(field.type, field_start, end - offset)) return false;
                        offset += field.type.get_byte_size();
                    }

                    return true;
                },
                .array => |array_type| {
                    for (0..array_type.element_count.?) |i| {
                        const offset = i * array_type.element_type.get_byte_size();
                        if (offset >= end) break;
                        const element_start = if (offset < start) start - offset else 0;
                        if (!contains_no_user_data(array_type.element_type, element_start, end - offset)) return false;
                    }

                    return true;
                },
                // .anonymous_struct => unreachable,
                else => return false,
            }
        }

        fn get_argument_pair(types: [2]*Type) Abi.Information {
            const low_size = types[0].get_byte_size();
            const high_alignment = types[1].get_byte_alignment();
            const high_start = lib.align_forward_u64(low_size, high_alignment);
            assert(high_start == 8);
            return .{
                .kind = .{
                    .direct_pair = types,
                },
            };
        }

        fn indirect_argument(ty: *Type, free_integer_registers: u32) Abi.Information {
            const is_illegal_vector = false;
            if (!ty.is_aggregate() and !is_illegal_vector) {
                if (ty.bb == .integer and ty.get_bit_size() < 32) {
                    unreachable;
                } else {
                    return .{
                        .kind = .direct,
                    };
                }
            } else {
                if (free_integer_registers == 0) {
                    if (ty.get_byte_alignment() <= 8 and ty.get_byte_size() <= 8) {
                        unreachable;
                    }
                }

                if (ty.get_byte_alignment() < 8) {
                    return .{
                        .kind = .{
                            .indirect = .{
                                .type = ty,
                                .alignment = 8,
                            },
                        },
                        .attributes = .{
                            .realign = true,
                            .by_value = true,
                        },
                    };
                } else {
                    return .{
                        .kind = .{
                            .indirect = .{
                                .type = ty,
                                .alignment = @intCast(ty.get_byte_alignment()),
                            },
                        },
                        .attributes = .{
                            .by_value = true,
                        },
                    };
                }
            }
            unreachable;
        }

        fn indirect_return(ty: *Type) Function.Abi.Information {
            if (ty.is_aggregate()) {
                return .{
                    .kind = .{
                        .indirect = .{
                            .type = ty,
                            .alignment = ty.alignment,
                        },
                    },
                };
            } else {
                unreachable;
            }
        }
    };
};

const ConvertOptions = struct {
    content: []const u8,
    path: [:0]const u8,
    executable: [:0]const u8,
    build_mode: BuildMode,
    name: []const u8,
    has_debug_info: bool,
    objects: []const [:0]const u8,
    target: Target,
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
        var is_extern = false;

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
                    .@"extern" => is_extern = true,
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
                        var semantic_argument_count: u32 = 0;

                        while (converter.offset < converter.content.len and converter.content[converter.offset] != right_parenthesis) : (semantic_argument_count += 1) {
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

                            argument_buffer[semantic_argument_count] = .{
                                .name = argument_name,
                                .type = argument_type,
                                .line = argument_line,
                                .column = argument_column,
                            };
                        }

                        converter.expect_character(right_parenthesis);

                        converter.skip_space();

                        const semantic_return_type = converter.parse_type(module);
                        const linkage_name = global_name;

                        var debug_argument_type_buffer: [argument_buffer.len + 1]*llvm.DI.Type = undefined;

                        const semantic_arguments = argument_buffer[0..semantic_argument_count];
                        const semantic_argument_types = lib.global.arena.allocate(*Type, semantic_argument_count);
                        for (semantic_arguments, semantic_argument_types) |argument, *argument_type| {
                            argument_type.* = argument.type;
                        }
                        const semantic_debug_argument_types = debug_argument_type_buffer[0 .. semantic_argument_count + 1];

                        semantic_debug_argument_types[0] = semantic_return_type.llvm.debug;

                        var return_type_abi: Abi.Information = undefined;
                        var argument_type_abi_buffer: [64]Abi.Information = undefined;

                        switch (calling_convention) {
                            .unknown => {
                                return_type_abi = .{ .kind = .direct };

                                for (0..semantic_argument_count) |i| {
                                    argument_type_abi_buffer[i] = .{
                                        .kind = .direct,
                                        .indices = .{ @intCast(i), @intCast(i + 1) },
                                    };
                                }
                            },
                            // TODO: C calling convention
                            .c => {
                                // Return type abi
                                switch (options.target.cpu) {
                                    .x86_64 => switch (options.target.os) {
                                        .linux => {
                                            return_type_abi = ret_ty_abi: {
                                                const type_classes = Abi.SystemV.classify(semantic_return_type, 0);
                                                assert(type_classes[1] != .memory or type_classes[0] == .memory);
                                                assert(type_classes[1] != .sseup or type_classes[0] == .sse);

                                                const result_type = switch (type_classes[0]) {
                                                    .none => switch (type_classes[1]) {
                                                        .none => break :ret_ty_abi .{
                                                            .kind = .ignore,
                                                        },
                                                        else => |t| @panic(@tagName(t)),
                                                    },
                                                    .integer => b: {
                                                        const result_type = Abi.SystemV.get_int_type_at_offset(semantic_return_type, 0, semantic_return_type, 0);
                                                        if (type_classes[1] == .none and semantic_return_type.get_bit_size() < 32) {
                                                            // const signed = switch (semantic_return_type.sema.id) {
                                                            //     .integer => @intFromEnum(semantic_return_type.get_payload(.integer).signedness) != 0,
                                                            //     .bitfield => false,
                                                            //     else => |t| @panic(@tagName(t)),
                                                            // };
                                                            // _ = signed;

                                                            @trap();
                                                            // break :rta .{
                                                            //     .kind = .{
                                                            //         .direct_coerce = semantic_return_type,
                                                            //     },
                                                            //     .attributes = .{
                                                            //         .sign_extend = signed,
                                                            //         .zero_extend = !signed,
                                                            //     },
                                                            // };
                                                        }

                                                        break :b result_type;
                                                    },
                                                    .memory => @trap(), // break :rta Abi.SystemV.indirect_return(semantic_return_type),
                                                    else => |t| @panic(@tagName(t)),
                                                };

                                                const high_part: ?*Type = switch (type_classes[1]) {
                                                    .none, .memory => null,
                                                    .integer => b: {
                                                        assert(type_classes[0] != .none);
                                                        const high_part = Abi.SystemV.get_int_type_at_offset(semantic_return_type, 8, semantic_return_type, 8);
                                                        break :b high_part;
                                                    },
                                                    else => |t| @panic(@tagName(t)),
                                                };

                                                if (high_part) |hp| {
                                                    _ = hp;
                                                    @trap();
                                                    // break :rta Abi.SystemV.get_argument_pair(.{ result_type, hp });
                                                } else {
                                                    // TODO
                                                    const is_type = true;
                                                    if (is_type) {
                                                        if (result_type == semantic_return_type) {
                                                            break :ret_ty_abi Abi.Information{
                                                                .kind = .direct,
                                                            };
                                                        } else {
                                                            @trap();
                                                            // break :rta Function.Abi.Information{
                                                            //     .kind = .{
                                                            //         .direct_coerce = result_type,
                                                            //     },
                                                            // };
                                                        }
                                                    } else {
                                                        unreachable;
                                                    }
                                                }
                                            };

                                            var available_registers = Abi.SystemV.RegisterCount{
                                                .gpr = 6,
                                                .sse = 8,
                                            };

                                            if (return_type_abi.kind == .indirect) {
                                                available_registers.gpr -= 1;
                                            }

                                            const return_by_reference = false;
                                            if (return_by_reference) {
                                                @trap();
                                            }

                                            for (semantic_arguments, argument_type_abi_buffer[0..semantic_arguments.len]) |semantic_argument, *argument_type_abi| {
                                                const semantic_argument_type = semantic_argument.type;
                                                var needed_registers = Abi.SystemV.RegisterCount{
                                                    .gpr = 0,
                                                    .sse = 0,
                                                };
                                                const argument_type_abi_classification: Abi.Information = ata: {
                                                    const type_classes = Abi.SystemV.classify(semantic_argument_type, 0);
                                                    assert(type_classes[1] != .memory or type_classes[0] == .memory);
                                                    assert(type_classes[1] != .sseup or type_classes[0] == .sse);

                                                    _ = &needed_registers; // autofix

                                                    const result_type = switch (type_classes[0]) {
                                                        .integer => b: {
                                                            needed_registers.gpr += 1;
                                                            const result_type = Abi.SystemV.get_int_type_at_offset(semantic_argument_type, 0, semantic_argument_type, 0);
                                                            if (type_classes[1] == .none and semantic_argument_type.get_bit_size() < 32) {
                                                                const signed = switch (semantic_argument_type.bb) {
                                                                    .integer => |integer_type| integer_type.signed,
                                                                    .bits => false, // TODO: signedness?
                                                                    else => |t| @panic(@tagName(t)),
                                                                };

                                                                break :ata .{
                                                                    .kind = .{
                                                                        .direct_coerce = semantic_argument_type,
                                                                    },
                                                                    .attributes = .{
                                                                        .sign_extend = signed,
                                                                        .zero_extend = !signed,
                                                                    },
                                                                };
                                                            }
                                                            break :b result_type;
                                                        },
                                                        .memory => break :ata Abi.SystemV.indirect_argument(semantic_argument_type, available_registers.gpr),
                                                        else => |t| @panic(@tagName(t)),
                                                    };
                                                    const high_part: ?*Type = switch (type_classes[1]) {
                                                        .none, .memory => null,
                                                        .integer => b: {
                                                            assert(type_classes[0] != .none);
                                                            needed_registers.gpr += 1;
                                                            const high_part = Abi.SystemV.get_int_type_at_offset(semantic_argument_type, 8, semantic_argument_type, 8);
                                                            break :b high_part;
                                                        },
                                                        else => |t| @panic(@tagName(t)),
                                                    };

                                                    if (high_part) |hp| {
                                                        break :ata Abi.SystemV.get_argument_pair(.{ result_type, hp });
                                                    } else {
                                                        // TODO
                                                        const is_type = true;
                                                        if (is_type) {
                                                            if (result_type == semantic_argument_type) {
                                                                break :ata Abi.Information{
                                                                    .kind = .direct,
                                                                };
                                                            } else if (result_type.bb == .integer and semantic_argument_type.bb == .integer and semantic_argument_type.get_byte_size() == result_type.get_byte_size()) {
                                                                unreachable;
                                                            } else {
                                                                break :ata Abi.Information{
                                                                    .kind = .{
                                                                        .direct_coerce = result_type,
                                                                    },
                                                                };
                                                            }
                                                        }
                                                        unreachable;
                                                    }
                                                };
                                                argument_type_abi.* = if (available_registers.sse < needed_registers.sse or available_registers.gpr < needed_registers.gpr) b: {
                                                    break :b Abi.SystemV.indirect_argument(semantic_argument_type, available_registers.gpr);
                                                } else b: {
                                                    available_registers.gpr -= needed_registers.gpr;
                                                    available_registers.sse -= needed_registers.sse;
                                                    break :b argument_type_abi_classification;
                                                };
                                            }
                                        },
                                    },
                                }
                            },
                        }

                        const argument_type_abis = lib.global.arena.allocate(Abi.Information, semantic_arguments.len);
                        @memcpy(argument_type_abis, argument_type_abi_buffer[0..semantic_arguments.len]);

                        var abi_argument_type_buffer: [64]*Type = undefined;
                        var abi_argument_type_count: usize = 0;

                        var llvm_abi_argument_type_buffer: [64]*llvm.Type = undefined;

                        const abi_return_type = switch (return_type_abi.kind) {
                            .ignore, .direct => semantic_return_type,
                            .direct_coerce => |coerced_type| coerced_type,
                            // .indirect => |indirect| b: {
                            //     _ = abi_argument_types.append(get_typed_pointer(thread, .{
                            //         .pointee = indirect.type,
                            //     }));
                            //     break :b &thread.void;
                            // },
                            // .direct_pair => |pair| get_anonymous_two_field_struct(thread, pair),
                            else => |t| @panic(@tagName(t)),
                        };

                        for (argument_type_abis, semantic_argument_types) |*argument_abi, original_argument_type| {
                            const start: u16 = @intCast(abi_argument_type_count);
                            switch (argument_abi.kind) {
                                .direct => {
                                    abi_argument_type_buffer[abi_argument_type_count] = original_argument_type;
                                    llvm_abi_argument_type_buffer[abi_argument_type_count] = original_argument_type.llvm.handle;
                                    abi_argument_type_count += 1;
                                },
                                .direct_coerce => |coerced_type| {
                                    abi_argument_type_buffer[abi_argument_type_count] = coerced_type;
                                    llvm_abi_argument_type_buffer[abi_argument_type_count] = coerced_type.llvm.handle;
                                    abi_argument_type_count += 1;
                                },
                                .direct_pair => |pair| {
                                    abi_argument_type_buffer[abi_argument_type_count] = pair[0];
                                    llvm_abi_argument_type_buffer[abi_argument_type_count] = pair[0].llvm.handle;
                                    abi_argument_type_count += 1;
                                    abi_argument_type_buffer[abi_argument_type_count] = pair[1];
                                    llvm_abi_argument_type_buffer[abi_argument_type_count] = pair[1].llvm.handle;
                                    abi_argument_type_count += 1;
                                },
                                // .indirect => |indirect| _ = abi_argument_types.append(get_typed_pointer(thread, .{
                                //     .pointee = indirect.type,
                                // })),
                                else => |t| @panic(@tagName(t)),
                            }

                            const end: u16 = @intCast(abi_argument_type_count);
                            argument_abi.indices = .{ start, end };
                        }

                        const abi_argument_types = lib.global.arena.allocate(*Type, abi_argument_type_count);
                        @memcpy(abi_argument_types, abi_argument_type_buffer[0..abi_argument_type_count]);
                        const llvm_abi_argument_types = llvm_abi_argument_type_buffer[0..abi_argument_type_count];

                        const llvm_function_type = llvm.Type.Function.get(abi_return_type.llvm.handle, llvm_abi_argument_types, false);
                        const llvm_handle = module.llvm.handle.create_function(.{
                            .name = global_name,
                            .linkage = switch (is_export or is_extern) {
                                true => .ExternalLinkage,
                                false => .InternalLinkage,
                            },
                            .type = llvm_function_type,
                        });
                        llvm_handle.set_calling_convention(calling_convention.to_llvm());

                        const global = module.globals.add();
                        var subroutine_type: *llvm.DI.Type.Subroutine = undefined;
                        const current_scope: *llvm.DI.Scope = if (module.llvm.di_builder) |di_builder| blk: {
                            const subroutine_type_flags = llvm.DI.Flags{};
                            subroutine_type = di_builder.create_subroutine_type(module.llvm.file, semantic_debug_argument_types, subroutine_type_flags);
                            const scope_line: u32 = @intCast(converter.line_offset + 1);
                            const local_to_unit = !is_export and !is_extern;
                            const flags = llvm.DI.Flags{};
                            const is_definition = !is_extern;
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
                                    .semantic_return_type = semantic_return_type,
                                    .semantic_argument_types = blk: {
                                        const sema_arg_types = lib.global.arena.allocate(*Type, semantic_argument_count);
                                        for (semantic_arguments, sema_arg_types) |argument, *argument_type| {
                                            argument_type.* = argument.type;
                                        }

                                        break :blk sema_arg_types.ptr;
                                    },
                                    .semantic_argument_count = semantic_argument_count,
                                    .abi_argument_count = @intCast(abi_argument_type_count),
                                    .abi_argument_types = abi_argument_types.ptr,
                                    .argument_type_abis = argument_type_abis.ptr,
                                    .return_type_abi = return_type_abi,
                                },
                            },
                        });

                        if (converter.consume_character_if_match(';')) {
                            const value = module.values.add();
                            value.* = .{
                                .llvm = llvm_handle.to_value(),
                                .type = function_type,
                                .bb = .external_function,
                            };

                            global.* = .{
                                .value = value,
                                .name = global_name,
                            };
                        } else {
                            const entry_block = module.llvm.context.create_basic_block("entry", llvm_handle);
                            module.llvm.builder.position_at_end(entry_block);

                            var llvm_argument_buffer: [argument_buffer.len]*llvm.Argument = undefined;
                            llvm_handle.get_arguments(&llvm_argument_buffer);
                            const llvm_arguments = llvm_argument_buffer[0..semantic_argument_count];

                            const value = module.values.add();
                            value.* = .{
                                .llvm = llvm_handle.to_value(),
                                .type = function_type,
                                .bb = .{
                                    .function = .{
                                        .current_basic_block = entry_block,
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

                            switch (return_type_abi.kind) {
                                .indirect => |indirect| {
                                    _ = indirect;
                                    @trap();
                                },
                                else => {},
                            }

                            if (semantic_arguments.len > 0) {
                                const argument_variables = global.value.bb.function.arguments.add_many(semantic_argument_count);
                                for (semantic_arguments, argument_type_abis, argument_variables, 0..) |semantic_argument, argument_abi, *argument_variable, argument_index| {
                                    const argument_abi_count = argument_abi.indices[1] - argument_abi.indices[0];
                                    const LowerKind = union(enum) {
                                        direct,
                                        direct_pair: [2]*Type,
                                        direct_coerce: *Type,
                                        indirect,
                                    };
                                    const lower_kind: LowerKind = switch (argument_abi.kind) {
                                        .direct => .direct,
                                        .direct_coerce => |coerced_type| if (semantic_argument.type == coerced_type) .direct else .{ .direct_coerce = coerced_type },
                                        .direct_pair => |pair| .{ .direct_pair = pair },
                                        .indirect => .indirect,
                                        else => @trap(),
                                    };

                                    const llvm_storage = switch (lower_kind) {
                                        .direct => d: {
                                            assert(argument_abi_count == 1);
                                            const argument_alloca = module.llvm.builder.create_alloca(semantic_argument.type.llvm.handle, semantic_argument.name);
                                            const abi_argument_index = argument_abi.indices[0];
                                            const llvm_argument = llvm_arguments[abi_argument_index];
                                            _ = module.llvm.builder.create_store(llvm_argument.to_value(), argument_alloca);
                                            break :d argument_alloca;
                                        },
                                        else => @trap(),
                                    };

                                    const argument_value = module.values.add();
                                    argument_value.* = .{
                                        .llvm = llvm_storage,
                                        .type = semantic_argument.type,
                                        .bb = .argument,
                                    };
                                    argument_variable.* = .{
                                        .value = argument_value,
                                        .name = semantic_argument.name,
                                    };

                                    if (module.llvm.di_builder) |di_builder| {
                                        const always_preserve = true;
                                        const flags = llvm.DI.Flags{};
                                        const parameter_variable = di_builder.create_parameter_variable(global.value.bb.function.current_scope, semantic_argument.name, @intCast(argument_index + 1), module.llvm.file, semantic_argument.line, semantic_argument.type.llvm.debug, always_preserve, flags);
                                        const inlined_at: ?*llvm.DI.Metadata = null; // TODO
                                        const debug_location = llvm.DI.create_debug_location(module.llvm.context, semantic_argument.line, semantic_argument.column, global.value.bb.function.current_scope, inlined_at);
                                        _ = di_builder.insert_declare_record_at_end(llvm_storage, parameter_variable, di_builder.null_expression(), debug_location, global.value.bb.function.current_basic_block);
                                    }
                                }
                            }

                            converter.parse_block(module);
                        }

                        if (module.llvm.di_builder) |di_builder| {
                            di_builder.finalize_subprogram(llvm_handle.get_subprogram());
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
