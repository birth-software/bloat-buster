const lib = @import("lib.zig");
const assert = lib.assert;
const builtin = lib.builtin;
const Arena = lib.Arena;

const llvm = @import("LLVM.zig");

pub const CPUArchitecture = enum {
    x86_64,
};

pub const OperatingSystem = enum {
    linux,
};

fn array_type_name(arena: *Arena, element_type: *Type, element_count: u64) [:0]const u8 {
    var buffer: [256]u8 = undefined;
    var i: u64 = 0;
    buffer[i] = left_bracket;
    i += 1;
    i += lib.string_format.integer_decimal(buffer[i..], element_count);
    buffer[i] = right_bracket;
    i += 1;
    const element_name = element_type.name;
    @memcpy(buffer[i..][0..element_name.len], element_name);
    i += element_name.len;
    return arena.duplicate_string(buffer[0..i]);
}

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

pub const Target = struct {
    cpu: CPUArchitecture,
    os: OperatingSystem,

    pub fn get_native() Target {
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

fn is_space(ch: u8) bool {
    return ((@intFromBool(ch == ' ') | @intFromBool(ch == '\n')) | ((@intFromBool(ch == '\t') | @intFromBool(ch == '\r')))) != 0;
}

const left_bracket = '[';
const right_bracket = ']';
const left_brace = '{';
const right_brace = '}';
const left_parenthesis = '(';
const right_parenthesis = ')';

const GlobalKeyword = enum {
    @"export",
    @"extern",
};
fn is_identifier_start_ch(ch: u8) bool {
    return (ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or ch == '_';
}

fn is_decimal_ch(ch: u8) bool {
    return ch >= '0' and ch <= '9';
}

fn is_octal_ch(ch: u8) bool {
    return ch >= '0' and ch <= '7';
}

fn is_binary_ch(ch: u8) bool {
    return ch == '0' or ch == '1';
}

fn is_identifier_ch(ch: u8) bool {
    return is_identifier_start_ch(ch) or is_decimal_ch(ch);
}

pub const Variable = struct {
    storage: ?*Value = null,
    initial_value: *Value,
    type: ?*Type,
    scope: *Scope,
    name: []const u8,
    line: u32,
    column: u32,

    fn resolve_type(variable: *Variable, auxiliary_type: *Type) void {
        const resolved_type: *Type = variable.type orelse auxiliary_type;
        variable.type = resolved_type;
    }
};

pub const Local = struct {
    variable: Variable,
    argument_index: ?u32,

    pub const Buffer = struct {
        buffer: lib.VirtualBuffer(Local),

        pub fn initialize() Buffer {
            return .{
                .buffer = .initialize(),
            };
        }

        pub fn find_by_name(locals: *Buffer, name: []const u8) ?*Local {
            const slice = locals.buffer.get_slice();
            for (slice) |*local| {
                if (lib.string.equal(local.variable.name, name)) {
                    return local;
                }
            } else {
                return null;
            }
        }

        pub fn get_slice(locals: *Buffer) []Local {
            return locals.buffer.get_slice();
        }

        pub fn add(locals: *Buffer) *Local {
            return locals.buffer.add();
        }
    };
};

pub const Linkage = enum {
    external,
    internal,
};

pub const Global = struct {
    variable: Variable,
    linkage: Linkage,

    pub const Buffer = struct {
        buffer: lib.VirtualBuffer(Global),

        pub fn get_slice(buffer: Buffer) []Global {
            return buffer.buffer.get_slice();
        }

        pub fn initialize() Buffer {
            return .{
                .buffer = .initialize(),
            };
        }

        pub fn find_by_name(globals: *Buffer, name: []const u8) ?*Global {
            const slice = globals.buffer.get_slice();
            for (slice) |*global| {
                if (lib.string.equal(global.variable.name, name)) {
                    return global;
                }
            } else {
                return null;
            }
        }

        pub fn add(globals: *Buffer) *Global {
            return globals.buffer.add();
        }
    };
};

const ConstantArgument = struct {
    kind: Kind,
    index: u8,
    const Kind = enum {
        type,
        value,
    };
};

pub const Macro = struct {
    arguments: []const *Local,
    argument_types: []const *Type,
    constant_argument_names: []const []const u8,
    constant_argument_values: []const *Value,
    type_arguments: []const *Type,
    constant_arguments: []const ConstantArgument,
    return_type: *Type,
    block: *LexicalBlock,
    name: []const u8,
    scope: Scope,
    is_generic: bool,

    pub const Instantiation = struct {
        declaration: *Macro,
        function: *Global,
        declaration_arguments: []*Local,
        instantiation_arguments: []const *Value,
        constant_argument_values: []const *Value,
        type_arguments: []*Type,
        return_type: *Type,
        block: *LexicalBlock,
        return_alloca: *llvm.Value,
        return_block: *llvm.BasicBlock,
        function_scope: Scope,
        instantiation_line: u32,
        instantiation_column: u32,
    };

    pub const Buffer = struct {
        buffer: lib.VirtualBuffer(Macro),

        pub fn get_slice(buffer: Buffer) []Macro {
            return buffer.buffer.get_slice();
        }

        pub fn initialize() Buffer {
            return .{
                .buffer = .initialize(),
            };
        }

        pub fn find_by_name(globals: *Buffer, name: []const u8) ?*Macro {
            const slice = globals.buffer.get_slice();
            for (slice) |*global| {
                if (lib.string.equal(global.variable.name, name)) {
                    return global;
                }
            } else {
                return null;
            }
        }

        pub fn add(globals: *Buffer) *Macro {
            return globals.buffer.add();
        }
    };
};

pub const ResolvedType = struct {
    handle: *llvm.Type,
    debug: *llvm.DI.Type,
};

pub const Enumerator = struct {
    fields: []const Enumerator.Field,
    string_to_enum: ?StringToEnum = null,
    enum_to_string: ?*llvm.Function = null,
    name_array_global: ?*Global = null,
    backing_type: *Type,
    line: u32,
    implicit_backing_type: bool,

    pub const Field = struct {
        name: []const u8,
        value: u64,
    };

    pub const StringToEnum = struct {
        function: *llvm.Function,
        struct_type: *Type,
    };
};

pub const Type = struct {
    bb: union(enum) {
        void,
        noreturn,
        integer: Type.Integer,
        enumerator: Enumerator,
        float: Float,
        bits: Type.Bits,
        pointer: Type.Pointer,
        function: Type.Function,
        array: Type.Array,
        structure: Type.Struct,
        @"union": Type.Union,
        vector,
        forward_declaration,
        alias: Type.Alias,
        unresolved,
    },
    name: []const u8,
    llvm: LLVM = .{},

    const Kind = enum {
        abi,
        memory,
    };

    const LLVM = struct {
        abi: ?*llvm.Type = null,
        memory: ?*llvm.Type = null,
        debug: ?*llvm.DI.Type = null,

        const Type = struct {
            handle: ?*llvm.Type = null,
            debug: ?*llvm.DI.Type = null,
        };
    };

    pub const Union = struct {
        fields: []Union.Field,
        byte_size: u64,
        byte_alignment: u32,
        line: u32,
        biggest_field: u32,

        const Field = struct {
            type: *Type,
            name: []const u8,
            line: u32,
        };
    };

    pub const Alias = struct {
        type: *Type,
        line: u32,
        scope: *Scope,
    };

    pub const Float = struct {
        const Kind = enum {
            half,
            bfloat,
            float,
            double,
            fp128,
        };
        kind: Float.Kind,
    };

    pub const Intrinsic = struct {
        const Id = enum {
            ReturnType,
            foo,
        };
    };

    pub fn is_slice(ty: *Type) bool {
        return switch (ty.bb) {
            .structure => |structure| structure.is_slice,
            else => false,
        };
    }

    pub fn is_integer_backing(ty: *Type) bool {
        return switch (ty.bb) {
            .enumerator, .integer, .bits, .pointer => true,
            else => false,
        };
    }

    pub fn get_llvm(ty: *Type, kind: Type.Kind) *llvm.Type {
        return switch (kind) {
            .abi => ty.llvm.abi.?,
            .memory => ty.llvm.memory.?,
        };
    }

    fn resolve(ty: *Type, module: *Module) void {
        if (ty.llvm.abi == null) {
            const abi_type = switch (ty.bb) {
                .void, .noreturn => module.llvm.void_type,
                .integer => |integer| module.llvm.context.get_integer_type(integer.bit_count).to_type(),
                .pointer => module.llvm.pointer_type,
                .array => |array| blk: {
                    array.element_type.resolve(module);
                    const array_type = array.element_type.llvm.memory.?.get_array_type(array.element_count);
                    break :blk array_type.to_type();
                },
                .enumerator => |enumerator| blk: {
                    enumerator.backing_type.resolve(module);
                    break :blk enumerator.backing_type.llvm.abi.?;
                },
                .structure => |structure| blk: {
                    var llvm_type_buffer: [64]*llvm.Type = undefined;
                    const llvm_types = llvm_type_buffer[0..structure.fields.len];
                    for (llvm_types, structure.fields) |*llvm_type, *field| {
                        field.type.resolve(module);
                        llvm_type.* = field.type.llvm.memory.?;
                    }
                    const struct_type = module.llvm.context.get_struct_type(llvm_types);
                    break :blk struct_type.to_type();
                },
                .bits => |bits| blk: {
                    bits.backing_type.resolve(module);
                    const t = bits.backing_type.llvm.abi.?;
                    break :blk t;
                },
                .alias => |alias| blk: {
                    alias.type.resolve(module);
                    break :blk alias.type.llvm.abi.?;
                },
                .@"union" => |union_type| blk: {
                    const biggest_type = union_type.fields[union_type.biggest_field].type;
                    biggest_type.resolve(module);
                    const result_type = module.llvm.context.get_struct_type(&.{biggest_type.llvm.memory.?});
                    break :blk result_type.to_type();
                },
                else => @trap(),
            };
            ty.llvm.abi = abi_type;

            const memory_type = switch (ty.bb) {
                .void,
                .noreturn,
                .pointer,
                .array,
                .structure,
                .@"union",
                => abi_type,
                .integer => module.llvm.context.get_integer_type(@intCast(ty.get_byte_size() * 8)).to_type(),
                .enumerator => |enumerator| enumerator.backing_type.llvm.memory.?,
                .bits => |bits| bits.backing_type.llvm.memory.?, // TODO: see assert below
                .alias => |alias| alias.type.llvm.memory.?,
                else => @trap(),
            };
            ty.llvm.memory = memory_type;
            if (ty.bb == .bits) assert(ty.llvm.memory == ty.llvm.abi);

            if (module.has_debug_info) {
                const debug_type = switch (ty.bb) {
                    .void, .noreturn => module.llvm.di_builder.create_basic_type(ty.name, 0, .void, .{ .no_return = ty.bb == .noreturn }),
                    .integer => |integer| module.llvm.di_builder.create_basic_type(ty.name, @max(lib.next_power_of_two(integer.bit_count), 8), switch (integer.bit_count) {
                        1 => .boolean,
                        else => switch (integer.signed) {
                            true => .signed,
                            false => .unsigned,
                        },
                    }, .{}),
                    .pointer => |pointer| b: {
                        pointer.type.resolve(module);
                        break :b module.llvm.di_builder.create_pointer_type(pointer.type.llvm.debug.?, 64, 64, 0, ty.name).to_type();
                    },
                    .array => |array| module.llvm.di_builder.create_array_type(array.element_count, 0, array.element_type.llvm.debug.?, &.{}).to_type(),
                    .enumerator => |enumerator| blk: {
                        var enumerator_buffer: [64]*llvm.DI.Enumerator = undefined;
                        const enumerators = enumerator_buffer[0..enumerator.fields.len];
                        for (enumerators, enumerator.fields) |*enumerator_pointer, *field| {
                            enumerator_pointer.* = module.llvm.di_builder.create_enumerator(field.name, @bitCast(field.value), false);
                        }
                        const alignment = 0; // TODO
                        const enumeration_type = module.llvm.di_builder.create_enumeration_type(module.scope.llvm.?, ty.name, module.llvm.file, enumerator.line, enumerator.backing_type.get_bit_size(), alignment, enumerators, enumerator.backing_type.llvm.debug.?);
                        break :blk enumeration_type.to_type();
                    },
                    .structure => |structure| blk: {
                        const struct_type = module.llvm.di_builder.create_replaceable_composite_type(module.llvm.debug_tag, ty.name, module.scope.llvm.?, module.llvm.file, structure.line);
                        ty.llvm.debug = struct_type.to_type();
                        module.llvm.debug_tag += 1;

                        var llvm_debug_member_type_buffer: [64]*llvm.DI.Type.Derived = undefined;
                        const llvm_debug_member_types = llvm_debug_member_type_buffer[0..structure.fields.len];

                        for (structure.fields, llvm_debug_member_types) |field, *llvm_debug_member_type| {
                            field.type.resolve(module);
                            const member_type = module.llvm.di_builder.create_member_type(module.scope.llvm.?, field.name, module.llvm.file, field.line, field.type.get_byte_size() * 8, @intCast(field.type.get_byte_alignment() * 8), field.bit_offset, .{}, field.type.llvm.debug.?);
                            llvm_debug_member_type.* = member_type;
                        }

                        const debug_struct_type = module.llvm.di_builder.create_struct_type(module.scope.llvm.?, ty.name, module.llvm.file, structure.line, structure.bit_size, @intCast(structure.bit_alignment), .{}, llvm_debug_member_types);
                        const forward_declared: *llvm.DI.Type.Composite = @ptrCast(ty.llvm.debug);
                        forward_declared.replace_all_uses_with(debug_struct_type);
                        break :blk debug_struct_type.to_type();
                    },
                    .bits => |bits| blk: {
                        var llvm_debug_member_type_buffer: [64]*llvm.DI.Type.Derived = undefined;
                        const llvm_debug_member_types = llvm_debug_member_type_buffer[0..bits.fields.len];
                        for (bits.fields, llvm_debug_member_types) |field, *llvm_debug_member_type| {
                            llvm_debug_member_type.* = module.llvm.di_builder.create_bit_field_member_type(module.scope.llvm.?, field.name, module.llvm.file, field.line, field.type.get_bit_size(), field.bit_offset, 0, .{}, bits.backing_type.llvm.debug.?);
                        }

                        const struct_type = module.llvm.di_builder.create_struct_type(module.scope.llvm.?, ty.name, module.llvm.file, bits.line, ty.get_bit_size(), @intCast(ty.get_bit_alignment()), .{}, llvm_debug_member_types);
                        break :blk struct_type.to_type();
                    },
                    .alias => |alias| blk: {
                        const typedef = module.llvm.di_builder.create_typedef(alias.type.llvm.debug.?, ty.name, module.llvm.file, alias.line, alias.scope.llvm.?, 0);
                        break :blk typedef.to_type();
                    },
                    .@"union" => |union_type| blk: {
                        const result_type = module.llvm.di_builder.create_replaceable_composite_type(module.llvm.debug_tag, ty.name, module.scope.llvm.?, module.llvm.file, union_type.line);
                        ty.llvm.debug = result_type.to_type();
                        module.llvm.debug_tag += 1;

                        var llvm_debug_member_type_buffer: [64]*llvm.DI.Type.Derived = undefined;
                        const llvm_debug_member_types = llvm_debug_member_type_buffer[0..union_type.fields.len];

                        for (union_type.fields, llvm_debug_member_types) |field, *llvm_debug_member_type| {
                            field.type.resolve(module);
                            const member_type = module.llvm.di_builder.create_member_type(module.scope.llvm.?, field.name, module.llvm.file, field.line, field.type.get_byte_size() * 8, @intCast(field.type.get_byte_alignment() * 8), 0, .{}, field.type.llvm.debug.?);
                            llvm_debug_member_type.* = member_type;
                        }

                        const debug_struct_type = module.llvm.di_builder.create_union_type(module.scope.llvm.?, ty.name, module.llvm.file, union_type.line, union_type.byte_size * 8, @intCast(union_type.byte_alignment * 8), .{}, llvm_debug_member_types);
                        const forward_declared: *llvm.DI.Type.Composite = @ptrCast(ty.llvm.debug);
                        forward_declared.replace_all_uses_with(debug_struct_type);
                        break :blk debug_struct_type.to_type();
                    },
                    else => @trap(),
                };
                ty.llvm.debug = debug_type;
            }
        }
    }

    const Bits = struct {
        fields: []const Struct.Field,
        backing_type: *Type,
        line: u32,
        implicit_backing_type: bool,
    };

    pub const Integer = struct {
        bit_count: u32,
        signed: bool,
    };

    pub const Pointer = struct {
        type: *Type,
        alignment: ?u32,

        pub fn get_alignment(p: *Pointer) u32 {
            if (p.alignment) |a| return a else {
                const type_alignment = p.type.get_byte_alignment();
                p.alignment = type_alignment;
                return type_alignment;
            }
        }
    };

    pub const Function = struct {
        semantic_return_type: *Type,
        semantic_argument_types: []const *Type,
        calling_convention: CallingConvention,
        is_var_args: bool,
        // Filled during codegen
        return_abi: Abi.Information = undefined,
        argument_abis: []Abi.Information = undefined,
        abi_argument_types: []*Type = undefined,
        abi_return_type: *Type = undefined,
        available_registers: Abi.RegisterCount = undefined,
    };

    pub const Struct = struct {
        fields: []Struct.Field,
        byte_size: u64,
        bit_size: u64,
        byte_alignment: u32,
        bit_alignment: u32,
        line: u32,
        is_slice: bool,

        const Field = struct {
            name: []const u8,
            type: *Type,
            bit_offset: u64,
            byte_offset: u64,
            line: u32,
        };
    };

    pub const Array = struct {
        element_type: *Type,
        element_count: u64,
    };

    pub const Buffer = struct {
        buffer: lib.VirtualBuffer(Type),

        pub fn initialize() Buffer {
            return .{
                .buffer = .initialize(),
            };
        }

        pub fn find_by_name(types: *Buffer, name: []const u8) ?*Type {
            const slice = types.buffer.get_slice();
            for (slice) |*ty| {
                if (lib.string.equal(ty.name, name)) {
                    return ty;
                }
            } else {
                return null;
            }
        }

        pub fn get(types: *Buffer, index: u64) *Type {
            const slice = types.get_slice();
            assert(index < slice.len);
            return &slice[index];
        }

        pub fn get_slice(types: *Buffer) []Type {
            const slice = types.buffer.get_slice();
            return slice;
        }

        pub fn append(types: *Buffer, ty: Type) *Type {
            return types.buffer.append(ty);
        }
    };

    pub fn is_signed(ty: *const Type) bool {
        return switch (ty.bb) {
            .integer => |integer| integer.signed,
            .bits => |bits| bits.backing_type.is_signed(),
            .enumerator => |enumerator| enumerator.backing_type.is_signed(),
            .alias => |alias| alias.type.is_signed(),
            else => @trap(),
        };
    }

    pub fn is_integral_or_enumeration_type(ty: *const Type) bool {
        return switch (ty.bb) {
            .integer => true,
            .bits => true,
            .structure => false,
            .alias => |alias| alias.type.is_integral_or_enumeration_type(),
            else => @trap(),
        };
    }

    pub fn is_arbitrary_bit_integer(ty: *Type) bool {
        return switch (ty.bb) {
            .integer => |integer| switch (integer.bit_count) {
                8, 16, 32, 64, 128 => false,
                else => true,
            },
            .bits => |bits| bits.backing_type.is_arbitrary_bit_integer(),
            .enumerator => |enumerator| enumerator.backing_type.is_arbitrary_bit_integer(),
            else => false,
        };
    }

    pub fn is_promotable_integer_type_for_abi(ty: *Type) bool {
        return switch (ty.bb) {
            .integer => |integer| integer.bit_count < 32,
            .bits => |bits| bits.backing_type.is_promotable_integer_type_for_abi(),
            .alias => |alias| alias.type.is_promotable_integer_type_for_abi(),
            else => @trap(),
        };
    }

    pub fn get_byte_alignment(ty: *const Type) u32 {
        const result: u32 = switch (ty.bb) {
            .void => unreachable,
            .integer => |integer| @intCast(@min(@divExact(@max(8, lib.next_power_of_two(integer.bit_count)), 8), 16)),
            .pointer => 8,
            .function => 1,
            .array => |array| array.element_type.get_byte_alignment(),
            .enumerator => |enumerator| enumerator.backing_type.get_byte_alignment(),
            .structure => |structure| structure.byte_alignment,
            .bits => |bits| bits.backing_type.get_byte_alignment(),
            .alias => |alias| alias.type.get_byte_alignment(),
            .unresolved => unreachable,
            .@"union" => |union_type| union_type.byte_alignment,
            else => @trap(),
        };
        return result;
    }

    pub fn get_bit_alignment(ty: *const Type) u32 {
        // TODO: fix
        return switch (ty.bb) {
            .integer => |integer| integer.bit_count, // TODO: is this correct?
            .pointer => 64,
            .bits => |bits| bits.backing_type.get_bit_alignment(),
            .array => |array| array.element_type.get_bit_alignment(),
            .structure => |structure| structure.bit_alignment,
            .enumerator => |enumerator| enumerator.backing_type.get_bit_alignment(),
            else => @trap(),
        };
    }

    pub fn get_byte_size(ty: *const Type) u64 {
        const byte_size: u64 = switch (ty.bb) {
            .integer => |integer| @divExact(@max(8, lib.next_power_of_two(integer.bit_count)), 8),
            .structure => |structure| structure.byte_size,
            .pointer => 8,
            .array => |array| array.element_type.get_byte_size() * array.element_count,
            .bits => |bits| bits.backing_type.get_byte_size(),
            .enumerator => |enumerator| enumerator.backing_type.get_byte_size(),
            .alias => |alias| alias.type.get_byte_size(),
            .@"union" => |union_type| union_type.byte_size,
            else => @trap(),
        };
        return byte_size;
    }
    pub fn get_bit_size(ty: *const Type) u64 {
        // TODO: fix
        const bit_size: u64 = switch (ty.bb) {
            .integer => |integer| integer.bit_count,
            .pointer => 64,
            .bits => |bits| bits.backing_type.get_bit_size(),
            .array => |array| array.element_type.get_bit_size() * array.element_count,
            .structure => |structure| structure.bit_size,
            .enumerator => |enumerator| enumerator.backing_type.get_bit_size(),
            .alias => |alias| alias.type.get_bit_size(),
            else => @trap(),
        };
        return bit_size;
    }

    pub fn get_byte_allocation_size(ty: *const Type) u64 {
        return lib.align_forward_u64(ty.get_byte_size(), ty.get_byte_alignment());
    }

    pub fn is_aggregate_type_for_abi(ty: *Type) bool {
        const ev_kind = ty.get_evaluation_kind();
        const is_member_function_pointer_type = false; // TODO
        return ev_kind != .scalar or is_member_function_pointer_type;
    }

    pub const EvaluationKind = enum {
        scalar,
        complex,
        aggregate,
    };

    pub fn get_evaluation_kind(ty: *const Type) EvaluationKind {
        return switch (ty.bb) {
            .structure, .array, .@"union" => .aggregate,
            .integer, .bits, .pointer, .enumerator => .scalar,
            .alias => |alias| alias.type.get_evaluation_kind(),
            else => @trap(),
        };
    }

    pub fn is_abi_equal(ty: *Type, other: *Type, module: *Module) bool {
        ty.resolve(module);
        other.resolve(module);

        return ty == other or ty.llvm.abi == other.llvm.abi;
    }
};

const ConstantInteger = struct {
    value: u64,
    signed: bool,
};

pub const Statement = struct {
    bb: union(enum) {
        local: *Local,
        @"return": ?*Value,
        assignment: Assignment,
        expression: *Value,
        @"if": If,
        @"while": While,
        for_each: ForEach,
        @"switch": Switch,
        block: *LexicalBlock,
        break_statement,
        continue_statement,
    },
    line: u32,
    column: u32,

    const ForEach = struct {
        locals: []const *Local,
        left_values: []const Value.Kind,
        right_values: []const *Value,
        predicate: *Statement,
        kind: Kind,
        scope: Scope,

        const Kind = enum {
            slice,
            range,
        };
    };

    const Assignment = struct {
        left: *Value,
        right: *Value,
        kind: Operator,

        const Operator = enum {
            @"=",
            @"+=",
            @"-=",
            @"*=",
            @"/=",
            @"%=",
            @">>=",
            @"<<=",
            @"&=",
            @"|=",
            @"^=",
        };
    };

    const If = struct {
        condition: *Value,
        if_statement: *Statement,
        else_statement: ?*Statement,
    };

    const While = struct {
        condition: *Value,
        block: *LexicalBlock,
    };

    const Switch = struct {
        discriminant: *Value,
        clauses: []Clause,

        const Clause = struct {
            values: []const *Value,
            block: *LexicalBlock,
            basic_block: *llvm.BasicBlock = undefined,
        };
    };
};

const Unary = struct {
    value: *Value,
    id: Id,

    const Id = enum {
        @"-",
        @"+",
        @"&",
        @"!",
        @"~",

        pub fn is_boolean(id: Id) bool {
            return switch (id) {
                .@"+", .@"-", .@"&", .@"~" => false,
                .@"!" => true,
            };
        }
    };
};

const Binary = struct {
    left: *Value,
    right: *Value,
    id: Id,

    const Id = enum {
        @"+",
        @"-",
        @"*",
        @"/",
        @"%",
        @"&",
        @"|",
        @"^",
        @"<<",
        @">>",
        @"==",
        @"!=",
        @">",
        @"<",
        @">=",
        @"<=",
        @"and",
        @"or",
        @"and?",
        @"or?",

        fn is_boolean(id: Binary.Id) bool {
            return switch (id) {
                .@"==",
                .@"!=",
                .@">",
                .@"<",
                .@">=",
                .@"<=",
                => true,
                else => false,
            };
        }

        fn is_shortcircuiting(id: Binary.Id) bool {
            return id == .@"and?" or id == .@"or?";
        }
    };
};

pub const Call = struct {
    callable: *Value,
    arguments: []const *Value,
    function_type: *Type = undefined,
};

pub const FieldAccess = struct {
    aggregate: *Value,
    field: []const u8,
};

pub const Value = struct {
    bb: union(enum) {
        external_function,
        function: Function,
        constant_integer: ConstantInteger,
        unary: Unary,
        binary: Binary,
        variable_reference: *Variable,
        local,
        argument,
        global,
        intrinsic: Intrinsic,
        dereference: *Value,
        call: Call,
        infer_or_ignore,
        array_initialization: ArrayInitialization,
        array_expression: ArrayExpression,
        enum_literal: []const u8,
        field_access: FieldAccess,
        string_literal: []const u8,
        aggregate_initialization: AggregateInitialization,
        zero,
        slice_expression: SliceExpression,
        @"unreachable",
        undefined,
        macro_reference: *Macro,
        macro_instantiation: Macro.Instantiation,
    },
    type: ?*Type = null,
    llvm: ?*llvm.Value = null,
    kind: Value.Kind = .right,

    pub const SliceExpression = struct {
        array_like: *Value,
        start: ?*Value,
        end: ?*Value,
    };

    pub const ArrayExpression = struct {
        array_like: *Value,
        index: *Value,
    };

    pub const ArrayInitialization = struct {
        values: []const *Value,
        is_constant: bool,
    };

    pub const AggregateInitialization = struct {
        names: []const []const u8,
        values: []const *Value,
        is_constant: bool,
        zero: bool,
    };

    const Intrinsic = union(Id) {
        alignof: *Type,
        byte_size: *Type,
        enum_name: *Value,
        extend: *Value,
        integer_max: *Type,
        int_from_enum: *Value,
        int_from_pointer: *Value,
        pointer_cast: *Value,
        select: Select,
        string_to_enum: StringToEnum,
        trap,
        truncate: *Value,
        va_start,
        va_end: *Value,
        va_copy,
        va_arg: VaArg,

        const Id = enum {
            alignof,
            byte_size,
            enum_name,
            extend,
            integer_max,
            int_from_enum,
            int_from_pointer,
            pointer_cast,
            select,
            string_to_enum,
            trap,
            truncate,
            va_start,
            va_end,
            va_copy,
            va_arg,
        };

        const Select = struct {
            condition: *Value,
            true_value: *Value,
            false_value: *Value,
        };

        const VaArg = struct {
            list: *Value,
            type: *Type,
        };

        const StringToEnum = struct {
            enum_type: *Type,
            string_value: *Value,
        };
    };

    fn is_constant(value: *Value) bool {
        // TODO: do some comptime evaluation?
        return switch (value.bb) {
            .constant_integer => true,
            .variable_reference => |variable| switch (value.kind) {
                .left => switch (variable.scope.kind) {
                    .global => true,
                    else => false,
                },
                .right => false,
            },
            .aggregate_initialization => |aggregate_initialization| aggregate_initialization.is_constant,
            .field_access => false,
            .binary => false,
            .array_initialization => |array_initialization| array_initialization.is_constant,
            .intrinsic => |intrinsic| switch (intrinsic) {
                .byte_size,
                .integer_max,
                => true,
                else => false,
            },
            .undefined => true,
            .call => false,
            .enum_literal => true,
            .unary => false,
            .array_expression => false,
            .string_literal => true,
            .dereference => false,
            else => @trap(),
        };
    }

    pub const Buffer = struct {
        buffer: lib.VirtualBuffer(Value),
        pub fn initialize() Buffer {
            return .{
                .buffer = .initialize(),
            };
        }

        pub fn add(values: *Buffer) *Value {
            return values.buffer.add();
        }
    };

    const Kind = enum {
        left,
        right,
    };

    const Keyword = enum {
        undefined,
        @"unreachable",
        zero,
    };

    const Builder = struct {
        kind: Value.Kind = .right,
        precedence: Precedence = .none,
        left: ?*Value = null,
        token: Token = .none,
        allow_assignment_operators: bool = false,

        fn with_token(vb: Builder, token: Token) Builder {
            var v = vb;
            v.token = token;
            return v;
        }

        fn with_precedence(vb: Builder, precedence: Precedence) Builder {
            var v = vb;
            v.precedence = precedence;
            return v;
        }

        fn with_left(vb: Builder, left: ?*Value) Builder {
            var v = vb;
            v.left = left;
            return v;
        }

        fn with_kind(vb: Builder, kind: Value.Kind) Builder {
            var v = vb;
            v.kind = kind;
            return v;
        }
    };
};

const Precedence = enum {
    none,
    assignment,
    @"or",
    @"and",
    comparison,
    bitwise,
    shifting,
    add_like,
    div_like,
    prefix,
    aggregate_initialization,
    postfix,

    pub fn increment(precedence: Precedence) Precedence {
        return @enumFromInt(@intFromEnum(precedence) + 1);
    }
};

const GlobalKind = enum {
    bits,
    @"enum",
    @"fn",
    macro,
    @"struct",
    typealias,
    @"union",
};

const CallingConvention = enum {
    c,

    pub fn to_llvm(calling_convention: CallingConvention) llvm.CallingConvention {
        return switch (calling_convention) {
            .c => .c,
        };
    }

    pub fn resolve(calling_convention: CallingConvention, target: Target) ResolvedCallingConvention {
        return switch (calling_convention) {
            .c => switch (target.cpu) {
                .x86_64 => switch (target.os) {
                    .linux => .system_v,
                },
            },
        };
    }
};

pub const Scope = struct {
    line: u32,
    column: u32,
    llvm: ?*llvm.DI.Scope = null,
    kind: Scope.Kind,
    parent: ?*Scope,

    pub const Kind = enum {
        global,
        function,
        local,
        for_each,
        macro_declaration,
        macro_instantiation_function,
        macro_instantiation_block,
    };
};

pub const LexicalBlock = struct {
    locals: lib.VirtualBuffer(*Local),
    statements: lib.VirtualBuffer(*Statement),
    scope: Scope,
};

pub const Function = struct {
    arguments: []const *Local,
    attributes: Attributes,
    main_block: *LexicalBlock,
    scope: Scope,

    return_alloca: ?*llvm.Value = null,
    exit_block: ?*llvm.BasicBlock = null,
    return_block: ?*llvm.BasicBlock = null,
    current_scope: ?*llvm.DI.Scope = null,
    return_pointer: ?*Value = null,

    const Keyword = enum {
        cc,
    };

    const Attributes = struct {
        inline_behavior: enum {
            default,
            always_inline,
            no_inline,
            inline_hint,
        } = .default,
        naked: bool = false,
    };
};

pub const ResolvedCallingConvention = enum {
    system_v,
    win64,
};

pub const IndexBuffer = lib.VirtualBuffer(u32);

pub const Module = struct {
    arena: *Arena,
    content: []const u8,
    offset: u64,
    line_offset: u64,
    line_character_offset: u64,
    types: Type.Buffer,
    locals: Local.Buffer,
    globals: Global.Buffer,
    values: Value.Buffer,
    macros: Macro.Buffer,
    pointer_types: IndexBuffer,
    slice_types: IndexBuffer,
    pair_struct_types: IndexBuffer,
    array_types: IndexBuffer,
    void_type: *Type,
    noreturn_type: *Type,
    va_list_type: ?*Type = null,
    void_value: *Value,
    lexical_blocks: lib.VirtualBuffer(LexicalBlock),
    statements: lib.VirtualBuffer(Statement),
    current_function: ?*Global = null,
    current_macro_declaration: ?*Macro = null,
    current_macro_instantiation: ?*Value = null,
    exit_block: ?*llvm.BasicBlock = null,
    continue_block: ?*llvm.BasicBlock = null,
    inline_at_debug_location: ?*llvm.DI.Location = null,
    name: []const u8,
    path: []const u8,
    executable: [:0]const u8,
    objects: []const [:0]const u8,
    scope: Scope,
    llvm: LLVM = undefined,
    build_mode: BuildMode,
    target: Target,
    has_debug_info: bool,
    silent: bool,

    const LLVM = struct {
        context: *llvm.Context,
        module: *llvm.Module,
        builder: *llvm.Builder,
        di_builder: *llvm.DI.Builder,
        file: *llvm.DI.File,
        compile_unit: *llvm.DI.CompileUnit,
        pointer_type: *llvm.Type,
        void_type: *llvm.Type,
        intrinsic_table: IntrinsicTable,
        memcmp: ?*llvm.Function = null,
        debug_tag: u32,

        const IntrinsicTable = struct {
            trap: llvm.Intrinsic.Id,
            va_start: llvm.Intrinsic.Id,
            va_end: llvm.Intrinsic.Id,
            va_copy: llvm.Intrinsic.Id,
        };
    };

    pub fn integer_type(module: *Module, bit_count: u32, sign: bool) *Type {
        switch (bit_count) {
            1...64 => {
                const index = @as(u64, @intFromBool(sign)) * 64 + bit_count;
                const result = module.types.get(index);
                assert(result.bb == .integer);
                assert(result.bb.integer.bit_count == bit_count);
                assert(result.bb.integer.signed == sign);
                return result;
            },
            128 => @trap(),
            else => @trap(),
        }
    }

    fn parse_hexadecimal(noalias module: *Module) u64 {
        var value: u64 = 0;
        while (true) {
            const ch = module.content[module.offset];
            if (!lib.is_hex_digit(ch)) {
                break;
            }

            module.offset += 1;
            value = lib.parse.accumulate_hexadecimal(value, ch);
        }

        return value;
    }

    fn parse_decimal(noalias module: *Module) u64 {
        var value: u64 = 0;
        while (true) {
            const ch = module.content[module.offset];
            if (!is_decimal_ch(ch)) {
                break;
            }

            module.offset += 1;
            value = lib.parse.accumulate_decimal(value, ch);
        }

        return value;
    }

    fn parse_octal(noalias module: *Module) u64 {
        var value: u64 = 0;
        while (true) {
            const ch = module.content[module.offset];
            if (!is_octal_ch(ch)) {
                break;
            }

            module.offset += 1;
            value = lib.parse.accumulate_octal(value, ch);
        }

        return value;
    }

    fn parse_binary(noalias module: *Module) u64 {
        var value: u64 = 0;
        while (true) {
            const ch = module.content[module.offset];
            if (!is_binary_ch(ch)) {
                break;
            }

            module.offset += 1;
            value = lib.parse.accumulate_binary(value, ch);
        }

        return value;
    }

    const AttributeBuildOptions = struct {
        return_type_abi: Abi.Information,
        abi_argument_types: []const *Type,
        argument_type_abis: []const Abi.Information,
        abi_return_type: *Type,
        attributes: Function.Attributes,
        call_site: bool,
    };

    pub fn build_attribute_list(module: *Module, options: AttributeBuildOptions) *llvm.Attribute.List {
        options.return_type_abi.semantic_type.resolve(module);
        const return_attributes = llvm.Attribute.Argument{
            .semantic_type = options.return_type_abi.semantic_type.llvm.memory.?,
            .abi_type = options.abi_return_type.llvm.abi.?,
            .dereferenceable_bytes = 0,
            .alignment = 0,
            .flags = .{
                .no_alias = false,
                .non_null = false,
                .no_undef = false,
                .sign_extend = options.return_type_abi.flags.kind == .extend and options.return_type_abi.flags.sign_extension,
                .zero_extend = options.return_type_abi.flags.kind == .extend and !options.return_type_abi.flags.sign_extension,
                .in_reg = false,
                .no_fp_class = .{},
                .struct_return = false,
                .writable = false,
                .dead_on_unwind = false,
                .in_alloca = false,
                .dereferenceable = false,
                .dereferenceable_or_null = false,
                .nest = false,
                .by_value = false,
                .by_reference = false,
                .no_capture = false,
            },
        };
        var argument_attribute_buffer: [128]llvm.Attribute.Argument = undefined;
        const argument_attributes = argument_attribute_buffer[0..options.abi_argument_types.len];

        if (options.return_type_abi.flags.kind == .indirect) {
            const abi_index = @intFromBool(options.return_type_abi.flags.sret_after_this);
            const argument_attribute = &argument_attributes[abi_index];
            argument_attribute.* = .{
                .semantic_type = options.return_type_abi.semantic_type.llvm.memory.?,
                .abi_type = options.abi_argument_types[abi_index].llvm.abi.?,
                .dereferenceable_bytes = 0,
                .alignment = options.return_type_abi.semantic_type.get_byte_alignment(),
                .flags = .{
                    .no_alias = true,
                    .non_null = false,
                    .no_undef = false,
                    .sign_extend = false,
                    .zero_extend = false,
                    .in_reg = options.return_type_abi.flags.in_reg,
                    .no_fp_class = .{},
                    .struct_return = true,
                    .writable = true,
                    .dead_on_unwind = true,
                    .in_alloca = false,
                    .dereferenceable = false,
                    .dereferenceable_or_null = false,
                    .nest = false,
                    .by_value = false,
                    .by_reference = false,
                    .no_capture = false,
                },
            };
        }

        for (options.argument_type_abis) |argument_type_abi| {
            for (argument_type_abi.abi_start..argument_type_abi.abi_start + argument_type_abi.abi_count) |abi_index| {
                const argument_attribute = &argument_attributes[abi_index];
                argument_type_abi.semantic_type.resolve(module);
                const abi_type = options.abi_argument_types[abi_index];
                abi_type.resolve(module);

                argument_attribute.* = .{
                    .semantic_type = argument_type_abi.semantic_type.llvm.memory.?,
                    .abi_type = abi_type.llvm.abi.?,
                    .dereferenceable_bytes = 0,
                    .alignment = if (argument_type_abi.flags.kind == .indirect) 8 else 0,
                    .flags = .{
                        .no_alias = false,
                        .non_null = false,
                        .no_undef = false,
                        .sign_extend = argument_type_abi.flags.kind == .extend and argument_type_abi.flags.sign_extension,
                        .zero_extend = argument_type_abi.flags.kind == .extend and !argument_type_abi.flags.sign_extension,
                        .in_reg = argument_type_abi.flags.in_reg,
                        .no_fp_class = .{},
                        .struct_return = false,
                        .writable = false,
                        .dead_on_unwind = false,
                        .in_alloca = false,
                        .dereferenceable = false,
                        .dereferenceable_or_null = false,
                        .nest = false,
                        .by_value = argument_type_abi.flags.indirect_by_value,
                        .by_reference = false,
                        .no_capture = false,
                    },
                };
            }
        }

        return llvm.Attribute.List.build(module.llvm.context, llvm.Attribute.Function{
            .prefer_vector_width = llvm.String{},
            .stack_protector_buffer_size = llvm.String{},
            .definition_probe_stack = llvm.String{},
            .definition_stack_probe_size = llvm.String{},
            .flags0 = .{
                .noreturn = options.return_type_abi.semantic_type == module.noreturn_type,
                .cmse_ns_call = false,
                .returns_twice = false,
                .cold = false,
                .hot = false,
                .no_duplicate = false,
                .convergent = false,
                .no_merge = false,
                .will_return = false,
                .no_caller_saved_registers = false,
                .no_cf_check = false,
                .no_callback = false,
                .alloc_size = false, // TODO
                .uniform_work_group_size = false,
                .nounwind = true,
                .aarch64_pstate_sm_body = false,
                .aarch64_pstate_sm_enabled = false,
                .aarch64_pstate_sm_compatible = false,
                .aarch64_preserves_za = false,
                .aarch64_in_za = false,
                .aarch64_out_za = false,
                .aarch64_inout_za = false,
                .aarch64_preserves_zt0 = false,
                .aarch64_in_zt0 = false,
                .aarch64_out_zt0 = false,
                .aarch64_inout_zt0 = false,
                .optimize_for_size = false,
                .min_size = false,
                .no_red_zone = false,
                .indirect_tls_seg_refs = false,
                .no_implicit_floats = false,
                .sample_profile_suffix_elision_policy = false,
                .memory_none = false,
                .memory_readonly = false,
                .memory_inaccessible_or_arg_memory_only = false,
                .memory_arg_memory_only = false,
                .strict_fp = false,
                .no_inline = options.attributes.inline_behavior == .no_inline,
                .always_inline = options.attributes.inline_behavior == .always_inline,
                .guard_no_cf = false,
                // TODO: branch protection function attributes
                // TODO: cpu features

                // CALL-SITE ATTRIBUTES
                .call_no_builtins = false,

                // DEFINITION-SITE ATTRIBUTES
                .definition_frame_pointer_kind = switch (module.has_debug_info) {
                    true => .all,
                    false => .none,
                },
                .definition_less_precise_fpmad = false,
                .definition_null_pointer_is_valid = false,
                .definition_no_trapping_fp_math = false,
                .definition_no_infs_fp_math = false,
                .definition_no_nans_fp_math = false,
                .definition_approx_func_fp_math = false,
                .definition_unsafe_fp_math = false,
                .definition_use_soft_float = false,
                .definition_no_signed_zeroes_fp_math = false,
                .definition_stack_realignment = false,
                .definition_backchain = false,
                .definition_split_stack = false,
                .definition_speculative_load_hardening = false,
                .definition_zero_call_used_registers = .all,
                // TODO: denormal builtins
                .definition_non_lazy_bind = false,
                .definition_cmse_nonsecure_entry = false,
                .definition_unwind_table_kind = .none,
            },
            .flags1 = .{
                .definition_disable_tail_calls = false,
                .definition_stack_protect_strong = false,
                .definition_stack_protect = false,
                .definition_stack_protect_req = false,
                .definition_aarch64_new_za = false,
                .definition_aarch64_new_zt0 = false,
                .definition_optimize_none = false,
                .definition_naked = !options.call_site and options.attributes.naked,
                .definition_inline_hint = !options.call_site and options.attributes.inline_behavior == .inline_hint,
            },
        }, return_attributes, argument_attributes, options.call_site);
    }

    const Pointer = struct {
        type: *Type,
        alignment: ?u32 = null,
    };

    pub fn get_pointer_type(module: *Module, pointer: Pointer) *Type {
        const p = Type.Pointer{
            .type = pointer.type,
            .alignment = if (pointer.alignment) |a| a else if (pointer.type.bb != .unresolved) pointer.type.get_byte_alignment() else null,
        };
        const all_types = module.types.get_slice();
        const pointer_type = for (module.pointer_types.get_slice()) |pointer_type_index| {
            const ty = &all_types[pointer_type_index];
            const pointer_type = &all_types[pointer_type_index].bb.pointer;
            if (pointer_type.type == p.type and pointer_type.alignment == p.alignment) {
                break ty;
            }
        } else blk: {
            const pointer_name = module.arena.join_string(&.{ "&", p.type.name });
            const pointer_type = module.types.append(.{
                .name = pointer_name,
                .bb = .{
                    .pointer = p,
                },
            });

            const index: u32 = @intCast(pointer_type - module.types.get_slice().ptr);
            _ = module.pointer_types.append(index);
            break :blk pointer_type;
        };

        return pointer_type;
    }

    fn parse_type(module: *Module) *Type {
        const start_character = module.content[module.offset];
        switch (start_character) {
            'a'...'z', 'A'...'Z', '_' => {
                const identifier = module.parse_identifier();
                var int_type = identifier.len > 1 and identifier[0] == 's' or identifier[0] == 'u';
                if (int_type) {
                    for (identifier[1..]) |ch| {
                        int_type = int_type and is_decimal_ch(ch);
                    }
                }

                if (int_type) {
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
                    const ty = module.types.find_by_name(identifier) orelse @trap();
                    return ty;
                }
            },
            '&' => {
                module.offset += 1;
                module.skip_space();
                const element_type = module.parse_type();
                const pointer_type = module.get_pointer_type(.{
                    .type = element_type,
                });
                return pointer_type;
            },
            left_bracket => {
                module.offset += 1;
                module.skip_space();

                const is_slice = module.consume_character_if_match(right_bracket);
                switch (is_slice) {
                    true => {
                        module.skip_space();
                        const element_type = module.parse_type();
                        const slice_type = module.get_slice_type(.{ .type = element_type });
                        return slice_type;
                    },
                    false => {
                        var length_inferred = false;
                        const offset = module.offset;
                        if (module.consume_character_if_match('_')) {
                            module.skip_space();
                            if (module.consume_character_if_match(']')) {
                                length_inferred = true;
                            } else {
                                module.offset = offset;
                            }
                        }

                        const element_count: u64 = switch (length_inferred) {
                            true => 0,
                            false => b: {
                                const v = module.parse_integer_value(false);
                                if (v == 0) {
                                    module.report_error();
                                }
                                break :b v;
                            },
                        };

                        if (!length_inferred) {
                            module.skip_space();
                            module.expect_character(right_bracket);
                        }

                        module.skip_space();

                        const element_type = module.parse_type();

                        const array_type = switch (element_count) {
                            0 => blk: {
                                const array_type = module.types.append(.{
                                    .name = "",
                                    .bb = .{
                                        .array = .{
                                            .element_type = element_type,
                                            .element_count = element_count,
                                        },
                                    },
                                });
                                break :blk array_type;
                            },
                            else => module.get_array_type(element_type, element_count),
                        };

                        return array_type;
                    },
                }
            },
            '#' => {
                module.offset += 1;

                const identifier = module.parse_identifier();
                if (lib.string.to_enum(Type.Intrinsic.Id, identifier)) |intrinsic| switch (intrinsic) {
                    .ReturnType => {
                        const return_type = module.current_function.?.variable.type.?.bb.function.semantic_return_type;
                        return return_type;
                    },
                    else => @trap(),
                } else module.report_error();
                @trap();
            },
            else => @trap(),
        }
    }

    pub fn get_array_type(module: *Module, element_type: *Type, element_count: u64) *Type {
        const all_types = module.types.get_slice();
        const array_type = for (module.array_types.get_slice()) |array_type_index| {
            const array_type = &all_types[array_type_index];
            assert(array_type.bb == .array);
            if (array_type.bb.array.element_count == element_count and array_type.bb.array.element_type == element_type) {
                break array_type;
            }
        } else module.types.append(.{
            .name = array_type_name(module.arena, element_type, element_count),
            .bb = .{
                .array = .{
                    .element_type = element_type,
                    .element_count = element_count,
                },
            },
        });

        return array_type;
    }

    const Slice = struct {
        type: *Type,
        alignment: ?u32 = null,
    };

    pub fn get_slice_type(module: *Module, slice: Slice) *Type {
        const alignment = if (slice.alignment) |a| a else slice.type.get_byte_alignment();
        const all_types = module.types.get_slice();

        for (module.slice_types.get_slice()) |slice_type_index| {
            const ty = &all_types[slice_type_index];
            const struct_type = &all_types[slice_type_index].bb.structure;
            assert(struct_type.is_slice);
            assert(struct_type.fields.len == 2);
            const pointer_type = struct_type.fields[0].type;
            if (pointer_type.bb.pointer.type == slice.type and pointer_type.bb.pointer.alignment == alignment) {
                return ty;
            }
        } else {
            const pointer_type = module.get_pointer_type(.{
                .type = slice.type,
                .alignment = slice.alignment,
            });
            const length_type = module.integer_type(64, false);

            const name = module.arena.join_string(&.{ "[]", slice.type.name });

            const fields = module.arena.allocate(Type.Struct.Field, 2);
            fields[0] = .{
                .bit_offset = 0,
                .byte_offset = 0,
                .type = pointer_type,
                .name = "pointer",
                .line = 0,
            };
            fields[1] = .{
                .bit_offset = 64,
                .byte_offset = 8,
                .type = length_type,
                .name = "length",
                .line = 0,
            };

            const slice_type = module.types.append(.{
                .bb = .{
                    .structure = .{
                        .fields = fields,
                        .byte_size = 16,
                        .bit_size = 128,
                        .byte_alignment = 8,
                        .bit_alignment = 64,
                        .line = 0,
                        .is_slice = true,
                    },
                },
                .name = name,
            });
            const index = slice_type - module.types.get_slice().ptr;
            _ = module.slice_types.append(@intCast(index));
            return slice_type;
        }
    }

    fn consume_character_if_match(noalias module: *Module, expected_ch: u8) bool {
        var is_ch = false;
        if (module.offset < module.content.len) {
            const ch = module.content[module.offset];
            is_ch = expected_ch == ch;
            module.offset += @intFromBool(is_ch);
        }

        return is_ch;
    }

    fn expect_character(noalias module: *Module, expected_ch: u8) void {
        if (!module.consume_character_if_match(expected_ch)) {
            module.report_error();
        }
    }

    fn report_error(noalias module: *Module) noreturn {
        @branchHint(.cold);
        _ = module;
        lib.os.abort();
    }

    fn get_line(module: *const Module) u32 {
        return @intCast(module.line_offset + 1);
    }

    fn get_column(module: *const Module) u32 {
        return @intCast(module.offset - module.line_character_offset + 1);
    }

    pub fn parse_identifier(noalias module: *Module) []const u8 {
        const start = module.offset;

        if (is_identifier_start_ch(module.content[start])) {
            module.offset += 1;

            while (module.offset < module.content.len) {
                if (is_identifier_ch(module.content[module.offset])) {
                    module.offset += 1;
                } else {
                    break;
                }
            }
        }

        if (module.offset - start == 0) {
            module.report_error();
        }

        return module.content[start..module.offset];
    }

    fn skip_space(noalias module: *Module) void {
        while (true) {
            const offset = module.offset;
            while (module.offset < module.content.len and is_space(module.content[module.offset])) {
                module.line_offset += @intFromBool(module.content[module.offset] == '\n');
                module.line_character_offset = if (module.content[module.offset] == '\n') module.offset else module.line_character_offset;
                module.offset += 1;
            }

            if (module.offset + 1 < module.content.len) {
                const i = module.offset;
                const is_comment = module.content[i] == '/' and module.content[i + 1] == '/';
                if (is_comment) {
                    while (module.offset < module.content.len and module.content[module.offset] != '\n') {
                        module.offset += 1;
                    }

                    if (module.offset < module.content.len) {
                        module.line_offset += 1;
                        module.line_character_offset = module.offset;
                        module.offset += 1;
                    }
                }
            }

            if (module.offset - offset == 0) {
                break;
            }
        }
    }

    const StatementStartKeyword = enum {
        @"_",
        @"return",
        @"if",
        // TODO: make `unreachable` a statement start keyword?
        @"for",
        @"while",
        @"switch",
        @"break",
        @"continue",
    };

    const rules = blk: {
        var r: [@typeInfo(Token.Id).@"enum".fields.len]Rule = undefined;
        var count: u32 = 0;
        r[@intFromEnum(Token.Id.none)] = .{
            .before = null,
            .after = null,
            .precedence = .none,
        };
        count += 1;
        r[@intFromEnum(Token.Id.end_of_statement)] = .{
            .before = null,
            .after = null,
            .precedence = .none,
        };
        count += 1;
        r[@intFromEnum(Token.Id.identifier)] = .{
            .before = &rule_before_identifier,
            .after = null,
            .precedence = .none,
        };
        count += 1;
        r[@intFromEnum(Token.Id.string_literal)] = .{
            .before = &rule_before_string_literal,
            .after = null,
            .precedence = .none,
        };
        count += 1;
        r[@intFromEnum(Token.Id.value_keyword)] = .{
            .before = &rule_before_value_keyword,
            .after = null,
            .precedence = .none,
        };
        count += 1;
        r[@intFromEnum(Token.Id.value_intrinsic)] = .{
            .before = &rule_before_value_intrinsic,
            .after = null,
            .precedence = .none,
        };
        count += 1;
        r[@intFromEnum(Token.Id.integer)] = .{
            .before = &rule_before_integer,
            .after = null,
            .precedence = .none,
        };
        count += 1;

        const assignment_operators = [_]Token.Id{
            .@"=",
            .@"+=",
            .@"-=",
            .@"*=",
            .@"/=",
            .@"%=",
            .@"&=",
            .@"|=",
            .@"^=",
            .@"<<=",
            .@">>=",
        };

        for (assignment_operators) |assignment_operator| {
            r[@intFromEnum(assignment_operator)] = .{
                .before = null,
                .after = rule_after_binary,
                .precedence = .assignment,
            };
            count += 1;
        }

        const comparison_operators = [_]Token.Id{
            .@"==",
            .@"!=",
            .@"<",
            .@">",
            .@"<=",
            .@">=",
        };

        for (comparison_operators) |comparison_operator| {
            r[@intFromEnum(comparison_operator)] = .{
                .before = null,
                .after = rule_after_binary,
                .precedence = .comparison,
            };
            count += 1;
        }

        const and_operators = [_]Token.Id{
            .@"and",
            .@"and?",
        };

        for (and_operators) |and_operator| {
            r[@intFromEnum(and_operator)] = .{
                .before = null,
                .after = rule_after_binary,
                .precedence = .@"or",
            };
            count += 1;
        }

        const or_operators = [_]Token.Id{
            .@"or",
            .@"or?",
        };

        for (or_operators) |or_operator| {
            r[@intFromEnum(or_operator)] = .{
                .before = null,
                .after = rule_after_binary,
                .precedence = .@"or",
            };
            count += 1;
        }

        const add_like_operators = [_]Token.Id{
            .@"+",
            .@"-",
        };

        for (add_like_operators) |add_like_operator| {
            r[@intFromEnum(add_like_operator)] = .{
                .before = rule_before_unary,
                .after = rule_after_binary,
                .precedence = .add_like,
            };
            count += 1;
        }

        const div_like_operators = [_]Token.Id{
            .@"*",
            .@"/",
            .@"%",
        };

        for (div_like_operators) |div_like_operator| {
            r[@intFromEnum(div_like_operator)] = .{
                .before = null,
                .after = rule_after_binary,
                .precedence = .div_like,
            };
            count += 1;
        }

        r[@intFromEnum(Token.Id.@"&")] = .{
            .before = rule_before_unary,
            .after = rule_after_binary,
            .precedence = .bitwise,
        };
        count += 1;

        r[@intFromEnum(Token.Id.@"!")] = .{
            .before = rule_before_unary,
            .after = null,
            .precedence = .none,
        };
        count += 1;

        r[@intFromEnum(Token.Id.@"~")] = .{
            .before = rule_before_unary,
            .after = null,
            .precedence = .none,
        };
        count += 1;

        const bitwise_operators = [_]Token.Id{
            .@"|",
            .@"^",
        };

        for (bitwise_operators) |bitwise_operator| {
            r[@intFromEnum(bitwise_operator)] = .{
                .before = null,
                .after = rule_after_binary,
                .precedence = .bitwise,
            };
            count += 1;
        }

        const shifting_operators = [_]Token.Id{
            .@"<<",
            .@">>",
        };

        for (shifting_operators) |shifting_operator| {
            r[@intFromEnum(shifting_operator)] = .{
                .before = null,
                .after = rule_after_binary,
                .precedence = .shifting,
            };
            count += 1;
        }

        r[@intFromEnum(Token.Id.@".&")] = .{
            .before = null,
            .after = rule_after_dereference,
            .precedence = .postfix,
        };
        count += 1;

        r[@intFromEnum(Token.Id.@"(")] = .{
            .before = rule_before_parenthesis,
            .after = rule_after_call,
            .precedence = .postfix,
        };
        count += 1;
        r[@intFromEnum(Token.Id.@")")] = .{
            .before = null,
            .after = null,
            .precedence = .none,
        };
        count += 1;

        r[@intFromEnum(Token.Id.@"[")] = .{
            .before = rule_before_bracket,
            .after = rule_after_bracket,
            .precedence = .postfix,
        };
        count += 1;
        r[@intFromEnum(Token.Id.@"]")] = .{
            .before = null,
            .after = null,
            .precedence = .none,
        };
        count += 1;

        r[@intFromEnum(Token.Id.@"{")] = .{
            .before = rule_before_brace,
            .after = null, // TODO: is this correct?
            .precedence = .none,
        };
        count += 1;
        r[@intFromEnum(Token.Id.@"}")] = .{
            .before = null,
            .after = null,
            .precedence = .none,
        };
        count += 1;

        r[@intFromEnum(Token.Id.@",")] = .{
            .before = null,
            .after = null,
            .precedence = .none,
        };
        count += 1;
        r[@intFromEnum(Token.Id.@".")] = .{
            .before = rule_before_dot,
            .after = rule_after_dot,
            .precedence = .postfix,
        };
        count += 1;
        r[@intFromEnum(Token.Id.@"..")] = .{
            .before = null,
            .after = null,
            .precedence = .none,
        };
        count += 1;
        r[@intFromEnum(Token.Id.@"...")] = .{
            .before = null,
            .after = null,
            .precedence = .none,
        };
        count += 1;

        assert(count == r.len);
        break :blk r;
    };

    const OperatorKeyword = enum {
        @"and",
        @"or",
    };

    fn tokenize(module: *Module) Token {
        module.skip_space();

        const start_index = module.offset;
        if (start_index == module.content.len) {
            module.report_error();
        }

        const start_character = module.content[start_index];
        const result: Token = switch (start_character) {
            ';' => blk: {
                module.offset += 1;
                break :blk .end_of_statement;
            },
            'a'...'z', 'A'...'Z', '_' => blk: {
                assert(is_identifier_start_ch(start_character));
                const identifier = module.parse_identifier();
                const token: Token = if (lib.string.to_enum(Value.Keyword, identifier)) |value_keyword|
                    .{ .value_keyword = value_keyword }
                else if (lib.string.to_enum(OperatorKeyword, identifier)) |operator_keyword| switch (operator_keyword) {
                    .@"and" => switch (module.content[module.offset]) {
                        '?' => b: {
                            module.offset += 1;
                            break :b .@"and?";
                        },
                        else => .@"and",
                    },
                    .@"or" => switch (module.content[module.offset]) {
                        '?' => b: {
                            module.offset += 1;
                            break :b .@"or?";
                        },
                        else => .@"or",
                    },
                } else .{ .identifier = identifier };
                break :blk token;
            },
            '#' => if (is_identifier_start_ch(module.content[module.offset + 1])) blk: {
                module.offset += 1;
                const value_intrinsic_identifier = module.parse_identifier();
                const value_intrinsic = lib.string.to_enum(Value.Intrinsic.Id, value_intrinsic_identifier) orelse module.report_error();
                break :blk .{
                    .value_intrinsic = value_intrinsic,
                };
            } else {
                @trap();
            },
            '0' => blk: {
                const next_ch = module.content[start_index + 1];
                const token_integer_kind: Token.Integer.Kind = switch (next_ch) {
                    'x' => .hexadecimal,
                    'o' => .octal,
                    'b' => .binary,
                    'd' => .decimal,
                    else => .decimal,
                };
                const value: u64 = switch (token_integer_kind) {
                    .binary => b: {
                        module.offset += 2;
                        const v = module.parse_binary();
                        break :b v;
                    },
                    .octal => b: {
                        module.offset += 2;
                        const v = module.parse_octal();
                        break :b v;
                    },
                    .decimal => switch (next_ch) {
                        0...9 => module.report_error(),
                        else => switch (next_ch) {
                            'd' => b: {
                                module.offset += 2;
                                const v = module.parse_decimal();
                                break :b v;
                            },
                            else => b: {
                                module.offset += 1;
                                break :b 0;
                            },
                        },
                    },
                    .hexadecimal => b: {
                        module.offset += 2;
                        const v = module.parse_hexadecimal();
                        break :b v;
                    },
                };

                if (module.content[module.offset] == '.' and module.content[module.offset + 1] != '.') {
                    @trap();
                } else {
                    break :blk .{ .integer = .{ .value = value, .kind = token_integer_kind } };
                }
            },
            '1'...'9' => blk: {
                const decimal = module.parse_decimal();
                if (module.content[module.offset] == '.' and module.content[module.offset + 1] != '.') {
                    @trap();
                } else {
                    break :blk .{ .integer = .{ .value = decimal, .kind = .decimal } };
                }
            },
            '+', '-', '*', '/', '%', '&', '|', '^', '!' => |c| blk: {
                const next_ch = module.content[start_index + 1];
                const token_id: Token.Id = switch (next_ch) {
                    '=' => switch (c) {
                        '!' => .@"!=",
                        '+' => .@"+=",
                        '-' => .@"-=",
                        '*' => .@"*=",
                        '/' => .@"/=",
                        '%' => .@"%=",
                        '^' => .@"^=",
                        '|' => .@"|=",
                        '&' => .@"&=",
                        else => @trap(),
                    },
                    else => switch (c) {
                        '+' => .@"+",
                        '-' => .@"-",
                        '*' => .@"*",
                        '/' => .@"/",
                        '%' => .@"%",
                        '&' => .@"&",
                        '|' => .@"|",
                        '^' => .@"^",
                        '!' => .@"!",
                        else => unreachable,
                    },
                };

                const token = switch (token_id) {
                    else => unreachable,
                    inline .@"+",
                    .@"-",
                    .@"*",
                    .@"/",
                    .@"%",
                    .@"&",
                    .@"|",
                    .@"^",
                    .@"!=",
                    .@"+=",
                    .@"-=",
                    .@"*=",
                    .@"/=",
                    .@"%=",
                    .@"&=",
                    .@"|=",
                    .@"^=",
                    .@"!",
                    => |tid| @unionInit(Token, @tagName(tid), {}),
                };

                module.offset += @as(u32, 1) + @intFromBool(next_ch == '=');

                break :blk token;
            },
            '<' => blk: {
                const next_ch = module.content[start_index + 1];
                const token_id: Token.Id = switch (next_ch) {
                    '<' => switch (module.content[start_index + 2]) {
                        '=' => .@"<<=",
                        else => .@"<<",
                    },
                    '=' => .@"<=",
                    else => .@"<",
                };

                module.offset += switch (token_id) {
                    .@"<<=" => 3,
                    .@"<<", .@"<=" => 2,
                    .@"<" => 1,
                    else => unreachable,
                };

                const token = switch (token_id) {
                    else => unreachable,
                    inline .@"<<=",
                    .@"<<",
                    .@"<=",
                    .@"<",
                    => |tid| @unionInit(Token, @tagName(tid), {}),
                };
                break :blk token;
            },
            '>' => blk: {
                const next_ch = module.content[start_index + 1];
                const token_id: Token.Id = switch (next_ch) {
                    '>' => switch (module.content[start_index + 2]) {
                        '=' => .@">>=",
                        else => .@">>",
                    },
                    '=' => .@">=",
                    else => .@">",
                };

                module.offset += switch (token_id) {
                    .@">>=" => 3,
                    .@">>", .@">=" => 2,
                    .@">" => 1,
                    else => unreachable,
                };

                const token = switch (token_id) {
                    else => unreachable,
                    inline .@">>=",
                    .@">>",
                    .@">=",
                    .@">",
                    => |tid| @unionInit(Token, @tagName(tid), {}),
                };
                break :blk token;
            },
            '.' => blk: {
                const next_ch = module.content[start_index + 1];
                const token_id: Token.Id = switch (next_ch) {
                    else => .@".",
                    '.' => switch (module.content[start_index + 2]) {
                        '.' => .@"...",
                        else => .@"..",
                    },
                    '&' => .@".&",
                };

                module.offset += switch (token_id) {
                    .@"." => 1,
                    .@".&" => 2,
                    .@".." => 2,
                    .@"..." => 3,
                    else => @trap(),
                };
                const token = switch (token_id) {
                    else => unreachable,
                    inline .@".&",
                    .@".",
                    .@"..",
                    .@"...",
                    => |tid| @unionInit(Token, @tagName(tid), {}),
                };
                break :blk token;
            },
            '=' => blk: {
                const next_ch = module.content[start_index + 1];
                const token_id: Token.Id = switch (next_ch) {
                    '=' => .@"==",
                    else => .@"=",
                };
                module.offset += switch (token_id) {
                    .@"==" => 2,
                    .@"=" => 1,
                    else => @trap(),
                };
                const token = switch (token_id) {
                    else => unreachable,
                    inline .@"==", .@"=" => |tid| @unionInit(Token, @tagName(tid), {}),
                };
                break :blk token;
            },
            left_parenthesis => blk: {
                module.offset += 1;
                break :blk .@"(";
            },
            right_parenthesis => blk: {
                module.offset += 1;
                break :blk .@")";
            },
            left_bracket => blk: {
                module.offset += 1;
                break :blk .@"[";
            },
            right_bracket => blk: {
                module.offset += 1;
                break :blk .@"]";
            },
            left_brace => blk: {
                module.offset += 1;
                break :blk .@"{";
            },
            right_brace => blk: {
                module.offset += 1;
                break :blk .@"}";
            },
            ',' => blk: {
                module.offset += 1;
                break :blk .@",";
            },
            '"' => blk: {
                module.offset += 1;

                const string_literal_start = start_index + 1;
                while (module.offset < module.content.len) : (module.offset += 1) {
                    if (module.consume_character_if_match('"')) {
                        break;
                    }
                }

                const string_slice = module.content[string_literal_start..][0 .. (module.offset - 1) - string_literal_start];

                break :blk .{
                    .string_literal = string_slice,
                };
            },
            '\'' => blk: {
                module.offset += 1;
                const ch_after_quote = module.content[module.offset];
                const ch: u8 = switch (ch_after_quote) {
                    '\\' => switch (module.content[module.offset + 1]) {
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        else => @trap(),
                    },
                    else => ch_after_quote,
                };
                module.offset += @as(u64, @intFromBool(ch_after_quote == '\\')) + 1;

                module.expect_character('\'');

                break :blk .{
                    .integer = .{
                        .value = ch,
                        .kind = .decimal,
                    },
                };
            },
            '~' => blk: {
                module.offset += 1;

                break :blk .@"~";
            },
            else => @trap(),
        };

        assert(start_index != module.offset);

        return result;
    }

    const Rule = struct {
        before: ?*const Rule.Function,
        after: ?*const Rule.Function,
        precedence: Precedence,

        const Function = fn (noalias module: *Module, scope: *Scope, value_builder: Value.Builder) *Value;
    };

    fn parse_value(module: *Module, scope: *Scope, value_builder: Value.Builder) *Value {
        assert(value_builder.precedence == .none);
        assert(value_builder.left == null);
        const value = module.parse_precedence(scope, value_builder.with_precedence(.assignment));
        return value;
    }

    fn parse_precedence(module: *Module, scope: *Scope, value_builder: Value.Builder) *Value {
        assert(value_builder.token == .none);
        const token = module.tokenize();
        const rule = &rules[@intFromEnum(token)];
        if (rule.before) |before| {
            const left = before(module, scope, value_builder.with_precedence(.none).with_token(token));
            const result = module.parse_precedence_left(scope, value_builder.with_left(left));
            return result;
        } else {
            module.report_error();
        }
    }

    fn parse_precedence_left(module: *Module, scope: *Scope, value_builder: Value.Builder) *Value {
        var result = value_builder.left;
        const precedence = value_builder.precedence;
        while (true) {
            const checkpoint = module.offset;
            const token = module.tokenize();
            const token_rule = &rules[@intFromEnum(token)];
            const token_precedence: Precedence = switch (token_rule.precedence) {
                .assignment => switch (value_builder.allow_assignment_operators) {
                    true => .assignment,
                    false => .none,
                },
                else => |p| p,
            };
            if (@intFromEnum(precedence) > @intFromEnum(token_precedence)) {
                module.offset = checkpoint;
                break;
            }

            const after_rule = token_rule.after orelse module.report_error();
            const old = result;
            const new = after_rule(module, scope, value_builder.with_token(token).with_precedence(.none).with_left(old));
            result = new;
        }

        return result.?;
    }

    fn parse_statement(module: *Module, scope: *Scope) *Statement {
        const statement_line = module.get_line();
        const statement_column = module.get_column();

        const statement_start_character = module.content[module.offset];
        const statement = module.statements.add();
        var require_semicolon = true;
        statement.* = .{
            .bb = switch (statement_start_character) {
                '>' => blk: {
                    module.offset += 1;
                    module.skip_space();
                    const local_name = module.parse_identifier();
                    module.skip_space();
                    const local_type: ?*Type = if (module.consume_character_if_match(':')) b: {
                        module.skip_space();
                        const t = module.parse_type();
                        module.skip_space();
                        break :b t;
                    } else null;
                    module.expect_character('=');
                    const local_value = module.parse_value(scope, .{});
                    const local = module.locals.add();
                    local.* = .{
                        .variable = .{
                            .initial_value = local_value,
                            .type = local_type,
                            .name = local_name,
                            .line = statement_line,
                            .column = statement_column,
                            .scope = scope,
                        },
                        .argument_index = null,
                    };
                    switch (scope.kind) {
                        .local => {
                            const block: *LexicalBlock = @fieldParentPtr("scope", scope);
                            _ = block.locals.append(local);
                        },
                        else => @trap(),
                    }
                    break :blk .{
                        .local = local,
                    };
                },
                '#' => .{
                    .expression = module.parse_value(scope, .{}),
                },
                'A'...'Z', 'a'...'z' => blk: {
                    const statement_start_identifier = module.parse_identifier();

                    if (lib.string.to_enum(StatementStartKeyword, statement_start_identifier)) |statement_start_keyword| switch (statement_start_keyword) {
                        ._ => @trap(),
                        .@"return" => break :blk .{
                            .@"return" = module.parse_value(scope, .{}),
                        },
                        .@"if" => {
                            module.skip_space();

                            module.expect_character(left_parenthesis);
                            module.skip_space();

                            const condition = module.parse_value(scope, .{});

                            module.skip_space();
                            module.expect_character(right_parenthesis);

                            module.skip_space();

                            const if_statement = module.parse_statement(scope);

                            module.skip_space();

                            var is_else = false;
                            if (is_identifier_start_ch(module.content[module.offset])) {
                                const identifier = module.parse_identifier();
                                is_else = lib.string.equal(identifier, "else");
                                if (!is_else) {
                                    module.offset -= identifier.len;
                                } else {
                                    module.skip_space();
                                }
                            }

                            const else_block = switch (is_else) {
                                true => module.parse_statement(scope),
                                false => null,
                            };

                            require_semicolon = false;

                            break :blk .{
                                .@"if" = .{
                                    .condition = condition,
                                    .if_statement = if_statement,
                                    .else_statement = else_block,
                                },
                            };
                        },
                        .@"while" => {
                            module.skip_space();

                            module.expect_character(left_parenthesis);
                            module.skip_space();

                            const condition = module.parse_value(scope, .{});

                            module.skip_space();
                            module.expect_character(right_parenthesis);

                            module.skip_space();

                            const while_block = module.parse_block(scope);

                            require_semicolon = false;

                            break :blk .{
                                .@"while" = .{
                                    .condition = condition,
                                    .block = while_block,
                                },
                            };
                        },
                        .@"for" => {
                            module.skip_space();

                            module.expect_character(left_parenthesis);
                            module.skip_space();

                            statement.* = .{
                                .line = statement_line,
                                .column = statement_column,
                                .bb = .{
                                    .for_each = .{
                                        .locals = &.{},
                                        .left_values = &.{},
                                        .right_values = &.{},
                                        .predicate = undefined,
                                        .scope = .{
                                            .line = statement_line,
                                            .column = statement_column,
                                            .kind = .for_each,
                                            .parent = scope,
                                        },
                                        .kind = undefined,
                                    },
                                },
                            };

                            var local_buffer: [64]*Local = undefined;
                            var left_value_buffer: [64]Value.Kind = undefined;
                            var left_value_count: u64 = 0;

                            while (true) {
                                module.skip_space();

                                const is_left = switch (module.content[module.offset]) {
                                    '&' => true,
                                    else => false,
                                };
                                module.offset += @intFromBool(is_left);

                                const for_local_line = module.get_line();
                                const for_local_column = module.get_column();

                                if (is_identifier_start_ch(module.content[module.offset])) {
                                    const identifier = module.parse_identifier();
                                    const local = module.locals.add();
                                    local.* = .{
                                        .variable = .{
                                            .type = null,
                                            .initial_value = undefined,
                                            .scope = &statement.bb.for_each.scope,
                                            .name = identifier,
                                            .line = for_local_line,
                                            .column = for_local_column,
                                        },
                                        .argument_index = null,
                                    };
                                    local_buffer[left_value_count] = local;
                                    left_value_buffer[left_value_count] = switch (is_left) {
                                        true => .left,
                                        false => .right,
                                    };
                                    left_value_count += 1;
                                } else {
                                    @trap();
                                }

                                module.skip_space();

                                if (!module.consume_character_if_match(',')) {
                                    module.expect_character(':');
                                    break;
                                }
                            }

                            module.skip_space();

                            var right_value_buffer: [64]*Value = undefined;
                            var right_value_count: u64 = 0;

                            right_value_buffer[right_value_count] = module.parse_value(scope, .{
                                .kind = .left,
                            });
                            right_value_count += 1;

                            module.skip_space();

                            const token = module.tokenize();
                            const kind: Statement.ForEach.Kind = switch (token) {
                                .@")" => b: {
                                    module.offset += 1;
                                    break :b .slice;
                                },
                                .@".." => b: {
                                    if (left_value_count != 1) {
                                        module.report_error();
                                    }
                                    right_value_buffer[0].kind = .right;

                                    right_value_buffer[right_value_count] = module.parse_value(scope, .{
                                        .kind = .right,
                                    });
                                    right_value_count += 1;

                                    module.expect_character(right_parenthesis);
                                    break :b .range;
                                },
                                else => @trap(),
                            };
                            statement.bb.for_each.kind = kind;

                            module.skip_space();
                            //     if (!module.consume_character_if_match(',')) {
                            //         module.expect_character(right_parenthesis);
                            //         @trap();
                            //     }
                            //
                            // while (true) {
                            //     module.skip_space();
                            //
                            //     right_value_buffer[right_value_count] = module.parse_value(scope, .{
                            //         .kind = .left,
                            //     });
                            //     right_value_count += 1;
                            //
                            //     module.skip_space();
                            //
                            //     if (!module.consume_character_if_match(',')) {
                            //         module.expect_character(right_parenthesis);
                            //         break;
                            //     }
                            // }

                            if (kind == .slice and left_value_count != right_value_count) {
                                module.report_error();
                            }

                            const locals = module.arena.allocate(*Local, left_value_count);
                            @memcpy(locals, local_buffer[0..left_value_count]);
                            const left_values = module.arena.allocate(Value.Kind, left_value_count);
                            @memcpy(left_values, left_value_buffer[0..left_value_count]);
                            const right_values = module.arena.allocate(*Value, right_value_count);
                            @memcpy(right_values, right_value_buffer[0..right_value_count]);

                            statement.bb.for_each.locals = locals;
                            statement.bb.for_each.left_values = left_values;
                            statement.bb.for_each.right_values = right_values;

                            const predicate = module.parse_statement(&statement.bb.for_each.scope);
                            statement.bb.for_each.predicate = predicate;

                            module.skip_space();

                            require_semicolon = false;

                            break :blk statement.bb;
                        },
                        .@"switch" => {
                            module.skip_space();
                            module.expect_character(left_parenthesis);
                            module.skip_space();

                            const discriminant = module.parse_value(scope, .{});

                            module.skip_space();
                            module.expect_character(right_parenthesis);

                            module.skip_space();
                            module.expect_character(left_brace);

                            var clause_buffer: [64]Statement.Switch.Clause = undefined;
                            var clause_count: u64 = 0;

                            while (true) {
                                module.skip_space();

                                const is_else = is_else_blk: {
                                    var is_else = false;
                                    if (is_identifier_start_ch(module.content[module.offset])) {
                                        const i = module.parse_identifier();
                                        is_else = lib.string.equal(i, "else");
                                        if (!is_else) {
                                            module.offset -= i.len;
                                        }
                                    }

                                    break :is_else_blk is_else;
                                };

                                const clause_values: []const *Value = if (is_else) b: {
                                    module.skip_space();

                                    module.expect_character('=');
                                    module.expect_character('>');
                                    break :b &.{};
                                } else b: {
                                    var case_buffer: [64]*Value = undefined;
                                    var case_count: u64 = 0;

                                    while (true) {
                                        const case_value = module.parse_value(scope, .{});
                                        case_buffer[case_count] = case_value;
                                        case_count += 1;

                                        _ = module.consume_character_if_match(',');

                                        module.skip_space();

                                        if (module.consume_character_if_match('=')) {
                                            module.expect_character('>');
                                            break;
                                        }
                                    }

                                    const clause_values = module.arena.allocate(*Value, case_count);
                                    @memcpy(clause_values, case_buffer[0..case_count]);
                                    break :b clause_values;
                                };

                                module.skip_space();

                                const clause_block = module.parse_block(scope);

                                clause_buffer[clause_count] = .{
                                    .values = clause_values,
                                    .block = clause_block,
                                };
                                clause_count += 1;

                                _ = module.consume_character_if_match(',');

                                module.skip_space();

                                if (module.consume_character_if_match(right_brace)) {
                                    break;
                                }
                            }

                            const clauses = module.arena.allocate(Statement.Switch.Clause, clause_count);
                            @memcpy(clauses, clause_buffer[0..clause_count]);

                            require_semicolon = false;

                            break :blk .{
                                .@"switch" = .{
                                    .discriminant = discriminant,
                                    .clauses = clauses,
                                },
                            };
                        },
                        .@"break" => break :blk .break_statement,
                        .@"continue" => break :blk .continue_statement,
                    } else {
                        module.offset -= statement_start_identifier.len;

                        const left = module.parse_value(scope, .{
                            .kind = .left,
                        });

                        module.skip_space();

                        if (module.consume_character_if_match(';')) {
                            require_semicolon = false;
                            break :blk .{
                                .expression = left,
                            };
                        } else {
                            const operator_start_character = module.content[module.offset];
                            const operator_next_character = module.content[module.offset + 1];
                            const operator_next_next_character = module.content[module.offset + 2];
                            const operator: Statement.Assignment.Operator = switch (operator_start_character) {
                                '=' => .@"=",
                                '+' => switch (operator_next_character) {
                                    '=' => .@"+=",
                                    else => @trap(),
                                },
                                '-' => switch (operator_next_character) {
                                    '=' => .@"-=",
                                    else => @trap(),
                                },
                                '*' => switch (operator_next_character) {
                                    '=' => .@"*=",
                                    else => @trap(),
                                },
                                '/' => switch (operator_next_character) {
                                    '=' => .@"/=",
                                    else => @trap(),
                                },
                                '%' => switch (operator_next_character) {
                                    '=' => .@"%=",
                                    else => @trap(),
                                },
                                '>' => switch (operator_next_character) {
                                    '>' => switch (operator_next_next_character) {
                                        '=' => .@">>=",
                                        else => @trap(),
                                    },
                                    else => @trap(),
                                },
                                '<' => switch (operator_next_character) {
                                    '<' => switch (operator_next_next_character) {
                                        '=' => .@"<<=",
                                        else => @trap(),
                                    },
                                    else => @trap(),
                                },
                                '&' => switch (operator_next_character) {
                                    '=' => .@"&=",
                                    else => @trap(),
                                },
                                '|' => switch (operator_next_character) {
                                    '=' => .@"|=",
                                    else => @trap(),
                                },
                                '^' => switch (operator_next_character) {
                                    '=' => .@"^=",
                                    else => @trap(),
                                },
                                else => @trap(),
                            };
                            module.offset += switch (operator) {
                                .@"=" => 1,
                                .@"+=",
                                .@"-=",
                                .@"*=",
                                .@"/=",
                                .@"%=",
                                .@"&=",
                                .@"|=",
                                .@"^=",
                                => 2,
                                .@">>=",
                                .@"<<=",
                                => 3,
                            };

                            module.skip_space();

                            const right = module.parse_value(scope, .{});

                            break :blk .{
                                .assignment = .{
                                    .left = left,
                                    .right = right,
                                    .kind = operator,
                                },
                            };
                        }
                    }
                },
                left_brace => blk: {
                    require_semicolon = false;
                    break :blk .{
                        .block = module.parse_block(scope),
                    };
                },
                else => @trap(),
            },
            .line = statement_line,
            .column = statement_column,
        };

        if (require_semicolon) {
            module.expect_character(';');
        }

        return statement;
    }

    fn parse_block(module: *Module, parent_scope: *Scope) *LexicalBlock {
        const block = module.lexical_blocks.append(.{
            .statements = .initialize(),
            .locals = .initialize(),
            .scope = .{
                .kind = .local,
                .parent = parent_scope,
                .line = module.get_line(),
                .column = module.get_column(),
            },
        });
        const scope = &block.scope;

        module.expect_character(left_brace);

        while (true) {
            module.skip_space();

            if (module.offset == module.content.len) {
                break;
            }

            if (module.consume_character_if_match(right_brace)) {
                break;
            }

            const statement = module.parse_statement(scope);
            _ = block.statements.append(statement);
        }

        return block;
    }

    fn rule_before_dot(noalias module: *Module, scope: *Scope, value_builder: Value.Builder) *Value {
        _ = scope;
        _ = value_builder;
        module.skip_space();
        const identifier = module.parse_identifier();

        const value = module.values.add();
        value.* = .{
            .bb = .{
                .enum_literal = identifier,
            },
        };
        return value;
    }

    fn rule_after_dot(noalias module: *Module, scope: *Scope, value_builder: Value.Builder) *Value {
        _ = scope;
        module.skip_space();
        const left = value_builder.left orelse module.report_error();
        left.kind = .left;
        const identifier = module.parse_identifier();
        const value = module.values.add();
        value.* = .{
            .bb = .{
                .field_access = .{
                    .aggregate = left,
                    .field = identifier,
                },
            },
            .kind = value_builder.kind,
        };
        return value;
    }

    fn rule_before_string_literal(noalias module: *Module, parent_scope: *Scope, value_builder: Value.Builder) *Value {
        _ = parent_scope;
        const value = module.values.add();
        value.* = .{
            .bb = .{
                .string_literal = value_builder.token.string_literal,
            },
        };
        return value;
    }

    fn reference_identifier(noalias module: *Module, current_scope: *Scope, identifier: []const u8, kind: Value.Kind) *Value {
        assert(!lib.string.equal(identifier, ""));
        assert(!lib.string.equal(identifier, "_"));

        var scope_it: ?*Scope = current_scope;
        const variable = blk: while (scope_it) |scope| : (scope_it = scope.parent) {
            switch (scope.kind) {
                .global => {
                    assert(scope.parent == null);
                    const m: *Module = @fieldParentPtr("scope", scope);
                    assert(m == module);
                    for (module.globals.get_slice()) |*global| {
                        if (lib.string.equal(global.variable.name, identifier)) {
                            break :blk &global.variable;
                        }
                    }

                    for (module.macros.get_slice()) |*macro| {
                        if (lib.string.equal(macro.name, identifier)) {
                            const value = module.values.add();
                            value.* = .{
                                .bb = .{
                                    .macro_reference = macro,
                                },
                            };
                            return value;
                        }
                    }
                },
                .function => {
                    assert(scope.parent != null);
                    const f: *Function = @fieldParentPtr("scope", scope);
                    for (f.arguments) |argument| {
                        if (lib.string.equal(argument.variable.name, identifier)) {
                            break :blk &argument.variable;
                        }
                    }
                },
                .local => {
                    assert(scope.parent != null);
                    assert(scope.parent.?.kind != .global);
                    const block: *LexicalBlock = @fieldParentPtr("scope", scope);
                    for (block.locals.get_slice()) |local| {
                        if (lib.string.equal(local.variable.name, identifier)) {
                            break :blk &local.variable;
                        }
                    }
                },
                .for_each => {
                    assert(scope.parent != null);
                    const for_each: *Statement.ForEach = @fieldParentPtr("scope", scope);
                    for (for_each.locals) |local| {
                        if (lib.string.equal(local.variable.name, identifier)) {
                            break :blk &local.variable;
                        }
                    }
                },
                .macro_declaration => {
                    assert(scope.parent != null);
                    const macro: *Macro = @fieldParentPtr("scope", scope);
                    for (macro.arguments) |argument| {
                        if (lib.string.equal(argument.variable.name, identifier)) {
                            break :blk &argument.variable;
                        }
                    }
                },
                .macro_instantiation_function => {
                    assert(scope.parent != null);
                    const macro: *Macro.Instantiation = @fieldParentPtr("function_scope", scope);
                    for (macro.declaration_arguments) |argument| {
                        if (lib.string.equal(argument.variable.name, identifier)) {
                            break :blk &argument.variable;
                        }
                    }
                },
                .macro_instantiation_block => unreachable,
            }
        } else {
            module.report_error();
        };

        const value = module.values.add();
        value.* = .{
            .bb = .{
                .variable_reference = variable,
            },
            .kind = kind,
        };

        return value;
    }

    fn rule_before_identifier(noalias module: *Module, current_scope: *Scope, value_builder: Value.Builder) *Value {
        const identifier = value_builder.token.identifier;
        const result = module.reference_identifier(current_scope, identifier, value_builder.kind);
        return result;
    }

    fn rule_before_value_keyword(noalias module: *Module, scope: *Scope, value_builder: Value.Builder) *Value {
        _ = scope;
        const value = module.values.add();
        const new_value: Value = switch (value_builder.token.value_keyword) {
            .zero => .{
                .bb = .zero,
            },
            .@"unreachable" => .{
                .bb = .@"unreachable",
            },
            .undefined => .{
                .bb = .undefined,
            },
        };
        value.* = new_value;
        return value;
    }

    fn rule_before_value_intrinsic(noalias module: *Module, scope: *Scope, value_builder: Value.Builder) *Value {
        const intrinsic = value_builder.token.value_intrinsic;
        const value = module.values.add();

        value.* = switch (intrinsic) {
            .alignof => blk: {
                module.skip_space();
                module.expect_character(left_parenthesis);
                module.skip_space();
                const ty = module.parse_type();
                module.expect_character(right_parenthesis);
                break :blk .{
                    .bb = .{
                        .intrinsic = .{
                            .alignof = ty,
                        },
                    },
                };
            },
            .byte_size => blk: {
                module.skip_space();
                module.expect_character(left_parenthesis);
                module.skip_space();
                const ty = module.parse_type();
                module.expect_character(right_parenthesis);
                break :blk .{
                    .bb = .{
                        .intrinsic = .{
                            .byte_size = ty,
                        },
                    },
                };
            },
            .enum_name => blk: {
                module.skip_space();
                module.expect_character(left_parenthesis);
                module.skip_space();
                const arg_value = module.parse_value(scope, .{});
                module.expect_character(right_parenthesis);
                break :blk .{
                    .bb = .{
                        .intrinsic = .{
                            .enum_name = arg_value,
                        },
                    },
                };
            },
            .extend => blk: {
                module.skip_space();
                module.expect_character(left_parenthesis);
                module.skip_space();
                const arg_value = module.parse_value(scope, .{});
                module.expect_character(right_parenthesis);
                break :blk .{
                    .bb = .{
                        .intrinsic = .{
                            .extend = arg_value,
                        },
                    },
                };
            },
            .integer_max => blk: {
                module.skip_space();
                module.expect_character(left_parenthesis);
                module.skip_space();
                const ty = module.parse_type();
                module.expect_character(right_parenthesis);
                break :blk .{
                    .bb = .{
                        .intrinsic = .{
                            .integer_max = ty,
                        },
                    },
                };
            },
            .int_from_enum => blk: {
                module.skip_space();
                module.expect_character(left_parenthesis);
                module.skip_space();
                const arg_value = module.parse_value(scope, .{});
                module.expect_character(right_parenthesis);
                break :blk .{
                    .bb = .{
                        .intrinsic = .{
                            .int_from_enum = arg_value,
                        },
                    },
                };
            },
            .int_from_pointer => blk: {
                module.skip_space();
                module.expect_character(left_parenthesis);
                module.skip_space();
                const arg_value = module.parse_value(scope, .{});
                module.expect_character(right_parenthesis);
                break :blk .{
                    .bb = .{
                        .intrinsic = .{
                            .int_from_pointer = arg_value,
                        },
                    },
                };
            },
            .pointer_cast => blk: {
                module.skip_space();
                module.expect_character(left_parenthesis);
                module.skip_space();
                const v = module.parse_value(scope, .{});
                module.expect_character(right_parenthesis);
                break :blk .{
                    .bb = .{
                        .intrinsic = .{
                            .pointer_cast = v,
                        },
                    },
                };
            },
            .select => blk: {
                module.skip_space();
                module.expect_character(left_parenthesis);
                module.skip_space();
                const condition = module.parse_value(scope, .{});
                module.expect_character(',');
                module.skip_space();
                const true_value = module.parse_value(scope, .{});
                module.expect_character(',');
                module.skip_space();
                const false_value = module.parse_value(scope, .{});
                module.skip_space();
                module.expect_character(right_parenthesis);
                break :blk .{
                    .bb = .{
                        .intrinsic = .{
                            .select = .{
                                .condition = condition,
                                .true_value = true_value,
                                .false_value = false_value,
                            },
                        },
                    },
                };
            },
            .string_to_enum => blk: {
                module.skip_space();
                module.expect_character(left_parenthesis);
                module.skip_space();
                const enum_type = module.parse_type();
                module.expect_character(',');
                module.skip_space();
                const string_value = module.parse_value(scope, .{});
                module.skip_space();
                module.expect_character(right_parenthesis);

                break :blk .{
                    .bb = .{
                        .intrinsic = .{
                            .string_to_enum = .{
                                .enum_type = enum_type,
                                .string_value = string_value,
                            },
                        },
                    },
                };
            },
            .trap => blk: {
                module.skip_space();
                module.expect_character(left_parenthesis);
                module.skip_space();
                module.expect_character(right_parenthesis);
                break :blk .{
                    .bb = .{
                        .intrinsic = .trap,
                    },
                };
            },
            .truncate => blk: {
                module.skip_space();
                module.expect_character(left_parenthesis);
                module.skip_space();
                const v = module.parse_value(scope, .{});
                module.expect_character(right_parenthesis);
                break :blk .{
                    .bb = .{
                        .intrinsic = .{
                            .truncate = v,
                        },
                    },
                };
            },
            .va_start => blk: {
                module.skip_space();
                module.expect_character(left_parenthesis);
                module.skip_space();
                module.expect_character(right_parenthesis);
                break :blk .{
                    .bb = .{
                        .intrinsic = .va_start,
                    },
                };
            },
            .va_end => blk: {
                module.skip_space();
                module.expect_character(left_parenthesis);
                module.skip_space();
                const va_list = module.parse_value(scope, .{});
                module.expect_character(right_parenthesis);
                break :blk .{
                    .bb = .{
                        .intrinsic = .{
                            .va_end = va_list,
                        },
                    },
                };
            },
            .va_arg => blk: {
                module.skip_space();
                module.expect_character(left_parenthesis);
                module.skip_space();
                const va_list = module.parse_value(scope, .{});
                module.skip_space();
                module.expect_character(',');
                module.skip_space();
                const ty = module.parse_type();
                module.expect_character(right_parenthesis);
                break :blk .{
                    .bb = .{
                        .intrinsic = .{
                            .va_arg = .{
                                .list = va_list,
                                .type = ty,
                            },
                        },
                    },
                };
            },
            else => @trap(),
        };

        return value;
    }

    fn rule_before_integer(noalias module: *Module, scope: *Scope, value_builder: Value.Builder) *Value {
        _ = scope;
        const v = value_builder.token.integer.value;
        const value = module.values.add();
        value.* = .{
            .bb = .{
                .constant_integer = .{
                    .value = v,
                    .signed = false,
                },
            },
        };
        return value;
    }

    fn rule_after_binary(noalias module: *Module, scope: *Scope, value_builder: Value.Builder) *Value {
        const binary_operator_token = value_builder.token;
        const binary_operator_token_precedence = rules[@intFromEnum(binary_operator_token)].precedence;
        const left = value_builder.left orelse module.report_error();
        assert(binary_operator_token_precedence != .assignment); // TODO: this may be wrong. Assignment operator is not allowed in expressions
        const right_precedence = if (binary_operator_token_precedence == .assignment) .assignment else binary_operator_token_precedence.increment();
        const right = module.parse_precedence(scope, value_builder.with_precedence(right_precedence).with_token(.none).with_left(null));

        const binary_operation_kind: Binary.Id = switch (binary_operator_token) {
            .none => unreachable,
            .@"+" => .@"+",
            .@"-" => .@"-",
            .@"*" => .@"*",
            .@"/" => .@"/",
            .@"%" => .@"%",
            .@"&" => .@"&",
            .@"|" => .@"|",
            .@"^" => .@"^",
            .@"<<" => .@"<<",
            .@">>" => .@">>",
            .@"==" => .@"==",
            .@"!=" => .@"!=",
            .@">=" => .@">=",
            .@"<=" => .@"<=",
            .@">" => .@">",
            .@"<" => .@"<",
            .@"and" => .@"and",
            .@"and?" => .@"and?",
            .@"or" => .@"or",
            .@"or?" => .@"or?",
            else => @trap(),
        };

        const value = module.values.add();
        value.* = .{
            .bb = .{
                .binary = .{
                    .left = left,
                    .right = right,
                    .id = binary_operation_kind,
                },
            },
        };

        return value;
    }

    fn rule_before_unary(noalias module: *Module, scope: *Scope, value_builder: Value.Builder) *Value {
        assert(value_builder.left == null);
        const unary_token = value_builder.token;
        const unary_id: Unary.Id = switch (unary_token) {
            .none => unreachable,
            .@"-" => .@"-",
            .@"+" => .@"+",
            .@"&" => .@"&",
            .@"!" => .@"!",
            .@"~" => .@"~",
            else => @trap(),
        };

        const right = module.parse_precedence(scope, value_builder.with_precedence(.prefix).with_token(.none).with_kind(if (unary_id == .@"&") .left else value_builder.kind));

        const value = module.values.add();
        value.* = .{
            .bb = .{
                .unary = .{
                    .id = unary_id,
                    .value = right,
                },
            },
        };
        return value;
    }

    fn rule_after_dereference(noalias module: *Module, scope: *Scope, value_builder: Value.Builder) *Value {
        _ = scope;
        const value = module.values.add();
        value.* = .{
            .bb = .{
                .dereference = value_builder.left orelse unreachable,
            },
        };
        return value;
    }

    fn rule_before_brace(noalias module: *Module, scope: *Scope, value_builder: Value.Builder) *Value {
        assert(value_builder.left == null);

        var name_buffer: [64][]const u8 = undefined;
        var value_buffer: [64]*Value = undefined;
        var field_count: u32 = 0;
        var zero = false;

        while (true) : (field_count += 1) {
            module.skip_space();

            if (module.consume_character_if_match(right_brace)) {
                break;
            }

            if (module.consume_character_if_match('.')) {
                const name = module.parse_identifier();
                name_buffer[field_count] = name;

                module.skip_space();

                module.expect_character('=');

                module.skip_space();

                const value = module.parse_value(scope, .{});
                value_buffer[field_count] = value;
                module.skip_space();

                _ = module.consume_character_if_match(',');
            } else {
                const token = module.tokenize();
                switch (token) {
                    .value_keyword => |vkw| switch (vkw) {
                        .zero => {
                            zero = true;
                            module.skip_space();

                            if (module.consume_character_if_match(',')) {
                                module.skip_space();
                            }

                            module.expect_character(right_brace);
                            break;
                        },
                        else => module.report_error(),
                    },
                    else => module.report_error(),
                }
            }
        }

        const blob = module.arena.allocate_bytes(field_count * @sizeOf([]const u8) + field_count * @sizeOf(*Value), @max(@alignOf([]const u8), @alignOf(*Value)));
        const names = @as([*][]const u8, @alignCast(@ptrCast(blob)))[0..field_count];
        @memcpy(names, name_buffer[0..field_count]);
        const values = @as([*]*Value, @alignCast(@ptrCast(blob + (@sizeOf([]const u8) * field_count))))[0..field_count];
        @memcpy(values, value_buffer[0..field_count]);

        const value = module.values.add();
        value.* = .{
            .bb = .{
                .aggregate_initialization = .{
                    .names = names,
                    .values = values,
                    .is_constant = false,
                    .zero = zero,
                },
            },
        };
        return value;
    }

    fn rule_after_brace(noalias module: *Module, value_builder: Value.Builder) *Value {
        _ = module;
        _ = value_builder;
        @trap();
    }

    // Array initialization
    fn rule_before_bracket(noalias module: *Module, scope: *Scope, value_builder: Value.Builder) *Value {
        assert(value_builder.left == null);

        var value_buffer: [64]*Value = undefined;
        var element_count: u64 = 0;

        while (true) : (element_count += 1) {
            module.skip_space();

            if (module.consume_character_if_match(right_bracket)) {
                break;
            }
            const v = module.parse_value(scope, .{});
            value_buffer[element_count] = v;

            _ = module.consume_character_if_match(',');
        }

        const values = module.arena.allocate(*Value, element_count);
        @memcpy(values, value_buffer[0..element_count]);

        const value = module.values.add();
        value.* = .{
            .bb = .{
                .array_initialization = .{
                    .values = values,
                    .is_constant = false,
                },
            },
        };

        return value;
    }

    // Array-like subscript
    fn rule_after_bracket(noalias module: *Module, scope: *Scope, value_builder: Value.Builder) *Value {
        const left = value_builder.left orelse module.report_error();
        module.skip_space();

        const value = module.values.add();

        switch (left.bb) {
            .macro_reference => |macro| {
                if (!macro.is_generic) {
                    module.report_error();
                }

                const type_arguments = module.arena.allocate(*Type, macro.type_arguments.len);
                var type_argument_count: u64 = 0;
                const constant_values = module.arena.allocate(*Value, macro.constant_argument_values.len);
                var constant_value_count: u64 = 0;
                var constant_argument_count: u64 = 0;

                const instantiation_line = module.get_line();
                const instantiation_column = module.get_column();

                while (true) {
                    module.skip_space();

                    if (module.consume_character_if_match(right_bracket)) {
                        break;
                    }

                    const constant_argument = macro.constant_arguments[constant_argument_count];
                    constant_argument_count += 1;

                    switch (constant_argument.kind) {
                        .value => {
                            _ = &constant_value_count;
                            @trap();
                        },
                        .type => {
                            if (type_argument_count >= macro.type_arguments.len) {
                                module.report_error();
                            }

                            if (constant_argument.index != type_argument_count) {
                                module.report_error();
                            }

                            const argument_type = module.parse_type();
                            type_arguments[constant_argument.index] = argument_type;

                            type_argument_count += 1;
                        },
                    }

                    module.skip_space();

                    _ = module.consume_character_if_match(',');
                }

                module.skip_space();

                module.expect_character(left_parenthesis);

                const instantiation_arguments = module.parse_call_arguments(scope);

                value.* = .{
                    .bb = .{
                        .macro_instantiation = .{
                            .declaration = macro,
                            .function = module.current_function.?,
                            .declaration_arguments = &.{},
                            .instantiation_arguments = instantiation_arguments,
                            .constant_argument_values = constant_values,
                            .type_arguments = type_arguments,
                            .return_type = macro.return_type,
                            .block = undefined,
                            .return_alloca = undefined,
                            .return_block = undefined,
                            .function_scope = .{
                                .line = macro.scope.line,
                                .column = macro.scope.column,
                                .kind = .macro_instantiation_function,
                                .parent = scope,
                            },
                            .instantiation_line = instantiation_line,
                            .instantiation_column = instantiation_column,
                        },
                    },
                };
            },
            else => {
                left.kind = .left;

                const is_start = !(module.content[module.offset] == '.' and module.content[module.offset + 1] == '.');
                const start = if (is_start) module.parse_value(scope, .{}) else null;
                value.* = .{
                    .bb = if (module.consume_character_if_match(right_bracket)) .{
                        .array_expression = .{
                            .array_like = left,
                            .index = start orelse module.report_error(),
                        },
                    } else blk: {
                        module.expect_character('.');
                        module.expect_character('.');

                        const end = switch (module.consume_character_if_match(right_bracket)) {
                            true => null,
                            false => b: {
                                const end = module.parse_value(scope, .{});
                                module.expect_character(right_bracket);
                                break :b end;
                            },
                        };
                        break :blk .{
                            .slice_expression = .{
                                .array_like = left,
                                .start = start,
                                .end = end,
                            },
                        };
                    },
                    .kind = value_builder.kind,
                };
            },
        }

        return value;
    }

    fn rule_before_parenthesis(noalias module: *Module, scope: *Scope, value_builder: Value.Builder) *Value {
        _ = value_builder;
        module.skip_space();
        const v = module.parse_value(scope, .{});
        module.expect_character(right_parenthesis);
        return v;
    }

    fn parse_call_arguments(noalias module: *Module, scope: *Scope) []const *Value {
        var semantic_argument_count: u32 = 0;
        var semantic_argument_buffer: [64]*Value = undefined;

        while (true) : (semantic_argument_count += 1) {
            module.skip_space();

            if (module.consume_character_if_match(right_parenthesis)) {
                break;
            }

            const argument = module.parse_value(scope, .{});
            const argument_index = semantic_argument_count;
            semantic_argument_buffer[argument_index] = argument;

            module.skip_space();

            _ = module.consume_character_if_match(',');
        }

        const arguments: []const *Value = if (semantic_argument_count != 0) blk: {
            const arguments = module.arena.allocate(*Value, semantic_argument_count);
            @memcpy(arguments, semantic_argument_buffer[0..semantic_argument_count]);
            break :blk arguments;
        } else &.{};
        return arguments;
    }

    fn rule_after_call(noalias module: *Module, scope: *Scope, value_builder: Value.Builder) *Value {
        const may_be_callable = value_builder.left orelse module.report_error();
        assert(value_builder.token == .@"(");

        switch (may_be_callable.bb) {
            .macro_reference => |macro| {
                if (macro.is_generic) {
                    module.report_error();
                }

                const instantiation_line = module.get_line();
                const instantiation_column = module.get_column();

                const arguments = module.parse_call_arguments(scope);
                const value = module.values.add();

                value.* = .{
                    .bb = .{
                        .macro_instantiation = .{
                            .declaration = macro,
                            .instantiation_arguments = arguments,
                            .type_arguments = &.{},
                            .function = module.current_function.?,
                            .return_alloca = undefined,
                            .return_block = undefined,
                            .block = undefined,
                            .return_type = macro.return_type,
                            .constant_argument_values = &.{},
                            .declaration_arguments = &.{},
                            .function_scope = .{
                                .line = macro.scope.line,
                                .column = macro.scope.column,
                                .kind = .macro_instantiation_function,
                                .parent = scope,
                            },
                            .instantiation_line = instantiation_line,
                            .instantiation_column = instantiation_column,
                        },
                    },
                };

                return value;
            },
            else => {
                const arguments = module.parse_call_arguments(scope);

                const call = module.values.add();
                call.* = .{
                    .bb = .{
                        .call = .{
                            .arguments = arguments,
                            .callable = may_be_callable,
                        },
                    },
                };
                return call;
            },
        }
    }

    pub fn get_anonymous_struct_pair(module: *Module, pair: [2]*Type) *Type {
        const all_types = module.types.get_slice();
        const struct_type = for (module.pair_struct_types.get_slice()) |struct_type_index| {
            const struct_type = &all_types[struct_type_index];
            assert(struct_type.bb.structure.fields.len == 2);
            if (struct_type.bb.structure.fields[0].type == pair[0] and struct_type.bb.structure.fields[1].type == pair[1]) {
                break struct_type;
            }
        } else blk: {
            const byte_alignment = @max(pair[0].get_byte_alignment(), pair[1].get_byte_alignment());
            const byte_size = lib.align_forward_u64(pair[0].get_byte_size() + pair[1].get_byte_size(), byte_alignment);

            const fields = module.arena.allocate(Type.Struct.Field, 2);
            fields[0] = .{
                .bit_offset = 0,
                .byte_offset = 0,
                .type = pair[0],
                .name = "",
                .line = 0,
            };
            fields[1] = .{
                .bit_offset = byte_alignment * 8,
                .byte_offset = byte_alignment,
                .type = pair[1],
                .name = "",
                .line = 0,
            };
            const pair_type = module.types.append(.{
                .name = "",
                .bb = .{
                    .structure = .{
                        .bit_alignment = byte_alignment * 8,
                        .byte_alignment = byte_alignment,
                        .byte_size = byte_size,
                        .bit_size = byte_size * 8,
                        .fields = fields,
                        .line = 0,
                        .is_slice = false,
                    },
                },
            });
            const struct_type_index = pair_type - all_types.ptr;
            _ = module.pair_struct_types.append(@intCast(struct_type_index));

            break :blk pair_type;
        };
        return struct_type;
    }

    pub fn parse(module: *Module) void {
        while (true) {
            module.skip_space();

            if (module.offset == module.content.len) {
                break;
            }

            var is_export = false;
            var is_extern = false;

            const global_line = module.get_line();
            const global_column = module.get_column();

            if (module.consume_character_if_match(left_bracket)) {
                while (module.offset < module.content.len) {
                    const global_keyword_string = module.parse_identifier();

                    const global_keyword = lib.string.to_enum(GlobalKeyword, global_keyword_string) orelse module.report_error();
                    switch (global_keyword) {
                        .@"export" => is_export = true,
                        .@"extern" => is_extern = true,
                    }

                    switch (module.content[module.offset]) {
                        right_bracket => break,
                        else => module.report_error(),
                    }
                }

                module.expect_character(right_bracket);

                module.skip_space();
            }

            const global_name = module.parse_identifier();

            if (module.types.find_by_name(global_name) != null) {
                module.report_error();
            }

            if (module.globals.find_by_name(global_name) != null) {
                module.report_error();
            }

            module.skip_space();

            var global_type: ?*Type = null;
            if (module.consume_character_if_match(':')) {
                module.skip_space();

                global_type = module.parse_type();

                module.skip_space();
            }

            module.expect_character('=');

            module.skip_space();

            var global_keyword = false;
            if (is_identifier_start_ch(module.content[module.offset])) {
                const identifier_offset = module.offset;
                const global_string = module.parse_identifier();
                module.skip_space();

                if (lib.string.to_enum(GlobalKind, global_string)) |global_kind| {
                    global_keyword = true;
                    switch (global_kind) {
                        .@"fn" => {
                            var calling_convention = CallingConvention.c;
                            const function_attributes = Function.Attributes{};
                            _ = function_attributes;
                            var is_var_args = false;

                            if (module.consume_character_if_match(left_bracket)) {
                                while (module.offset < module.content.len) {
                                    const function_identifier = module.parse_identifier();

                                    const function_keyword = lib.string.to_enum(Function.Keyword, function_identifier) orelse module.report_error();

                                    module.skip_space();

                                    switch (function_keyword) {
                                        .cc => {
                                            module.expect_character(left_parenthesis);

                                            module.skip_space();

                                            const calling_convention_string = module.parse_identifier();

                                            calling_convention = lib.string.to_enum(CallingConvention, calling_convention_string) orelse module.report_error();

                                            module.skip_space();

                                            module.expect_character(right_parenthesis);
                                        },
                                    }

                                    module.skip_space();

                                    switch (module.content[module.offset]) {
                                        right_bracket => break,
                                        else => module.report_error(),
                                    }
                                }

                                module.expect_character(right_bracket);
                            }

                            module.skip_space();

                            module.expect_character(left_parenthesis);

                            var semantic_argument_count: u32 = 0;
                            var semantic_argument_type_buffer: [64]*Type = undefined;
                            var semantic_argument_name_buffer: [64][]const u8 = undefined;

                            while (module.offset < module.content.len) : (semantic_argument_count += 1) {
                                module.skip_space();

                                if (module.consume_character_if_match('.')) {
                                    module.expect_character('.');
                                    module.expect_character('.');
                                    module.skip_space();
                                    module.expect_character(right_parenthesis);
                                    is_var_args = true;
                                    break;
                                }

                                if (module.consume_character_if_match(right_parenthesis)) {
                                    break;
                                }

                                const argument_name = module.parse_identifier();
                                semantic_argument_name_buffer[semantic_argument_count] = argument_name;

                                module.skip_space();

                                module.expect_character(':');

                                module.skip_space();

                                const argument_type = module.parse_type();
                                semantic_argument_type_buffer[semantic_argument_count] = argument_type;

                                module.skip_space();

                                if (module.consume_character_if_match(',')) {
                                    module.skip_space();
                                }
                            }

                            module.skip_space();

                            const return_type = module.parse_type();
                            const argument_types: []const *Type = if (semantic_argument_count == 0) &.{} else blk: {
                                const argument_types = module.arena.allocate(*Type, semantic_argument_count);
                                @memcpy(argument_types, semantic_argument_type_buffer[0..argument_types.len]);
                                break :blk argument_types;
                            };

                            module.skip_space();

                            const is_declaration = module.consume_character_if_match(';');

                            const function_type = module.types.append(.{
                                .bb = .{
                                    .function = .{
                                        .semantic_return_type = return_type,
                                        .semantic_argument_types = argument_types,
                                        .calling_convention = calling_convention,
                                        .is_var_args = is_var_args,
                                    },
                                },
                                .name = "",
                            });
                            const storage = module.values.add();
                            storage.* = .{
                                .bb = undefined,
                                .type = module.get_pointer_type(.{
                                    .type = function_type,
                                }),
                            };

                            const global = module.globals.add();
                            global.* = .{
                                .variable = .{
                                    .storage = storage,
                                    .initial_value = undefined,
                                    .type = function_type,
                                    .name = global_name,
                                    .line = global_line,
                                    .column = global_column,
                                    .scope = &module.scope,
                                },
                                .linkage = if (is_export or is_extern) .external else .internal,
                            };
                            module.current_function = global;
                            defer module.current_function = null;

                            if (!is_declaration) {
                                storage.bb = .{
                                    .function = .{
                                        .main_block = undefined,
                                        .arguments = &.{},
                                        .attributes = .{},
                                        .scope = .{
                                            .kind = .function,
                                            .line = global_line,
                                            .column = global_column,
                                            .parent = &module.scope,
                                        },
                                    },
                                };

                                if (semantic_argument_count != 0) {
                                    const arguments = module.arena.allocate(*Local, semantic_argument_count);
                                    storage.bb.function.arguments = arguments;
                                    for (argument_types, semantic_argument_name_buffer[0..semantic_argument_count], arguments, 0..) |argument_type, argument_name, *argument, argument_index| {
                                        const result = module.locals.add();
                                        argument.* = result;
                                        result.* = .{
                                            .variable = .{
                                                .line = 0,
                                                .column = 0,
                                                .name = argument_name,
                                                .scope = &storage.bb.function.scope,
                                                .type = argument_type,
                                                .initial_value = undefined,
                                            },
                                            .argument_index = @intCast(argument_index),
                                        };
                                    }
                                }

                                storage.bb.function.main_block = module.parse_block(&storage.bb.function.scope);
                            } else {
                                storage.bb = .external_function;
                            }
                        },
                        .@"enum" => {
                            const is_implicit_type = module.content[module.offset] == left_brace;
                            const maybe_backing_type: ?*Type = switch (is_implicit_type) {
                                true => null,
                                false => module.parse_type(),
                            };

                            module.skip_space();

                            module.expect_character(left_brace);

                            var highest_value: u64 = 0;
                            var lowest_value = ~@as(u64, 0);

                            var field_buffer: [64]Enumerator.Field = undefined;
                            var field_count: u64 = 0;

                            while (true) : (field_count += 1) {
                                module.skip_space();

                                if (module.consume_character_if_match(right_brace)) {
                                    break;
                                }

                                const field_index = field_count;
                                const field_name = module.parse_identifier();
                                module.skip_space();
                                const has_explicit_value = module.consume_character_if_match('=');
                                const field_value = if (has_explicit_value) blk: {
                                    module.skip_space();
                                    const field_value = module.parse_integer_value(false);
                                    break :blk field_value;
                                } else field_index;

                                field_buffer[field_index] = .{
                                    .name = field_name,
                                    .value = field_value,
                                };

                                highest_value = @max(highest_value, field_value);
                                lowest_value = @min(lowest_value, field_value);

                                module.skip_space();
                                module.expect_character(',');
                            }

                            module.skip_space();

                            _ = module.consume_character_if_match(';');

                            const backing_type = maybe_backing_type orelse blk: {
                                const bits_needed = 64 - @clz(highest_value);
                                const int_type = module.integer_type(if (bits_needed == 0) 1 else bits_needed, false);
                                break :blk int_type;
                            };

                            if (maybe_backing_type) |bt| {
                                const bits_needed = 64 - @clz(highest_value);
                                if (bits_needed > bt.get_bit_size()) {
                                    module.report_error();
                                }
                            }

                            const fields = module.arena.allocate(Enumerator.Field, field_count);
                            @memcpy(fields, field_buffer[0..field_count]);

                            _ = module.types.append(.{
                                .bb = .{
                                    .enumerator = .{
                                        .backing_type = backing_type,
                                        .fields = fields,
                                        .implicit_backing_type = is_implicit_type,
                                        .line = global_line,
                                    },
                                },
                                .name = global_name,
                            });
                        },
                        .bits => {
                            const is_implicit_type = module.content[module.offset] == left_brace;
                            const maybe_backing_type: ?*Type = switch (is_implicit_type) {
                                true => null,
                                false => module.parse_type(),
                            };

                            module.skip_space();

                            module.expect_character(left_brace);

                            var field_buffer: [128]Type.Struct.Field = undefined;
                            var field_line_buffer: [128]u32 = undefined;
                            var field_count: u64 = 0;

                            var field_bit_offset: u64 = 0;

                            while (true) : (field_count += 1) {
                                module.skip_space();

                                if (module.consume_character_if_match(right_brace)) {
                                    break;
                                }

                                const field_line = module.get_line();
                                field_line_buffer[field_count] = field_line;

                                const field_name = module.parse_identifier();

                                module.skip_space();

                                module.expect_character(':');

                                module.skip_space();

                                const field_type = module.parse_type();

                                field_buffer[field_count] = .{
                                    .name = field_name,
                                    .type = field_type,
                                    .bit_offset = field_bit_offset,
                                    .byte_offset = 0,
                                    .line = field_line,
                                };

                                const field_bit_size = field_type.get_bit_size();

                                field_bit_offset += field_bit_size;

                                module.skip_space();

                                _ = module.consume_character_if_match(',');
                            }

                            _ = module.consume_character_if_match(';');

                            const fields = module.arena.allocate(Type.Struct.Field, field_count);
                            @memcpy(fields, field_buffer[0..field_count]);

                            // const field_lines = field_line_buffer[0..field_count];

                            const backing_type = if (maybe_backing_type) |bt| bt else module.integer_type(@intCast(@max(8, lib.next_power_of_two(field_bit_offset))), false);
                            if (backing_type.bb != .integer) {
                                module.report_error();
                            }

                            if (backing_type.get_bit_size() > 64) {
                                module.report_error();
                            }

                            _ = module.types.append(.{
                                .name = global_name,
                                .bb = .{
                                    .bits = .{
                                        .fields = fields,
                                        .backing_type = backing_type,
                                        .line = global_line,
                                        .implicit_backing_type = is_implicit_type,
                                    },
                                },
                            });
                        },
                        .@"struct" => {
                            module.skip_space();

                            module.expect_character(left_brace);

                            if (module.types.find_by_name(global_name) != null) {
                                @trap();
                            }

                            const struct_type = module.types.append(.{
                                .name = global_name,
                                .bb = .forward_declaration,
                            });

                            var field_buffer: [256]Type.Struct.Field = undefined;
                            var field_count: u64 = 0;
                            var byte_offset: u64 = 0;
                            var byte_alignment: u32 = 1;
                            var bit_alignment: u32 = 1;

                            while (true) {
                                module.skip_space();

                                if (module.consume_character_if_match(right_brace)) {
                                    break;
                                }

                                const field_line = module.get_line();
                                const field_name = module.parse_identifier();

                                module.skip_space();

                                module.expect_character(':');

                                module.skip_space();

                                const field_type = module.parse_type();

                                const field_byte_alignment = field_type.get_byte_alignment();
                                const field_bit_alignment = field_byte_alignment * 8;
                                const field_byte_size = field_type.get_byte_size();

                                const field_byte_offset = lib.align_forward_u64(byte_offset, field_byte_alignment);
                                const field_bit_offset = field_byte_offset * 8;

                                field_buffer[field_count] = .{
                                    .byte_offset = field_byte_offset,
                                    .bit_offset = field_bit_offset,
                                    .type = field_type,
                                    .name = field_name,
                                    .line = field_line,
                                };

                                byte_alignment = @max(byte_alignment, field_byte_alignment);
                                bit_alignment = @max(bit_alignment, field_bit_alignment);
                                byte_offset = field_byte_offset + field_byte_size;

                                field_count += 1;

                                module.skip_space();

                                switch (module.content[module.offset]) {
                                    ',' => module.offset += 1,
                                    else => {},
                                }
                            }

                            module.skip_space();

                            _ = module.consume_character_if_match(';');

                            const byte_size = byte_offset;

                            const fields = module.arena.allocate(Type.Struct.Field, field_count);
                            @memcpy(fields, field_buffer[0..field_count]);

                            struct_type.bb = .{
                                .structure = .{
                                    .bit_size = byte_size * 8,
                                    .byte_size = byte_size,
                                    .bit_alignment = bit_alignment,
                                    .byte_alignment = byte_alignment,
                                    .fields = fields,
                                    .is_slice = false,
                                    .line = global_line,
                                },
                            };
                        },
                        .typealias => {
                            const aliased_type = module.parse_type();
                            if (!module.consume_character_if_match(';')) {
                                module.report_error();
                            }
                            const alias_type = module.types.append(.{
                                .bb = .{
                                    .alias = .{
                                        .type = aliased_type,
                                        .line = global_line,
                                        .scope = &module.scope,
                                    },
                                },
                                .name = global_name,
                            });
                            _ = alias_type;
                        },
                        .macro => {
                            var type_argument_buffer: [64]*Type = undefined;
                            var type_argument_count: u64 = 0;

                            var constant_argument_value_buffer: [64]*Value = undefined;
                            var constant_argument_name_buffer: [64][]const u8 = undefined;
                            var constant_argument_buffer: [64]ConstantArgument = undefined;
                            var constant_argument_value_count: u64 = 0;
                            var constant_argument_count: u64 = 0;

                            const is_generic = module.consume_character_if_match(left_bracket);
                            if (is_generic) {
                                while (true) {
                                    module.skip_space();

                                    if (module.consume_character_if_match(right_bracket)) {
                                        break;
                                    }

                                    const argument_name = module.parse_identifier();

                                    module.skip_space();

                                    const has_value = module.consume_character_if_match(':');
                                    const index: u64 = if (has_value) {
                                        _ = &constant_argument_value_buffer;
                                        _ = &constant_argument_name_buffer;
                                        _ = &constant_argument_value_count;
                                        @trap();
                                    } else blk: {
                                        const ty = module.types.append(.{
                                            .bb = .unresolved,
                                            .name = argument_name,
                                        });
                                        const index = type_argument_count;
                                        type_argument_buffer[index] = ty;
                                        type_argument_count = index + 1;
                                        break :blk index;
                                    };

                                    constant_argument_buffer[constant_argument_count] = .{
                                        .kind = switch (has_value) {
                                            true => .value,
                                            false => .type,
                                        },
                                        .index = @intCast(index),
                                    };

                                    constant_argument_count += 1;
                                }

                                module.skip_space();
                            }

                            module.expect_character(left_parenthesis);

                            const type_arguments = module.arena.allocate(*Type, type_argument_count);
                            @memcpy(type_arguments, type_argument_buffer[0..type_argument_count]);

                            const constant_argument_names = module.arena.allocate([]const u8, constant_argument_value_count);
                            @memcpy(constant_argument_names, constant_argument_name_buffer[0..constant_argument_value_count]);

                            const constant_argument_values = module.arena.allocate(*Value, constant_argument_value_count);
                            @memcpy(constant_argument_values, constant_argument_value_buffer[0..constant_argument_value_count]);

                            const constant_arguments = module.arena.allocate(ConstantArgument, constant_argument_count);
                            @memcpy(constant_arguments, constant_argument_buffer[0..constant_argument_count]);

                            const macro = module.macros.add();
                            macro.* = .{
                                .arguments = &.{},
                                .argument_types = &.{},
                                .constant_argument_names = constant_argument_names,
                                .constant_argument_values = constant_argument_values,
                                .constant_arguments = constant_arguments,
                                .type_arguments = type_arguments,
                                .return_type = undefined,
                                .block = undefined,
                                .name = global_name,
                                .scope = .{
                                    .parent = &module.scope,
                                    .kind = .macro_declaration,
                                    .line = global_line,
                                    .column = global_column,
                                },
                                .is_generic = is_generic,
                            };

                            module.current_macro_declaration = macro;
                            defer module.current_macro_declaration = null;

                            var argument_buffer: [64]*Local = undefined;
                            var argument_count: u32 = 0;

                            while (true) {
                                module.skip_space();

                                if (module.consume_character_if_match(right_parenthesis)) {
                                    break;
                                }

                                const argument_line = module.get_line();
                                const argument_column = module.get_column();

                                const argument_name = module.parse_identifier();

                                module.skip_space();
                                module.expect_character(':');
                                module.skip_space();

                                const argument_type = module.parse_type();

                                const argument = module.locals.add();
                                argument.* = .{
                                    .variable = .{
                                        .initial_value = undefined,
                                        .scope = &macro.scope,
                                        .type = argument_type,
                                        .name = argument_name,
                                        .line = argument_line,
                                        .column = argument_column,
                                    },
                                    .argument_index = argument_count,
                                };
                                argument_buffer[argument_count] = argument;
                                argument_count += 1;

                                module.skip_space();
                                _ = module.consume_character_if_match(',');
                            }

                            module.skip_space();

                            const arguments = module.arena.allocate(*Local, argument_count);
                            @memcpy(arguments, argument_buffer[0..argument_count]);
                            macro.arguments = arguments;

                            const argument_types = module.arena.allocate(*Type, argument_count);
                            for (arguments, argument_types) |argument, *argument_type| {
                                argument_type.* = argument.variable.type.?;
                            }
                            macro.argument_types = argument_types;

                            const return_type = module.parse_type();
                            macro.return_type = return_type;

                            module.skip_space();

                            const block = module.parse_block(&macro.scope);
                            macro.block = block;
                        },
                        .@"union" => {
                            module.skip_space();

                            module.expect_character(left_brace);

                            if (module.types.find_by_name(global_name) != null) {
                                @trap();
                            }

                            const union_type = module.types.append(.{
                                .name = global_name,
                                .bb = .forward_declaration,
                            });

                            var field_buffer: [256]Type.Union.Field = undefined;
                            var field_count: u64 = 0;
                            var byte_size: u64 = 0;
                            var byte_alignment: u32 = 1;
                            var bit_alignment: u32 = 1;
                            var biggest_field: u32 = 0;

                            while (true) {
                                module.skip_space();

                                if (module.consume_character_if_match(right_brace)) {
                                    break;
                                }

                                const field_line = module.get_line();
                                const field_name = module.parse_identifier();

                                module.skip_space();

                                module.expect_character(':');

                                module.skip_space();

                                const field_type = module.parse_type();

                                const field_byte_alignment = field_type.get_byte_alignment();
                                const field_bit_alignment = field_byte_alignment * 8;
                                const field_byte_size = field_type.get_byte_size();

                                field_buffer[field_count] = .{
                                    .type = field_type,
                                    .name = field_name,
                                    .line = field_line,
                                };

                                biggest_field = if (byte_size > field_byte_size) @intCast(field_count) else biggest_field;
                                byte_alignment = @max(byte_alignment, field_byte_alignment);
                                bit_alignment = @max(bit_alignment, field_bit_alignment);
                                byte_size = @max(field_byte_size, byte_size);

                                field_count += 1;

                                module.skip_space();

                                switch (module.content[module.offset]) {
                                    ',' => module.offset += 1,
                                    else => {},
                                }
                            }

                            module.skip_space();

                            _ = module.consume_character_if_match(';');

                            const fields = module.arena.allocate(Type.Union.Field, field_count);
                            @memcpy(fields, field_buffer[0..field_count]);

                            union_type.bb = .{
                                .@"union" = .{
                                    .byte_size = byte_size,
                                    .byte_alignment = byte_alignment,
                                    .fields = fields,
                                    .line = global_line,
                                    .biggest_field = biggest_field,
                                },
                            };
                        },
                    }
                } else {
                    module.offset = identifier_offset;
                }
            }

            if (!global_keyword) {
                const v = module.parse_value(&module.scope, .{});
                module.skip_space();
                module.expect_character(';');

                const global = module.globals.add();
                const global_storage = module.values.add();
                global_storage.* = .{
                    .bb = .global,
                };
                global.* = .{
                    .variable = .{
                        .storage = global_storage,
                        .initial_value = v,
                        .type = global_type,
                        .scope = &module.scope,
                        .name = global_name,
                        .line = global_line,
                        .column = global_column,
                    },
                    .linkage = .internal,
                };
            }
        }
    }

    fn parse_integer_value(module: *Module, sign: bool) u64 {
        const start = module.offset;
        const integer_start_ch = module.content[start];
        assert(!is_space(integer_start_ch));
        assert(is_decimal_ch(integer_start_ch));

        const absolute_value: u64 = switch (integer_start_ch) {
            '0' => blk: {
                module.offset += 1;

                const next_ch = module.content[module.offset];
                break :blk switch (sign) {
                    false => switch (next_ch) {
                        'x' => b: {
                            module.offset += 1;
                            break :b module.parse_hexadecimal();
                        },
                        'd' => b: {
                            module.offset += 1;
                            break :b module.parse_decimal();
                        },
                        'o' => b: {
                            module.offset += 1;
                            break :b module.parse_octal();
                        },
                        'b' => b: {
                            module.offset += 1;
                            break :b module.parse_binary();
                        },
                        '0'...'9' => {
                            module.report_error();
                        },
                        // Zero literal
                        else => 0,
                    },
                    true => switch (next_ch) {
                        'x', 'o', 'b', '0' => module.report_error(),
                        '1'...'9' => module.parse_decimal(),
                        else => unreachable,
                    },
                };
            },
            '1'...'9' => module.parse_decimal(),
            else => unreachable,
        };

        return absolute_value;
    }

    fn initialize_llvm(module: *Module) void {
        llvm.default_initialize();
        const context = llvm.Context.create();
        const m = context.create_module(module.name);
        const di_builder = if (module.has_debug_info) m.create_di_builder() else undefined;

        var compile_unit: *llvm.DI.CompileUnit = undefined;

        const file = if (module.has_debug_info) blk: {
            const index = lib.string.last_character(module.path, '/') orelse lib.os.abort();
            const directory = module.path[0..index];
            const file_name = module.path[index + 1 ..];
            const file = di_builder.create_file(file_name, directory);
            compile_unit = di_builder.create_compile_unit(file, module.build_mode.is_optimized());
            module.scope.llvm = compile_unit.to_scope();
            break :blk file;
        } else undefined;

        module.llvm = LLVM{
            .context = context,
            .module = m,
            .builder = context.create_builder(),
            .di_builder = di_builder,
            .file = file,
            .compile_unit = compile_unit,
            .void_type = context.get_void_type(),
            .pointer_type = context.get_pointer_type(0).to_type(),
            .intrinsic_table = .{
                .trap = llvm.lookup_intrinsic_id("llvm.trap"),
                .va_start = llvm.lookup_intrinsic_id("llvm.va_start"),
                .va_end = llvm.lookup_intrinsic_id("llvm.va_end"),
                .va_copy = llvm.lookup_intrinsic_id("llvm.va_copy"),
            },
            .debug_tag = 0,
        };
    }

    pub fn emit_block(module: *Module, block: *llvm.BasicBlock) void {
        const maybe_current_block = module.llvm.builder.get_insert_block();

        var emit_branch = false;
        if (maybe_current_block) |current_block| {
            emit_branch = current_block.get_terminator() == null;
        }

        if (emit_branch) {
            _ = module.llvm.builder.create_branch(block);
        }

        if (maybe_current_block != null and maybe_current_block.?.get_parent() != null) {
            module.llvm.builder.insert_basic_block_after_insert_block(block);
        } else {
            module.current_function.?.variable.storage.?.llvm.?.to_function().append_basic_block(block);
        }

        module.llvm.builder.position_at_end(block);
    }

    pub fn emit_va_arg(module: *Module, value: *Value, left_llvm: ?*llvm.Value, left_type: ?*Type) *llvm.Value {
        switch (value.bb) {
            .intrinsic => |intrinsic| switch (intrinsic) {
                .va_arg => |va_arg| {
                    const raw_va_list_type = module.get_va_list_type();
                    module.emit_value(va_arg.list, .memory);
                    const uint64 = module.integer_type(64, false);
                    uint64.resolve(module);
                    const va_list = module.llvm.builder.create_gep(.{
                        .type = raw_va_list_type.llvm.memory.?,
                        .aggregate = va_arg.list.llvm.?,
                        .indices = &([1]*llvm.Value{uint64.llvm.memory.?.to_integer().get_constant(0, @intFromBool(false)).to_value()} ** 2),
                    });
                    const r = Abi.SystemV.classify_argument_type(module, va_arg.type, .{
                        .available_gpr = 0,
                        .is_named_argument = false,
                        .is_reg_call = false,
                    });
                    const abi = r[0];
                    const needed_register_count = r[1];
                    const abi_kind = abi.flags.kind;
                    assert(abi_kind != .ignore);

                    const va_list_struct = raw_va_list_type.bb.array.element_type;
                    const llvm_address = switch (needed_register_count.gpr == 0 and needed_register_count.sse == 0) {
                        true => Abi.SystemV.emit_va_arg_from_memory(module, va_list, va_list_struct, va_arg.type),
                        false => c: {
                            const va_list_struct_llvm = va_list_struct.llvm.memory.?.to_struct();
                            const gpr_offset_pointer = if (needed_register_count.gpr != 0) module.llvm.builder.create_struct_gep(va_list_struct_llvm, va_list, 0) else undefined;
                            const gpr_offset = if (needed_register_count.gpr != 0) module.create_load(.{ .type = va_list_struct.bb.structure.fields[0].type, .value = gpr_offset_pointer, .alignment = 16 }) else undefined;
                            const raw_in_regs = 48 - needed_register_count.gpr * 8;
                            const int32 = module.integer_type(32, false);
                            const int32_llvm = int32.llvm.abi.?.to_integer();
                            var in_regs = if (needed_register_count.gpr != 0) int32_llvm.get_constant(raw_in_regs, @intFromBool(false)).to_value() else @trap();
                            in_regs = if (needed_register_count.gpr != 0) module.llvm.builder.create_integer_compare(.ule, gpr_offset, in_regs) else in_regs;

                            const fp_offset_pointer = if (needed_register_count.sse != 0) module.llvm.builder.create_struct_gep(va_list_struct_llvm, va_list, 1) else undefined;
                            const fp_offset = if (needed_register_count.sse != 0) module.create_load(.{ .type = va_list_struct.bb.structure.fields[1].type, .value = fp_offset_pointer }) else undefined;
                            const raw_fits_in_fp = 176 - needed_register_count.sse * 16;
                            var fits_in_fp = if (needed_register_count.sse != 0) int32_llvm.get_constant(raw_fits_in_fp, @intFromBool(false)).to_value() else undefined;
                            fits_in_fp = if (needed_register_count.sse != 0) module.llvm.builder.create_integer_compare(.ule, fp_offset, fits_in_fp) else undefined;
                            in_regs = if (needed_register_count.sse != 0 and needed_register_count.gpr != 0) @trap() else in_regs;

                            const in_reg_block = module.llvm.context.create_basic_block("va_arg.in_reg", null);
                            const in_mem_block = module.llvm.context.create_basic_block("va_arg.in_mem", null);
                            const end_block = module.llvm.context.create_basic_block("va_arg.end", null);
                            _ = module.llvm.builder.create_conditional_branch(in_regs, in_reg_block, in_mem_block);
                            module.emit_block(in_reg_block);

                            const reg_save_area = module.create_load(.{ .type = va_list_struct.bb.structure.fields[3].type, .value = module.llvm.builder.create_struct_gep(va_list_struct_llvm, va_list, 3), .alignment = 16 });

                            const register_address = if (needed_register_count.gpr != 0 and needed_register_count.sse != 0) {
                                @trap();
                            } else if (needed_register_count.gpr != 0) b: {
                                const t = va_list_struct.bb.structure.fields[3].type.bb.pointer.type;
                                t.resolve(module);
                                const register_address = module.llvm.builder.create_gep(.{
                                    .type = t.llvm.abi.?,
                                    .aggregate = reg_save_area,
                                    .indices = &.{gpr_offset},
                                    .inbounds = false,
                                });
                                if (va_arg.type.get_byte_alignment() > 8) {
                                    @trap();
                                }
                                break :b register_address;
                            } else if (needed_register_count.sse == 1) {
                                @trap();
                            } else {
                                assert(needed_register_count.sse == 2);
                                @trap();
                            };

                            if (needed_register_count.gpr != 0) {
                                const raw_offset = needed_register_count.gpr * 8;
                                const new_offset = module.llvm.builder.create_add(gpr_offset, int32_llvm.get_constant(raw_offset, @intFromBool(false)).to_value());
                                _ = module.create_store(.{ .destination_value = gpr_offset_pointer, .source_value = new_offset, .type = int32, .alignment = 16 });
                            }

                            if (needed_register_count.sse != 0) {
                                @trap();
                            }

                            _ = module.llvm.builder.create_branch(end_block);

                            module.emit_block(in_mem_block);

                            const memory_address = Abi.SystemV.emit_va_arg_from_memory(module, va_list, va_list_struct, va_arg.type);
                            module.emit_block(end_block);

                            const values = &.{ register_address, memory_address };
                            const blocks = &.{ in_reg_block, in_mem_block };
                            const phi = module.llvm.builder.create_phi(module.llvm.pointer_type);
                            phi.add_incoming(values, blocks);
                            break :c phi.to_value();
                        },
                    };
                    const result = switch (va_arg.type.get_evaluation_kind()) {
                        .scalar => module.create_load(.{ .type = va_arg.type, .value = llvm_address }),
                        .aggregate => if (left_llvm) |l| b: {
                            uint64.resolve(module);
                            _ = module.llvm.builder.create_memcpy(l, left_type.?.bb.pointer.alignment.?, llvm_address, va_arg.type.get_byte_alignment(), uint64.llvm.abi.?.to_integer().get_constant(va_arg.type.get_byte_size(), 0).to_value());
                            break :b l;
                        } else llvm_address,
                        .complex => @trap(),
                    };
                    return result;
                },
                else => unreachable,
            },
            else => unreachable,
        }
    }

    pub fn emit_call(module: *Module, value: *Value, left_llvm: ?*llvm.Value, left_type: ?*Type) *llvm.Value {
        switch (value.bb) {
            .call => |call| {
                const raw_function_type = call.function_type;
                // TODO: improve this code, which works for now
                const llvm_callable = switch (call.callable.bb) {
                    .variable_reference => |variable| switch (variable.type.?.bb) {
                        .pointer => |pointer| switch (pointer.type.bb) {
                            .function => module.create_load(.{ .type = module.get_pointer_type(.{ .type = raw_function_type }), .value = variable.storage.?.llvm.? }),
                            else => @trap(),
                        },
                        .function => variable.storage.?.llvm.?,
                        else => @trap(),
                    },
                    else => @trap(),
                };

                const function_type = &raw_function_type.bb.function;
                const calling_convention = function_type.calling_convention;
                const llvm_calling_convention = calling_convention.to_llvm();
                var llvm_abi_argument_value_buffer: [64]*llvm.Value = undefined;
                var llvm_abi_argument_type_buffer: [64]*llvm.Type = undefined;
                var abi_argument_type_buffer: [64]*Type = undefined;
                var argument_type_abi_buffer: [64]Abi.Information = undefined;

                var abi_argument_count: u16 = 0;
                const function_semantic_argument_count = function_type.argument_abis.len;

                // TODO
                const uses_in_alloca = false;
                if (uses_in_alloca) {
                    @trap();
                }

                const llvm_indirect_return_value: *llvm.Value = switch (function_type.return_abi.flags.kind) {
                    .indirect, .in_alloca, .coerce_and_expand => blk: {
                        // TODO: handle edge cases:
                        // - virtual function pointer thunk
                        // - return alloca already exists
                        const semantic_return_type = function_type.return_abi.semantic_type;
                        const pointer = if (left_llvm) |l| b: {
                            assert(left_type.?.bb.pointer.type == semantic_return_type);
                            break :b l;
                        } else b: {
                            const temporal_alloca = module.create_alloca(.{ .type = semantic_return_type, .name = "tmp" });
                            break :b temporal_alloca;
                        };
                        const has_sret = function_type.return_abi.flags.kind == .indirect;
                        if (has_sret) {
                            llvm_abi_argument_value_buffer[abi_argument_count] = pointer;
                            abi_argument_type_buffer[abi_argument_count] = module.void_type;
                            llvm_abi_argument_type_buffer[abi_argument_count] = module.void_type.llvm.abi.?;
                            abi_argument_count += 1;
                            break :blk pointer;
                        } else if (function_type.return_abi.flags.kind == .in_alloca) {
                            @trap();
                        } else {
                            @trap();
                        }
                    },
                    else => undefined,
                };

                var available_registers = function_type.available_registers;

                for (call.arguments, 0..) |semantic_argument_value, semantic_argument_index| {
                    const is_named_argument = semantic_argument_index < function_semantic_argument_count;
                    const semantic_argument_type = switch (is_named_argument) {
                        true => function_type.argument_abis[semantic_argument_index].semantic_type,
                        false => semantic_argument_value.type.?,
                    };
                    semantic_argument_type.resolve(module);

                    const argument_abi = if (is_named_argument) function_type.argument_abis[semantic_argument_index] else Abi.SystemV.classify_argument(module, &available_registers, &llvm_abi_argument_type_buffer, &abi_argument_type_buffer, .{
                        .type = semantic_argument_type,
                        .abi_start = abi_argument_count,
                        .is_named_argument = true,
                    });
                    if (semantic_argument_type.get_byte_size() > 60 and argument_abi.flags.kind != .indirect) {
                        @trap();
                    }
                    if (is_named_argument) {
                        for (llvm_abi_argument_type_buffer[argument_abi.abi_start..][0..argument_abi.abi_count], abi_argument_type_buffer[argument_abi.abi_start..][0..argument_abi.abi_count], function_type.abi_argument_types[argument_abi.abi_start..][0..argument_abi.abi_count]) |*llvm_t, *t, abi_argument_type| {
                            llvm_t.* = abi_argument_type.llvm.abi.?;
                            t.* = abi_argument_type;
                        }
                    }
                    argument_type_abi_buffer[semantic_argument_index] = argument_abi;

                    if (argument_abi.padding.type) |padding_type| {
                        _ = padding_type;
                        @trap();
                    }
                    assert(abi_argument_count == argument_abi.abi_start);
                    const argument_abi_kind = argument_abi.flags.kind;
                    switch (argument_abi_kind) {
                        .direct, .extend => {
                            const coerce_to_type = argument_abi.get_coerce_to_type();
                            coerce_to_type.resolve(module);
                            if (coerce_to_type.bb != .structure and semantic_argument_type.is_abi_equal(coerce_to_type, module) and argument_abi.attributes.direct.offset == 0) {
                                module.emit_value(semantic_argument_value, .memory);
                                const v = switch (argument_abi.semantic_type.get_evaluation_kind()) {
                                    .aggregate => @trap(),
                                    else => semantic_argument_value,
                                };

                                if (!coerce_to_type.is_abi_equal(v.type.?, module)) {
                                    switch (v.type.?) {
                                        else => @trap(),
                                    }
                                }

                                // TODO: bitcast
                                // if (argument_abi.abi_start < function_type.argument_type_abis.len and v.type.llvm.handle != abi_arguments

                                // TODO: fill types
                                llvm_abi_argument_value_buffer[abi_argument_count] = v.llvm.?;
                                abi_argument_count += 1;
                            } else {
                                if (coerce_to_type.bb == .structure and argument_abi.flags.kind == .direct and !argument_abi.flags.can_be_flattened) {
                                    @trap();
                                }

                                const evaluation_kind = semantic_argument_type.get_evaluation_kind();
                                var src = switch (evaluation_kind) {
                                    .aggregate => semantic_argument_value,
                                    .scalar => {
                                        @trap();
                                    },
                                    .complex => @trap(),
                                };

                                src = switch (argument_abi.attributes.direct.offset > 0) {
                                    true => @trap(),
                                    false => src,
                                };

                                if (coerce_to_type.bb == .structure and argument_abi.flags.kind == .direct and argument_abi.flags.can_be_flattened) {
                                    const source_type_size_is_scalable = false; // TODO
                                    if (source_type_size_is_scalable) {
                                        @trap();
                                    } else {
                                        if (src.kind == .right) {
                                            if (src.bb == .variable_reference) {
                                                src.type = null;
                                                src.kind = .left;
                                                module.analyze_value_type(src, .{});
                                            }
                                        }
                                        module.emit_value(semantic_argument_value, .memory);
                                        const destination_size = coerce_to_type.get_byte_size();
                                        const source_size = argument_abi.semantic_type.get_byte_size();

                                        const alignment = argument_abi.semantic_type.get_byte_alignment();
                                        const source = switch (source_size < destination_size) {
                                            true => blk: {
                                                const temporal_alloca = module.create_alloca(.{ .type = coerce_to_type, .name = "coerce", .alignment = alignment });
                                                const destination = temporal_alloca;
                                                const source = semantic_argument_value.llvm.?;
                                                const uint64 = module.integer_type(64, false);
                                                uint64.resolve(module);
                                                _ = module.llvm.builder.create_memcpy(destination, alignment, source, alignment, uint64.llvm.abi.?.to_integer().get_constant(semantic_argument_type.get_byte_size(), @intFromBool(false)).to_value());
                                                break :blk temporal_alloca;
                                            },
                                            false => src.llvm.?,
                                        };

                                        // TODO:
                                        assert(argument_abi.attributes.direct.offset == 0);

                                        switch (semantic_argument_value.kind) {
                                            .left => {
                                                for (coerce_to_type.bb.structure.fields, 0..) |field, field_index| {
                                                    const gep = module.llvm.builder.create_struct_gep(coerce_to_type.llvm.memory.?.to_struct(), source, @intCast(field_index));
                                                    const maybe_undef = false;
                                                    if (maybe_undef) {
                                                        @trap();
                                                    }
                                                    const load = module.create_load(.{ .value = gep, .type = field.type, .alignment = alignment });

                                                    llvm_abi_argument_value_buffer[abi_argument_count] = load;
                                                    abi_argument_count += 1;
                                                }
                                            },
                                            .right => {
                                                if (coerce_to_type.is_abi_equal(semantic_argument_type, module)) {
                                                    for (0..coerce_to_type.bb.structure.fields.len) |field_index| {
                                                        const extract_value = module.llvm.builder.create_extract_value(source, @intCast(field_index));
                                                        llvm_abi_argument_value_buffer[abi_argument_count] = extract_value;
                                                        abi_argument_count += 1;
                                                    }
                                                } else {
                                                    switch (semantic_argument_value.bb) {
                                                        .aggregate_initialization => |aggregate_initialization| switch (aggregate_initialization.is_constant) {
                                                            true => {
                                                                const global_variable = module.llvm.module.create_global_variable(.{
                                                                    .linkage = .InternalLinkage,
                                                                    .name = "conststruct", // TODO: format properly
                                                                    .initial_value = semantic_argument_value.llvm.?.to_constant(),
                                                                    .type = semantic_argument_type.llvm.abi.?,
                                                                });
                                                                global_variable.set_unnamed_address(.global);
                                                                global_variable.to_value().set_alignment(semantic_argument_type.get_byte_alignment());
                                                                for (coerce_to_type.bb.structure.fields, 0..) |field, field_index| {
                                                                    const gep = module.llvm.builder.create_struct_gep(coerce_to_type.llvm.abi.?.to_struct(), global_variable.to_value(), @intCast(field_index));
                                                                    const maybe_undef = false;
                                                                    if (maybe_undef) {
                                                                        @trap();
                                                                    }
                                                                    const load = module.create_load(.{ .value = gep, .type = field.type, .alignment = alignment });

                                                                    llvm_abi_argument_value_buffer[abi_argument_count] = load;
                                                                    abi_argument_count += 1;
                                                                }
                                                            },
                                                            false => @trap(),
                                                        },
                                                        else => @trap(),
                                                    }
                                                }
                                            },
                                        }
                                    }
                                } else {
                                    assert(argument_abi.abi_count == 1);
                                    // TODO: handmade change
                                    if (src.type.?.bb != .pointer) {
                                        assert(src.kind == .right);
                                        assert(src.type.?.bb == .structure);
                                        src.type = null;
                                        src.kind = .left;
                                        module.analyze_value_type(src, .{});
                                    }
                                    module.emit_value(src, .memory);

                                    assert(src.type.?.bb == .pointer);
                                    const source_type = src.type.?.bb.pointer.type;
                                    assert(source_type == argument_abi.semantic_type);
                                    const destination_type = argument_abi.get_coerce_to_type();
                                    const load = module.create_coerced_load(src.llvm.?, source_type, destination_type);

                                    const is_cmse_ns_call = false;
                                    if (is_cmse_ns_call) {
                                        @trap();
                                    }
                                    const maybe_undef = false;
                                    if (maybe_undef) {
                                        @trap();
                                    }

                                    llvm_abi_argument_value_buffer[abi_argument_count] = load;
                                    abi_argument_count += 1;
                                }
                            }
                        },
                        .indirect, .indirect_aliased => indirect: {
                            if (semantic_argument_type.get_evaluation_kind() == .aggregate) {
                                const same_address_space = true;
                                assert(argument_abi.abi_start >= function_type.abi_argument_types.len or same_address_space);

                                // TODO: handmade code, may contain bugs
                                assert(argument_abi.abi_count == 1);
                                const abi_argument_type = abi_argument_type_buffer[argument_abi.abi_start];

                                if (abi_argument_type == semantic_argument_value.type) {
                                    @trap();
                                } else if (abi_argument_type.bb == .pointer and abi_argument_type.bb.pointer.type == semantic_argument_value.type) switch (semantic_argument_value.is_constant()) {
                                    true => {
                                        module.emit_value(semantic_argument_value, .memory);
                                        const global_variable = module.llvm.module.create_global_variable(.{
                                            .linkage = .InternalLinkage,
                                            .name = "conststruct", // TODO: format properly
                                            .initial_value = semantic_argument_value.llvm.?.to_constant(),
                                            .type = semantic_argument_type.llvm.abi.?,
                                        });
                                        global_variable.set_unnamed_address(.global);
                                        const alignment = semantic_argument_type.get_byte_alignment();
                                        global_variable.to_value().set_alignment(alignment);
                                        llvm_abi_argument_value_buffer[abi_argument_count] = global_variable.to_value();
                                        abi_argument_count += 1;
                                        break :indirect;
                                    },
                                    false => switch (semantic_argument_value.bb) {
                                        .variable_reference => {
                                            const pointer_type = module.get_pointer_type(.{ .type = semantic_argument_value.type.? });
                                            semantic_argument_value.type = null;
                                            semantic_argument_value.kind = .left;
                                            module.analyze(semantic_argument_value, .{ .type = pointer_type }, .memory);
                                            llvm_abi_argument_value_buffer[abi_argument_count] = semantic_argument_value.llvm.?;
                                            abi_argument_count += 1;
                                            break :indirect;
                                        },
                                        else => {
                                            assert(abi_argument_type.bb.pointer.type == semantic_argument_value.type);
                                            const alloca = module.create_alloca(.{
                                                .type = semantic_argument_value.type.?,
                                            });
                                            const pointer_type = module.get_pointer_type(.{ .type = semantic_argument_value.type.? });
                                            module.emit_assignment(alloca, pointer_type, semantic_argument_value);
                                            llvm_abi_argument_value_buffer[abi_argument_count] = alloca;
                                            abi_argument_count += 1;
                                            break :indirect;
                                        },
                                    },
                                } else {
                                    @trap();
                                }

                                // const indirect_alignment = argument_abi.attributes.indirect.alignment;
                                // const address_alignment = semantic_argument_type.get_byte_alignment();
                                // const get_or_enforce_known_alignment = indirect_alignment;
                                // llvm::getOrEnforceKnownAlignment(Addr.emitRawPointer(*this),
                                //      Align.getAsAlign(),
                                //      *TD) < Align.getAsAlign()) {

                                // TODO
                                // const need_copy = switch (address_alignment < indirect_alignment and get_or_enforce_known_alignment < indirect_alignment) {
                                //     true => @trap(),
                                //     false => b: {
                                //         const is_lvalue = !(semantic_argument_value.type.?.bb == .pointer and semantic_argument_type == semantic_argument_value.type.?.bb.pointer.type);
                                //         if (is_lvalue) {
                                //             var need_copy = false;
                                //             const is_by_val_or_by_ref = argument_abi.flags.kind == .indirect_aliased or argument_abi.flags.indirect_by_value;
                                //
                                //             const lv_alignment = semantic_argument_value.type.?.get_byte_alignment();
                                //             const arg_type_alignment = argument_abi.semantic_type.get_byte_alignment();
                                //             if (!is_by_val_or_by_ref or lv_alignment < arg_type_alignment) {
                                //                 need_copy = true;
                                //             }
                                //
                                //             break :b need_copy;
                                //         } else {
                                //             break :b false;
                                //         }
                                //     },
                                // };
                                //
                                // if (!need_copy) {
                                //     const abi_argument_type = abi_argument_type_buffer[argument_abi.abi_start];
                                //     assert(abi_argument_type == semantic_argument_value.type);
                                //     llvm_abi_argument_value_buffer[abi_argument_count] = semantic_argument_value.llvm.?;
                                //     abi_argument_count += 1;
                                //     break :indirect;
                                // }
                            }

                            @trap();
                        },
                        .ignore => unreachable,
                        else => @trap(),
                    }

                    assert(abi_argument_count == argument_abi.abi_start + argument_abi.abi_count);
                }

                if (function_type.is_var_args) {
                    assert(abi_argument_count >= function_type.abi_argument_types.len);
                } else {
                    // TODO
                    assert(abi_argument_count == function_type.abi_argument_types.len);
                }

                const llvm_abi_argument_values = llvm_abi_argument_value_buffer[0..abi_argument_count];
                const llvm_call = module.llvm.builder.create_call(raw_function_type.llvm.abi.?.to_function(), llvm_callable, llvm_abi_argument_values);

                const attribute_list = module.build_attribute_list(.{
                    .return_type_abi = function_type.return_abi,
                    .abi_return_type = function_type.abi_return_type,
                    .abi_argument_types = abi_argument_type_buffer[0..abi_argument_count],
                    .argument_type_abis = argument_type_abi_buffer[0..call.arguments.len],
                    .attributes = .{},
                    .call_site = true,
                });

                const call_base = llvm_call.to_instruction().to_call_base();
                call_base.set_calling_convention(llvm_calling_convention);
                call_base.set_attributes(attribute_list);

                const return_type_abi = &function_type.return_abi;
                const return_abi_kind = return_type_abi.flags.kind;

                switch (return_abi_kind) {
                    .ignore => {
                        assert(return_type_abi.semantic_type == module.noreturn_type or return_type_abi.semantic_type == module.void_type);
                        return llvm_call;
                    },
                    .direct, .extend => {
                        const coerce_to_type = return_type_abi.get_coerce_to_type();

                        if (return_type_abi.semantic_type.is_abi_equal(coerce_to_type, module) and return_type_abi.attributes.direct.offset == 0) {
                            const coerce_to_type_kind = coerce_to_type.get_evaluation_kind();
                            switch (coerce_to_type_kind) {
                                .aggregate => {},
                                .complex => @trap(),
                                .scalar => {
                                    return llvm_call;
                                    // TODO: maybe a bug?
                                    // const v = module.values.add();
                                    // v.* = .{
                                    //     .llvm = llvm_call,
                                    //     .bb = .instruction,
                                    //     .type = return_type_abi.semantic_type,
                                    //     .lvalue = false,
                                    //     .dereference_to_assign = false,
                                    // };
                                    // break :c v;
                                },
                            }
                        }

                        // TODO: if
                        const fixed_vector_type = false;
                        if (fixed_vector_type) {
                            @trap();
                        }

                        const coerce_alloca = if (left_llvm) |l| b: {
                            assert(left_type.?.bb.pointer.type == return_type_abi.semantic_type);
                            break :b l;
                        } else module.create_alloca(.{ .type = return_type_abi.semantic_type, .name = "coerce" });
                        const destination_pointer = switch (return_type_abi.attributes.direct.offset == 0) {
                            true => coerce_alloca,
                            false => @trap(),
                        };

                        var destination_type = return_type_abi.semantic_type;
                        if (return_type_abi.semantic_type.bb.structure.fields.len > 0) {
                            // CreateCoercedStore(
                            // CI, StorePtr,
                            // llvm::TypeSize::getFixed(DestSize - RetAI.getDirectOffset()),
                            // DestIsVolatile);

                            const source_value = llvm_call;
                            const source_type = function_type.abi_return_type;
                            // const source_size = source_type.get_byte_size();
                            const destination_size = destination_type.get_byte_size();
                            // const destination_alignment = destination_type.get_byte_alignment();
                            const left_destination_size = destination_size - return_type_abi.attributes.direct.offset;

                            const is_destination_volatile = false; // TODO
                            module.create_coerced_store(source_value, source_type, destination_pointer, destination_type, left_destination_size, is_destination_volatile);
                        } else {
                            @trap();
                        }

                        if (left_llvm) |l| {
                            assert(destination_pointer == l);
                            return destination_pointer;
                        } else return switch (value.kind) {
                            .left => @trap(),
                            .right => module.create_load(.{ .type = destination_type, .value = destination_pointer }),
                        };
                    },
                    .indirect => {
                        return llvm_indirect_return_value;
                        // TODO
                        // const v = module.values.add();
                        // v.* = .{
                        //     .llvm = llvm_indirect_return_value,
                        //     .bb = .instruction,
                        //     .type = module.get_pointer_type(.{ .type = return_type_abi.semantic_type }),
                        //     .lvalue = true,
                        //     .dereference_to_assign = true,
                        // };
                        // break :c v;
                    },
                    else => @trap(),
                }
            },
            else => unreachable,
        }
    }

    pub fn emit(module: *Module) void {
        module.initialize_llvm();

        for (module.globals.get_slice()) |*global| {
            switch (global.variable.storage.?.bb) {
                .function, .external_function => {
                    const function_type = &global.variable.storage.?.type.?.bb.pointer.type.bb.function;
                    function_type.argument_abis = module.arena.allocate(Abi.Information, function_type.semantic_argument_types.len);

                    const resolved_calling_convention = function_type.calling_convention.resolve(module.target);
                    const is_reg_call = resolved_calling_convention == .system_v and false; // TODO: regcall calling_convention

                    var llvm_abi_argument_type_buffer: [64]*llvm.Type = undefined;
                    var abi_argument_type_buffer: [64]*Type = undefined;
                    var abi_argument_type_count: u16 = 0;

                    switch (resolved_calling_convention) {
                        .system_v => {
                            function_type.available_registers = switch (resolved_calling_convention) {
                                .system_v => .{
                                    .system_v = .{
                                        .gpr = if (is_reg_call) 11 else 6,
                                        .sse = if (is_reg_call) 16 else 8,
                                    },
                                },
                                .win64 => @trap(),
                            };

                            function_type.return_abi = Abi.SystemV.classify_return_type(module, function_type.semantic_return_type);
                            const return_abi_kind = function_type.return_abi.flags.kind;
                            function_type.abi_return_type = switch (return_abi_kind) {
                                .direct, .extend => function_type.return_abi.coerce_to_type.?,
                                .ignore, .indirect => module.void_type,
                                else => |t| @panic(@tagName(t)),
                            };
                            function_type.abi_return_type.resolve(module);

                            if (function_type.return_abi.flags.kind == .indirect) {
                                assert(!function_type.return_abi.flags.sret_after_this);
                                function_type.available_registers.system_v.gpr -= 1;
                                const indirect_type = module.get_pointer_type(.{ .type = function_type.return_abi.semantic_type });
                                indirect_type.resolve(module);
                                abi_argument_type_buffer[abi_argument_type_count] = indirect_type;
                                llvm_abi_argument_type_buffer[abi_argument_type_count] = indirect_type.llvm.abi.?;
                                abi_argument_type_count += 1;
                            }

                            const required_arguments = function_type.semantic_argument_types.len;

                            for (function_type.argument_abis, function_type.semantic_argument_types, 0..) |*argument_type_abi, semantic_argument_type, semantic_argument_index| {
                                const is_named_argument = semantic_argument_index < required_arguments;
                                assert(is_named_argument);

                                argument_type_abi.* = Abi.SystemV.classify_argument(module, &function_type.available_registers, &llvm_abi_argument_type_buffer, &abi_argument_type_buffer, .{
                                    .type = semantic_argument_type,
                                    .abi_start = abi_argument_type_count,
                                    .is_named_argument = is_named_argument,
                                });

                                abi_argument_type_count += argument_type_abi.abi_count;
                            }

                            function_type.abi_argument_types = module.arena.allocate(*Type, abi_argument_type_count);
                            @memcpy(function_type.abi_argument_types, abi_argument_type_buffer[0..function_type.abi_argument_types.len]);
                        },
                        .win64 => {
                            @trap();
                        },
                    }

                    const llvm_abi_argument_types = llvm_abi_argument_type_buffer[0..abi_argument_type_count];
                    const llvm_function_type = llvm.Type.Function.get(function_type.abi_return_type.llvm.abi.?, llvm_abi_argument_types, function_type.is_var_args);

                    const subroutine_type_flags = llvm.DI.Flags{};
                    const subroutine_type = if (module.has_debug_info) blk: {
                        var debug_argument_type_buffer: [64 + 1]*llvm.DI.Type = undefined;
                        const semantic_debug_argument_types = debug_argument_type_buffer[0 .. function_type.argument_abis.len + 1 + @intFromBool(function_type.is_var_args)];
                        semantic_debug_argument_types[0] = function_type.return_abi.semantic_type.llvm.debug.?;

                        for (function_type.argument_abis, semantic_debug_argument_types[1..][0..function_type.argument_abis.len]) |argument_abi, *debug_argument_type| {
                            debug_argument_type.* = argument_abi.semantic_type.llvm.debug.?;
                        }

                        if (function_type.is_var_args) {
                            semantic_debug_argument_types[function_type.argument_abis.len + 1] = module.void_type.llvm.debug.?;
                        }

                        const subroutine_type = module.llvm.di_builder.create_subroutine_type(module.llvm.file, semantic_debug_argument_types, subroutine_type_flags);
                        break :blk subroutine_type;
                    } else undefined;
                    global.variable.storage.?.type.?.bb.pointer.type.llvm.abi = llvm_function_type.to_type();
                    global.variable.storage.?.type.?.bb.pointer.type.llvm.debug = subroutine_type.to_type();

                    const llvm_function_value = module.llvm.module.create_function(.{
                        .name = global.variable.name,
                        // TODO: make it better
                        .linkage = switch (global.linkage) {
                            .external => .ExternalLinkage,
                            .internal => .InternalLinkage,
                        },
                        .type = global.variable.storage.?.type.?.bb.pointer.type.llvm.abi.?.to_function(),
                    });

                    global.variable.storage.?.llvm = llvm_function_value.to_value();

                    llvm_function_value.set_calling_convention(function_type.calling_convention.to_llvm());

                    const attribute_list = module.build_attribute_list(.{
                        .abi_return_type = function_type.abi_return_type,
                        .abi_argument_types = function_type.abi_argument_types,
                        .argument_type_abis = function_type.argument_abis,
                        .return_type_abi = function_type.return_abi,
                        .attributes = switch (global.variable.storage.?.bb) {
                            .function => |function| function.attributes,
                            else => .{},
                        },
                        .call_site = false,
                    });

                    llvm_function_value.set_attributes(attribute_list);

                    const function_scope: *llvm.DI.Scope = if (module.has_debug_info) blk: {
                        const scope_line: u32 = @intCast(module.line_offset + 1);
                        const local_to_unit = switch (global.linkage) {
                            .internal => true,
                            .external => false,
                        };
                        const flags = llvm.DI.Flags{};
                        const is_definition = switch (global.variable.storage.?.bb) {
                            .function => true,
                            .external_function => false,
                            else => @trap(),
                        };
                        const name = global.variable.name;
                        const linkage_name = name;
                        const subprogram = module.llvm.di_builder.create_function(module.scope.llvm.?, name, linkage_name, module.llvm.file, global.variable.line, subroutine_type, local_to_unit, is_definition, scope_line, flags, module.build_mode.is_optimized());
                        llvm_function_value.set_subprogram(subprogram);

                        break :blk @ptrCast(subprogram);
                    } else undefined;

                    if (global.variable.storage.?.bb == .function) {
                        module.current_function = global;
                        defer module.current_function = null;

                        global.variable.storage.?.bb.function.scope.llvm = function_scope;

                        const entry_block = module.llvm.context.create_basic_block("entry", llvm_function_value);
                        global.variable.storage.?.bb.function.return_block = module.llvm.context.create_basic_block("ret_block", null);

                        module.llvm.builder.position_at_end(entry_block);
                        module.llvm.builder.set_current_debug_location(null);

                        var llvm_abi_argument_buffer: [64]*llvm.Argument = undefined;
                        llvm_function_value.get_arguments(&llvm_abi_argument_buffer);

                        const llvm_abi_arguments = llvm_abi_argument_buffer[0..function_type.abi_argument_types.len];

                        const return_abi_kind = function_type.return_abi.flags.kind;
                        switch (return_abi_kind) {
                            .ignore => {},
                            .indirect => {
                                const indirect_argument_index = @intFromBool(function_type.return_abi.flags.sret_after_this);
                                if (function_type.return_abi.flags.sret_after_this) {
                                    @trap();
                                }
                                global.variable.storage.?.bb.function.return_alloca = llvm_abi_arguments[indirect_argument_index].to_value();
                                if (!function_type.return_abi.flags.indirect_by_value) {
                                    @trap();
                                }
                            },
                            .in_alloca => {
                                @trap();
                            },
                            else => {
                                const alloca = module.create_alloca(.{ .type = function_type.return_abi.semantic_type, .name = "retval" });
                                global.variable.storage.?.bb.function.return_alloca = alloca;
                            },
                        }

                        const argument_variables = global.variable.storage.?.bb.function.arguments;
                        for (function_type.argument_abis, argument_variables, 0..) |argument_abi, argument_variable, argument_index| {
                            const abi_arguments = llvm_abi_arguments[argument_abi.abi_start..][0..argument_abi.abi_count];
                            assert(argument_abi.flags.kind == .ignore or argument_abi.abi_count != 0);
                            const argument_abi_kind = argument_abi.flags.kind;
                            const semantic_argument_storage = switch (argument_abi_kind) {
                                .direct, .extend => blk: {
                                    const first_argument = abi_arguments[0];
                                    const coerce_to_type = argument_abi.get_coerce_to_type();
                                    if (coerce_to_type.bb != .structure and coerce_to_type.is_abi_equal(argument_abi.semantic_type, module) and argument_abi.attributes.direct.offset == 0) {
                                        assert(argument_abi.abi_count == 1);
                                        const is_promoted = false;
                                        var v = first_argument.to_value();
                                        v = switch (coerce_to_type.llvm.abi.? == v.get_type()) {
                                            true => v,
                                            false => @trap(),
                                        };
                                        if (is_promoted) {
                                            @trap();
                                        }

                                        switch (argument_abi.semantic_type.is_arbitrary_bit_integer()) {
                                            true => {
                                                const bit_count = argument_abi.semantic_type.get_bit_size();
                                                const abi_bit_count: u32 = @intCast(@max(8, lib.next_power_of_two(bit_count)));
                                                const is_signed = argument_abi.semantic_type.is_signed();
                                                const destination_type = module.align_integer_type(argument_abi.semantic_type);
                                                const alloca = module.create_alloca(.{ .type = destination_type, .name = argument_variable.variable.name });
                                                const result = switch (bit_count < abi_bit_count) {
                                                    true => switch (is_signed) {
                                                        true => module.llvm.builder.create_sign_extend(first_argument.to_value(), destination_type.llvm.memory.?),
                                                        false => module.llvm.builder.create_zero_extend(first_argument.to_value(), destination_type.llvm.memory.?),
                                                    },
                                                    false => @trap(),
                                                };
                                                _ = module.create_store(.{ .source_value = result, .destination_value = alloca, .type = destination_type });
                                                break :blk alloca;
                                            },
                                            false => { // TODO: ExtVectorBoolType
                                                const alloca = module.create_alloca(.{ .type = argument_abi.semantic_type, .name = argument_variable.variable.name });
                                                _ = module.create_store(.{ .source_value = first_argument.to_value(), .destination_value = alloca, .type = argument_abi.semantic_type });
                                                break :blk alloca;
                                            },
                                        }
                                    } else {
                                        const is_fixed_vector_type = false;
                                        if (is_fixed_vector_type) {
                                            @trap();
                                        }

                                        if (coerce_to_type.bb == .structure and coerce_to_type.bb.structure.fields.len > 1 and argument_abi.flags.kind == .direct and !argument_abi.flags.can_be_flattened) {
                                            const contains_homogeneous_scalable_vector_types = false;
                                            if (contains_homogeneous_scalable_vector_types) {
                                                @trap();
                                            }
                                        }

                                        const alloca = module.create_alloca(.{ .type = argument_abi.semantic_type });
                                        const pointer = switch (argument_abi.attributes.direct.offset > 0) {
                                            true => @trap(),
                                            false => alloca,
                                        };
                                        const pointer_type = switch (argument_abi.attributes.direct.offset > 0) {
                                            true => @trap(),
                                            false => argument_abi.semantic_type,
                                        };

                                        if (coerce_to_type.bb == .structure and coerce_to_type.bb.structure.fields.len > 1 and argument_abi.flags.kind == .direct and argument_abi.flags.can_be_flattened) {
                                            const struct_size = coerce_to_type.get_byte_size();
                                            const pointer_element_size = pointer_type.get_byte_size(); // TODO: fix
                                            const is_scalable = false;

                                            switch (is_scalable) {
                                                true => @trap(),
                                                false => {
                                                    const source_size = struct_size;
                                                    const destination_size = pointer_element_size;
                                                    const address_alignment = argument_abi.semantic_type.get_byte_alignment();
                                                    const address = switch (source_size <= destination_size) {
                                                        true => alloca,
                                                        false => module.create_alloca(.{ .type = coerce_to_type, .alignment = address_alignment, .name = "coerce" }),
                                                    };
                                                    assert(coerce_to_type.bb.structure.fields.len == argument_abi.abi_count);
                                                    coerce_to_type.resolve(module);
                                                    for (coerce_to_type.bb.structure.fields, abi_arguments, 0..) |field, abi_argument, field_index| {
                                                        const gep = module.llvm.builder.create_struct_gep(coerce_to_type.llvm.abi.?.to_struct(), address, @intCast(field_index));
                                                        // TODO: check if alignment is right
                                                        _ = module.create_store(.{ .source_value = abi_argument.to_value(), .destination_value = gep, .type = field.type });
                                                    }

                                                    if (source_size > destination_size) {
                                                        _ = module.llvm.builder.create_memcpy(pointer, pointer_type.get_byte_alignment(), address, address_alignment, module.integer_type(64, false).llvm.abi.?.to_integer().get_constant(destination_size, @intFromBool(false)).to_value());
                                                    }
                                                },
                                            }
                                        } else {
                                            assert(argument_abi.abi_count == 1);
                                            const abi_argument_type = function_type.abi_argument_types[argument_abi.abi_start];
                                            const destination_size = pointer_type.get_byte_size() - argument_abi.attributes.direct.offset;
                                            const is_volatile = false;
                                            module.create_coerced_store(abi_arguments[0].to_value(), abi_argument_type, pointer, pointer_type, destination_size, is_volatile);
                                        }

                                        switch (argument_abi.semantic_type.get_evaluation_kind()) {
                                            .scalar => @trap(),
                                            else => {
                                                // TODO
                                            },
                                        }

                                        break :blk alloca;
                                    }
                                },
                                .indirect, .indirect_aliased => blk: {
                                    assert(argument_abi.abi_count == 1);
                                    switch (argument_abi.semantic_type.get_evaluation_kind()) {
                                        .scalar => @trap(),
                                        else => {
                                            if (argument_abi.flags.indirect_realign or argument_abi.flags.kind == .indirect_aliased) {
                                                @trap();
                                            }

                                            const use_indirect_debug_address = !argument_abi.flags.indirect_by_value;
                                            if (use_indirect_debug_address) {
                                                @trap();
                                            }

                                            const llvm_argument = abi_arguments[0];
                                            break :blk llvm_argument.to_value();
                                        },
                                    }
                                },
                                else => @trap(),
                            };

                            const storage = module.values.add();
                            storage.* = .{
                                .bb = .argument,
                                .type = module.get_pointer_type(.{
                                    .type = argument_variable.variable.type.?,
                                }),
                                .llvm = semantic_argument_storage,
                            };
                            argument_variable.variable.storage = storage;

                            // no pointer
                            const argument_type = argument_variable.variable.storage.?.type.?.bb.pointer.type;
                            if (module.has_debug_info) {
                                const always_preserve = true;
                                const flags = llvm.DI.Flags{};
                                const parameter_variable = module.llvm.di_builder.create_parameter_variable(function_scope, argument_variable.variable.name, @intCast(argument_index + 1), module.llvm.file, argument_variable.variable.line, argument_type.llvm.debug.?, always_preserve, flags);
                                const inlined_at: ?*llvm.DI.Metadata = @ptrCast(module.inline_at_debug_location);
                                const debug_location = llvm.DI.create_debug_location(module.llvm.context, argument_variable.variable.line, argument_variable.variable.column, function_scope, inlined_at);
                                _ = module.llvm.di_builder.insert_declare_record_at_end(semantic_argument_storage, parameter_variable, module.llvm.di_builder.null_expression(), debug_location, entry_block);
                            }
                        }

                        module.analyze_block(global.variable.storage.?.bb.function.main_block);

                        // Handle jump to the return block
                        const return_block = global.variable.storage.?.bb.function.return_block orelse module.report_error();

                        if (module.llvm.builder.get_insert_block()) |current_basic_block| {
                            assert(current_basic_block.get_terminator() == null);

                            if (current_basic_block.is_empty() or current_basic_block.to_value().use_empty()) {
                                return_block.to_value().replace_all_uses_with(current_basic_block.to_value());
                                return_block.delete();
                            } else {
                                module.emit_block(return_block);
                            }
                        } else {
                            var is_reachable = false;

                            if (return_block.to_value().has_one_use()) {
                                if (llvm.Value.to_branch(return_block.user_begin())) |branch| {
                                    is_reachable = !branch.is_conditional() and branch.get_successor(0) == return_block;

                                    if (is_reachable) {
                                        module.llvm.builder.position_at_end(branch.to_instruction().get_parent());
                                        branch.to_instruction().erase_from_parent();
                                        return_block.delete();
                                    }
                                }
                            }

                            if (!is_reachable) {
                                module.emit_block(return_block);
                            }
                        }

                        // End function debug info
                        if (llvm_function_value.get_subprogram()) |subprogram| {
                            module.llvm.di_builder.finalize_subprogram(subprogram);
                        }

                        if (function_type.return_abi.semantic_type == module.noreturn_type or global.variable.storage.?.bb.function.attributes.naked) {
                            _ = module.llvm.builder.create_unreachable();
                        } else if (function_type.return_abi.semantic_type == module.void_type) {
                            module.llvm.builder.create_ret_void();
                        } else {
                            const abi_kind = function_type.return_abi.flags.kind;
                            const return_value: ?*llvm.Value = switch (abi_kind) {
                                .direct, .extend => blk: {
                                    const coerce_to_type = function_type.return_abi.get_coerce_to_type();
                                    const return_alloca = global.variable.storage.?.bb.function.return_alloca orelse unreachable;

                                    if (function_type.return_abi.semantic_type.is_abi_equal(coerce_to_type, module) and function_type.return_abi.attributes.direct.offset == 0) {
                                        if (module.llvm.builder.find_return_value_dominating_store(return_alloca, function_type.return_abi.semantic_type.llvm.abi.?)) |store| {
                                            const store_instruction = store.to_instruction();
                                            const return_value = store_instruction.to_value().get_operand(0);
                                            const alloca = store_instruction.to_value().get_operand(1);
                                            assert(alloca == return_alloca);
                                            store_instruction.erase_from_parent();
                                            assert(alloca.use_empty());
                                            alloca.to_instruction().erase_from_parent();
                                            break :blk return_value;
                                        } else {
                                            const load_value = module.create_load(.{ .type = function_type.return_abi.semantic_type, .value = return_alloca });
                                            break :blk load_value;
                                        }
                                    } else {
                                        const source = switch (function_type.return_abi.attributes.direct.offset == 0) {
                                            true => return_alloca,
                                            false => @trap(),
                                        };

                                        const source_type = function_type.return_abi.semantic_type;
                                        const destination_type = coerce_to_type;
                                        const result = module.create_coerced_load(source, source_type, destination_type);
                                        break :blk result;
                                    }
                                },
                                .indirect => switch (function_type.return_abi.semantic_type.get_evaluation_kind()) {
                                    .complex => @trap(),
                                    .aggregate => null,
                                    .scalar => @trap(),
                                },
                                else => @trap(),
                            };

                            if (return_value) |rv| {
                                module.llvm.builder.create_ret(rv);
                            } else {
                                module.llvm.builder.create_ret_void();
                            }
                        }
                    }

                    if (lib.optimization_mode == .Debug) {
                        const verify_result = llvm_function_value.verify();
                        if (!verify_result.success) {
                            lib.print_string(module.llvm.module.to_string());
                            lib.print_string("============================\n");
                            lib.print_string(llvm_function_value.to_string());
                            lib.print_string("============================\n");
                            lib.print_string(verify_result.error_message orelse unreachable);
                            lib.print_string("\n============================\n");
                            lib.os.abort();
                        }
                    }
                },
                .global => {
                    module.analyze(global.variable.initial_value, .{ .type = global.variable.type }, .memory);

                    if (global.variable.type == null) {
                        global.variable.type = global.variable.initial_value.type;
                    }

                    if (global.variable.type != global.variable.initial_value.type) {
                        module.report_error();
                    }

                    global.variable.type.?.resolve(module);

                    const global_variable = module.llvm.module.create_global_variable(.{
                        .linkage = switch (global.linkage) {
                            .internal => .InternalLinkage,
                            .external => .ExternalLinkage,
                        },
                        .name = global.variable.name,
                        .initial_value = global.variable.initial_value.llvm.?.to_constant(),
                        .type = global.variable.type.?.llvm.memory.?,
                    });
                    global_variable.to_value().set_alignment(global.variable.type.?.get_byte_alignment());
                    global.variable.storage.?.llvm = global_variable.to_value();
                    global.variable.storage.?.type = module.get_pointer_type(.{ .type = global.variable.type.? });

                    if (module.has_debug_info) {
                        const linkage_name = global.variable.name;
                        const local_to_unit = global.linkage == .internal;
                        const alignment = 0; // TODO
                        const global_variable_expression = module.llvm.di_builder.create_global_variable(module.scope.llvm.?, global.variable.name, linkage_name, module.llvm.file, global.variable.line, global.variable.type.?.llvm.debug.?, local_to_unit, module.llvm.di_builder.null_expression(), alignment);
                        global_variable.add_debug_info(global_variable_expression);
                    }
                },
                else => @trap(),
            }
        }

        if (module.has_debug_info) {
            module.llvm.di_builder.finalize();
        }

        const verify_result = module.llvm.module.verify();
        if (!verify_result.success) {
            lib.print_string(module.llvm.module.to_string());
            lib.print_string("============================\n");
            lib.print_string(verify_result.error_message orelse unreachable);
            lib.os.abort();
        }

        if (!module.silent) {
            const module_string = module.llvm.module.to_string();
            lib.print_string_stderr(module_string);
        }

        var error_message: llvm.String = undefined;
        var target_options = llvm.Target.Options.default();
        target_options.flags0.trap_unreachable = switch (module.build_mode) {
            .debug_none, .debug_fast, .debug_size => true,
            else => false,
        };
        const target_machine = llvm.Target.Machine.create(.{
            .target_options = target_options,
            .cpu_triple = llvm.String.from_slice(llvm.global.host_triple),
            .cpu_model = llvm.String.from_slice(llvm.global.host_cpu_model),
            .cpu_features = llvm.String.from_slice(llvm.global.host_cpu_features),
            .optimization_level = module.build_mode.to_llvm_machine(),
            .relocation_model = .default,
            .code_model = .none,
            .jit = false,
        }, &error_message) orelse {
            lib.os.abort();
        };

        const object_generate_result = llvm.object_generate(module.llvm.module, target_machine, .{
            .optimize_when_possible = @intFromEnum(module.build_mode) > @intFromEnum(BuildMode.soft_optimize),
            .debug_info = module.has_debug_info,
            .optimization_level = if (module.build_mode != .debug_none) module.build_mode.to_llvm_ir() else null,
            .path = module.objects[0],
        });

        switch (object_generate_result) {
            .success => {
                const result = llvm.link(module.arena, .{
                    .output_path = module.executable,
                    .objects = module.objects,
                });

                switch (result.success) {
                    true => {},
                    false => lib.os.abort(),
                }
            },
            else => lib.os.abort(),
        }
    }

    pub fn get_va_list_type(module: *Module) *Type {
        if (module.va_list_type) |va_list_type| {
            @branchHint(.likely);
            return va_list_type;
        } else {
            @branchHint(.unlikely);
            const unsigned_int = module.integer_type(32, false);
            const void_pointer = module.get_pointer_type(.{
                .type = module.integer_type(8, false),
            });
            const va_list_name = "va_list";

            const field_buffer = [_]Type.Struct.Field{
                .{ .name = "gp_offset", .type = unsigned_int, .bit_offset = 0, .byte_offset = 0, .line = 0 },
                .{ .name = "fp_offset", .type = unsigned_int, .bit_offset = 32, .byte_offset = 4, .line = 0 },
                .{ .name = "overflow_arg_area", .type = void_pointer, .bit_offset = 64, .byte_offset = 8, .line = 0 },
                .{ .name = "reg_save_area", .type = void_pointer, .bit_offset = 128, .byte_offset = 16, .line = 0 },
            };
            const fields = module.arena.allocate(Type.Struct.Field, 4);
            @memcpy(fields, &field_buffer);

            const result = module.types.append(.{
                .name = va_list_name,
                .bb = .{
                    .structure = .{
                        .bit_alignment = 64,
                        .byte_alignment = 16,
                        .byte_size = 24,
                        .bit_size = 24 * 8,
                        .fields = fields,
                        .is_slice = false,
                        .line = 0,
                    },
                },
            });

            const element_count = 1;
            const element_type = result;
            const ty = module.types.append(.{
                .name = array_type_name(module.arena, element_type, element_count),
                .bb = .{
                    .array = .{
                        .element_type = element_type,
                        .element_count = element_count,
                    },
                },
            });
            module.va_list_type = ty;
            return ty;
        }
    }

    const ValueAnalysis = struct {
        type: ?*Type = null,
    };

    pub fn analyze(module: *Module, value: *Value, analysis: ValueAnalysis, type_kind: Type.Kind) void {
        module.analyze_value_type(value, analysis);
        module.emit_value(value, type_kind);
    }

    pub fn analyze_binary(module: *Module, left: *Value, right: *Value, is_boolean: bool, a: ValueAnalysis) void {
        var analysis = a;
        const is_left_constant = left.is_constant();
        const is_right_constant = right.is_constant();
        if (analysis.type == null) {
            if (is_left_constant and is_right_constant) {
                if (left.type == null and right.type == null) {
                    const are_string_literal = left.bb == .string_literal and right.bb == .string_literal;
                    if (are_string_literal) {
                        analysis.type = module.get_slice_type(.{ .type = module.integer_type(8, false) });
                    } else {
                        module.report_error();
                    }
                }
            }
        }

        if (is_boolean or analysis.type == null) {
            if (is_left_constant) {
                module.analyze_value_type(right, .{});
                module.analyze_value_type(left, .{
                    .type = right.type,
                });
            } else if (is_right_constant) {
                module.analyze_value_type(left, .{});
                module.analyze_value_type(right, .{
                    .type = left.type,
                });
            } else {
                module.analyze_value_type(left, .{});
                module.analyze_value_type(right, .{ .type = left.type });
            }
        } else if (!is_boolean and analysis.type != null) {
            const expected_type = analysis.type.?;
            module.analyze_value_type(left, .{
                .type = expected_type,
            });
            module.analyze_value_type(right, .{
                .type = expected_type,
            });
        } else {
            @trap();
        }

        assert(left.type != null);
        assert(right.type != null);
    }

    pub fn typecheck(module: *Module, analysis: ValueAnalysis, ty: *Type) void {
        if (analysis.type) |expected_type| {
            module.check_types(expected_type, ty);
        }
    }

    fn fully_resolve_alias(module: *Module, ty: *Type) *Type {
        const result_type = switch (ty.bb) {
            .bits,
            .structure,
            .@"union",
            .integer,
            .enumerator,
            .array,
            .noreturn,
            .void,
            .function,
            => ty,
            .alias => |alias| alias.type,
            .pointer => |pointer| module.get_pointer_type(.{ .type = module.fully_resolve_alias(pointer.type) }),
            else => @trap(),
        };

        return result_type;
    }

    pub fn check_types(module: *Module, expected_type: *Type, source_type: *Type) void {
        if (expected_type != source_type) {
            const dst_p_src_i = expected_type.bb == .pointer and source_type.bb == .integer;
            if (!dst_p_src_i) {
                const source = module.fully_resolve_alias(source_type);
                const expected = module.fully_resolve_alias(expected_type);
                if (source != expected) {
                    module.report_error();
                }
            }
        }
    }

    pub fn copy_statement(module: *Module, scope: *Scope, old_statement: *Statement) *Statement {
        const new_statement = module.statements.add();
        new_statement.line = old_statement.line;
        new_statement.column = old_statement.column;

        new_statement.bb = switch (old_statement.bb) {
            .@"return" => |rv| if (rv) |v| .{
                .@"return" = module.clone_value(scope, v),
            } else old_statement.bb,
            .@"if" => |if_stmt| blk: {
                const condition = module.clone_value(scope, if_stmt.condition);
                const if_statement = module.copy_statement(scope, if_stmt.if_statement);
                const else_statement = if (if_stmt.else_statement) |else_statement| module.copy_statement(scope, else_statement) else null;
                break :blk .{
                    .@"if" = .{
                        .condition = condition,
                        .if_statement = if_statement,
                        .else_statement = else_statement,
                    },
                };
            },
            .block => |block| blk: {
                const lexical_block = module.lexical_blocks.add();
                module.copy_block(scope, .{
                    .source = block,
                    .destination = lexical_block,
                });

                break :blk .{
                    .block = lexical_block,
                };
            },
            .expression => |v| .{
                .expression = module.clone_value(scope, v),
            },
            else => @trap(),
        };

        return new_statement;
    }

    const BlockCopy = struct {
        source: *LexicalBlock,
        destination: *LexicalBlock,
    };

    pub fn copy_block(module: *Module, parent_scope: *Scope, block_copy: BlockCopy) void {
        const source = block_copy.source;
        const destination = block_copy.destination;
        destination.* = .{
            .locals = .initialize(),
            .statements = .initialize(),
            .scope = .{
                .line = source.scope.line,
                .column = source.scope.column,
                .kind = source.scope.kind,
                .parent = parent_scope,
            },
        };

        const scope = &destination.scope;

        for (source.statements.get_slice()) |old_statement| {
            const statement = module.copy_statement(scope, old_statement);
            _ = destination.statements.append(statement);
        }
    }

    pub fn clone_value(module: *Module, scope: *Scope, source: *Value) *Value {
        const result = switch (source.bb) {
            .variable_reference => |variable| module.reference_identifier(scope, variable.name, source.kind),
            else => blk: {
                const result = module.values.add();

                result.* = .{
                    .bb = switch (source.bb) {
                        .unary => |unary| .{
                            .unary = .{
                                .value = module.clone_value(scope, unary.value),
                                .id = unary.id,
                            },
                        },
                        .binary => |binary| .{
                            .binary = .{
                                .left = module.clone_value(scope, binary.left),
                                .right = module.clone_value(scope, binary.right),
                                .id = binary.id,
                            },
                        },
                        .variable_reference => unreachable,
                        .call => |call| b: {
                            const callable = module.clone_value(scope, call.callable);
                            const arguments = module.arena.allocate(*Value, call.arguments.len);
                            for (arguments, call.arguments) |*new_argument, old_argument| {
                                new_argument.* = module.clone_value(scope, old_argument);
                            }
                            break :b .{
                                .call = .{
                                    .callable = callable,
                                    .arguments = arguments,
                                    .function_type = call.function_type,
                                },
                            };
                        },
                        .intrinsic => |intrinsic| .{
                            .intrinsic = switch (intrinsic) {
                                .alignof => |ty| .{
                                    .alignof = module.resolve_type(ty),
                                },
                                .byte_size => |ty| .{
                                    .byte_size = module.resolve_type(ty),
                                },
                                .pointer_cast => |value| .{
                                    .pointer_cast = module.clone_value(scope, value),
                                },
                                else => @trap(),
                            },
                        },
                        .@"unreachable" => .@"unreachable",
                        else => @trap(),
                    },
                    .kind = source.kind,
                };

                break :blk result;
            },
        };

        return result;
    }

    pub fn analyze_value_type(module: *Module, value: *Value, a: ValueAnalysis) void {
        assert(value.type == null);
        assert(value.llvm == null);

        var analysis = a;
        if (analysis.type) |expected_type| switch (expected_type.bb) {
            .unresolved => {
                const macro_instantiation = (module.current_macro_instantiation orelse module.report_error()).bb.macro_instantiation;
                const macro_declaration = macro_instantiation.declaration;

                const resolved_type = for (macro_declaration.type_arguments, macro_instantiation.type_arguments) |t, result_type| {
                    if (t == expected_type) {
                        result_type.resolve(module);
                        break result_type;
                    }
                } else unreachable;
                analysis.type = resolved_type;
                @trap();
            },
            else => {},
        };
        // .unresolved => blk: {
        //     // TODO: nest macros
        // },

        const value_type = switch (value.bb) {
            .unary => |unary| b: {
                if (unary.id.is_boolean()) {
                    module.analyze_value_type(unary.value, .{});
                    const boolean_type = module.integer_type(1, false);
                    module.typecheck(analysis, boolean_type);
                    break :b boolean_type;
                } else {
                    module.analyze_value_type(unary.value, analysis);
                    const result_type = unary.value.type.?;
                    module.typecheck(analysis, result_type);

                    break :b result_type;
                }
            },
            .binary => |binary| blk: {
                const is_boolean = binary.id.is_boolean();

                module.analyze_binary(binary.left, binary.right, is_boolean, analysis);
                module.check_types(binary.left.type.?, binary.right.type.?);

                const result_type = if (is_boolean) module.integer_type(1, false) else binary.left.type.?;
                module.typecheck(analysis, result_type);
                break :blk result_type;
            },
            .constant_integer => |constant_integer| blk: {
                const expected_type = analysis.type orelse module.report_error();
                expected_type.resolve(module);
                const et = switch (expected_type.bb) {
                    .alias => b: {
                        var it = expected_type;
                        while (it.bb == .alias) {
                            it = it.bb.alias.type;
                        }
                        break :b it;
                    },
                    else => expected_type,
                };
                const ty = switch (et.bb) {
                    .integer => |integer| switch (constant_integer.signed) {
                        true => {
                            if (!integer.signed) {
                                module.report_error();
                            }

                            @trap();
                        },
                        false => {
                            const bit_count = integer.bit_count;
                            const max_value = if (bit_count == 64) ~@as(u64, 0) else (@as(u64, 1) << @intCast(bit_count - @intFromBool(integer.signed))) - 1;

                            if (constant_integer.value > max_value) {
                                module.report_error();
                            }

                            break :blk expected_type;
                        },
                    },
                    .pointer => module.integer_type(64, false),
                    else => @trap(),
                };
                module.typecheck(analysis, ty);
                break :blk ty;
            },
            .variable_reference => |variable| b: {
                const ty = switch (value.kind) {
                    .left => variable.storage.?.type.?,
                    .right => variable.type.?,
                };
                module.typecheck(analysis, ty);
                break :b ty;
            },
            .@"unreachable" => module.noreturn_type,
            .call => |*call| blk: {
                module.analyze_value_type(call.callable, .{});
                call.function_type = switch (call.callable.bb) {
                    .variable_reference => |variable| switch (variable.type.?.bb) {
                        .function => variable.type.?,
                        .pointer => |pointer| switch (pointer.type.bb) {
                            .function => pointer.type,
                            else => @trap(),
                        },
                        else => @trap(),
                    },
                    else => @trap(),
                };

                const declaration_argument_types = call.function_type.bb.function.semantic_argument_types;

                switch (call.function_type.bb.function.is_var_args) {
                    true => if (call.arguments.len < declaration_argument_types.len) {
                        module.report_error();
                    },
                    false => if (call.arguments.len != declaration_argument_types.len) {
                        module.report_error();
                    },
                }

                for (declaration_argument_types, call.arguments[0..declaration_argument_types.len]) |argument_type, call_argument| {
                    module.analyze_value_type(call_argument, .{ .type = argument_type });
                    module.check_types(argument_type, call_argument.type.?);
                }

                for (call.arguments[declaration_argument_types.len..]) |call_argument| {
                    module.analyze_value_type(call_argument, .{});
                }

                const semantic_return_type = call.function_type.bb.function.semantic_return_type;
                module.typecheck(analysis, semantic_return_type);
                break :blk semantic_return_type;
            },
            .intrinsic => |intrinsic| switch (intrinsic) {
                .alignof => |ty| blk: {
                    const expected_type = analysis.type orelse module.report_error();
                    // TODO
                    if (expected_type.bb != .integer) {
                        module.report_error();
                    }

                    const alignment = ty.get_byte_alignment();

                    const max_value = if (expected_type.bb.integer.bit_count == 64) ~@as(u64, 0) else (@as(u64, 1) << @intCast(expected_type.bb.integer.bit_count - @intFromBool(expected_type.bb.integer.signed))) - 1;
                    if (alignment > max_value) {
                        module.report_error();
                    }

                    break :blk expected_type;
                },
                .byte_size => |ty| blk: {
                    const expected_type = analysis.type orelse module.report_error();
                    // TODO
                    if (expected_type.bb != .integer) {
                        module.report_error();
                    }

                    const size = ty.get_byte_size();
                    const max_value = if (expected_type.bb.integer.bit_count == 64) ~@as(u64, 0) else (@as(u64, 1) << @intCast(expected_type.bb.integer.bit_count - @intFromBool(expected_type.bb.integer.signed))) - 1;
                    if (size > max_value) {
                        module.report_error();
                    }

                    break :blk expected_type;
                },
                .enum_name => |enum_value| blk: {
                    const string_type = module.get_slice_type(.{ .type = module.integer_type(8, false) });
                    module.typecheck(analysis, string_type);
                    module.analyze_value_type(enum_value, .{});
                    const enum_type = enum_value.type.?;
                    switch (enum_type.bb) {
                        .enumerator => |*enumerator| {
                            const enum_array_name_global = module.get_enum_name_array_global(enum_value.type.?);
                            if (enumerator.enum_to_string == null) {
                                const current_block = module.llvm.builder.get_insert_block();
                                const llvm_function_type = llvm.Type.Function.get(string_type.llvm.memory.?, &.{enum_type.llvm.abi.?}, false);
                                const llvm_function_value = module.llvm.module.create_function(.{
                                    .name = module.arena.join_string(&.{ "enum_to_string.", enum_type.name }),
                                    .linkage = .InternalLinkage,
                                    .type = llvm_function_type,
                                });
                                llvm_function_value.set_calling_convention(.fast);
                                var llvm_function_arguments: [1]*llvm.Argument = undefined;
                                llvm_function_value.get_arguments(&llvm_function_arguments);
                                const llvm_arg = llvm_function_arguments[0];

                                const function_entry_block = module.llvm.context.create_basic_block("entry", llvm_function_value);
                                module.llvm.builder.position_at_end(function_entry_block);

                                const alloca = module.create_alloca(.{
                                    .type = string_type,
                                    .name = "retval",
                                });

                                const return_block = module.llvm.context.create_basic_block("return_block", llvm_function_value);
                                const else_block = module.llvm.context.create_basic_block("else_block", llvm_function_value);

                                const switch_i = module.llvm.builder.create_switch(llvm_arg.to_value(), else_block, @intCast(enumerator.fields.len));
                                const backing_type = enumerator.backing_type.llvm.abi.?.to_integer();
                                const uint64 = module.integer_type(64, false).llvm.abi.?.to_integer();

                                for (enumerator.fields, 0..) |field, field_index| {
                                    const case_block = module.llvm.context.create_basic_block(module.arena.join_string(&.{ "case_block.", field.name }), llvm_function_value);
                                    const case_value = backing_type.get_constant(field.value, 0).to_value();
                                    switch_i.add_case(case_value, case_block);
                                    module.llvm.builder.position_at_end(case_block);
                                    const case_value_result_pointer = module.llvm.builder.create_gep(.{
                                        .type = enum_array_name_global.variable.type.?.llvm.memory.?,
                                        .aggregate = enum_array_name_global.variable.storage.?.llvm.?,
                                        .indices = &.{ uint64.get_constant(0, 0).to_value(), uint64.get_constant(field_index, 0).to_value() },
                                    });
                                    const case_value_result = module.create_load(.{
                                        .type = string_type,
                                        .value = case_value_result_pointer,
                                    });
                                    _ = module.create_store(.{
                                        .type = string_type,
                                        .destination_value = alloca,
                                        .source_value = case_value_result,
                                    });
                                    _ = module.llvm.builder.create_branch(return_block);
                                }

                                module.llvm.builder.position_at_end(else_block);
                                _ = module.llvm.builder.create_unreachable();

                                module.llvm.builder.position_at_end(return_block);
                                const function_result = module.create_load(.{
                                    .type = string_type,
                                    .value = alloca,
                                });

                                module.llvm.builder.create_ret(function_result);

                                if (current_block) |bb| {
                                    module.llvm.builder.position_at_end(bb);
                                }

                                enumerator.enum_to_string = llvm_function_value;
                            }

                            break :blk string_type;
                        },
                        else => module.report_error(),
                    }
                },
                .extend => |extended_value| blk: {
                    const expected_type = analysis.type orelse module.report_error();
                    module.analyze_value_type(extended_value, .{});
                    assert(extended_value.type != null);
                    const destination_type = expected_type;
                    const source_type = extended_value.type.?;

                    if (source_type.get_bit_size() > destination_type.get_bit_size()) {
                        module.report_error();
                    } else if (source_type.get_bit_size() == destination_type.get_bit_size() and source_type.is_signed() == destination_type.is_signed()) {
                        module.report_error();
                    }

                    break :blk expected_type;
                },
                .integer_max => |integer_max_type| blk: {
                    if (integer_max_type.bb != .integer) {
                        module.report_error();
                    }
                    if (analysis.type) |expected_type| {
                        if (expected_type.bb != .integer) {
                            module.report_error();
                        }
                    }

                    const result_type = if (analysis.type) |et| et else integer_max_type;
                    module.typecheck(analysis, result_type);

                    break :blk result_type;
                },
                .int_from_enum => |enum_value| blk: {
                    module.analyze_value_type(enum_value, .{});
                    if (enum_value.type.?.bb != .enumerator) {
                        module.report_error();
                    }

                    const enum_backing_type = enum_value.type.?.bb.enumerator.backing_type;
                    module.typecheck(analysis, enum_backing_type);
                    break :blk enum_backing_type;
                },
                .int_from_pointer => |pointer_value| blk: {
                    module.analyze_value_type(pointer_value, .{});
                    assert(pointer_value.type != null);
                    if (pointer_value.type.?.bb != .pointer) {
                        module.report_error();
                    }

                    const result_type = module.integer_type(64, false);
                    module.typecheck(analysis, result_type);

                    break :blk result_type;
                },
                .pointer_cast => |pointer_value| blk: {
                    const expected_type = analysis.type orelse module.report_error();
                    if (expected_type.bb != .pointer) {
                        module.report_error();
                    }
                    module.analyze_value_type(pointer_value, .{});
                    const pointer_type = pointer_value.type orelse module.report_error();

                    if (pointer_type == expected_type) {
                        module.report_error();
                    }

                    if (pointer_type.bb != .pointer) {
                        module.report_error();
                    }

                    break :blk expected_type;
                },
                .select => |select| blk: {
                    module.analyze_value_type(select.condition, .{});
                    const is_boolean = false; // This indicates that the result type must not be a boolean type
                    module.analyze_binary(select.true_value, select.false_value, is_boolean, analysis);

                    const left_type = select.true_value.type.?;
                    const right_type = select.false_value.type.?;
                    module.check_types(left_type, right_type);
                    assert(left_type == right_type);
                    const result_type = left_type;
                    module.typecheck(analysis, result_type);

                    break :blk result_type;
                },
                .string_to_enum => |string_to_enum| blk: {
                    if (string_to_enum.enum_type.bb != .enumerator) {
                        module.report_error();
                    }

                    if (string_to_enum.enum_type.bb.enumerator.string_to_enum == null) {
                        const fields = string_to_enum.enum_type.bb.enumerator.fields;
                        const array_element_count = fields.len;

                        const insert_block = module.llvm.builder.get_insert_block();
                        defer module.llvm.builder.position_at_end(insert_block.?);

                        const uint1 = module.integer_type(1, false);
                        uint1.resolve(module);
                        const uint8 = module.integer_type(8, false);
                        uint8.resolve(module);

                        const alignment = string_to_enum.enum_type.get_byte_alignment();
                        const byte_size = lib.align_forward_u64(string_to_enum.enum_type.get_byte_size() + 1, alignment);

                        const struct_fields = module.arena.allocate(Type.Struct.Field, 2);
                        struct_fields[0] = .{
                            .bit_offset = 0,
                            .line = 0,
                            .type = string_to_enum.enum_type,
                            .name = "enum_value",
                            .byte_offset = 0,
                        };
                        struct_fields[1] = .{
                            .byte_offset = string_to_enum.enum_type.get_byte_size(),
                            .bit_offset = string_to_enum.enum_type.get_byte_size() * 8,
                            .line = 0,
                            .type = uint1,
                            .name = "is_valid",
                        };

                        const struct_type = module.types.append(.{
                            .name = "string_to_enum",
                            .bb = .{
                                .structure = .{
                                    .fields = struct_fields,
                                    .byte_size = byte_size,
                                    .bit_size = byte_size * 8,
                                    .byte_alignment = alignment,
                                    .bit_alignment = alignment * 8,
                                    .line = 0,
                                    .is_slice = false,
                                },
                            },
                        });
                        struct_type.resolve(module);

                        const uint64 = module.integer_type(64, false);
                        uint64.resolve(module);
                        const llvm_function_type = llvm.Type.Function.get(struct_type.llvm.abi.?, &.{ module.llvm.pointer_type, uint64.llvm.abi.? }, false);
                        const slice_struct_type = module.get_slice_type(.{ .type = uint8 });

                        const llvm_function_value = module.llvm.module.create_function(.{
                            .name = module.arena.join_string(&.{ "string_to_enum.", string_to_enum.enum_type.name }),
                            .linkage = .InternalLinkage,
                            .type = llvm_function_type,
                        });
                        llvm_function_value.set_calling_convention(.fast);

                        const name_array_global = module.get_enum_name_array_global(string_to_enum.enum_type);

                        var value_constant_buffer: [64]*llvm.Constant = undefined;

                        for (string_to_enum.enum_type.bb.enumerator.fields, 0..) |field, field_index| {
                            const value_global = string_to_enum.enum_type.llvm.memory.?.to_integer().get_constant(field.value, 0);
                            value_constant_buffer[field_index] = value_global.to_constant();
                        }

                        const value_array = string_to_enum.enum_type.llvm.memory.?.get_constant_array(value_constant_buffer[0..array_element_count]);
                        const value_array_variable_type = string_to_enum.enum_type.llvm.memory.?.get_array_type(array_element_count);
                        const value_array_variable = module.llvm.module.create_global_variable(.{
                            .type = value_array_variable_type.to_type(),
                            .linkage = .InternalLinkage,
                            .initial_value = value_array,
                            .name = "value.array.enum",
                        });
                        value_array_variable.to_value().set_alignment(string_to_enum.enum_type.get_byte_alignment());

                        const function_entry_block = module.llvm.context.create_basic_block("entry", llvm_function_value);
                        const return_block = module.llvm.context.create_basic_block("return_block", llvm_function_value);
                        const loop_entry_block = module.llvm.context.create_basic_block("loop.entry", llvm_function_value);
                        const loop_body_block = module.llvm.context.create_basic_block("loop.body", llvm_function_value);
                        const loop_exit_block = module.llvm.context.create_basic_block("loop.exit", llvm_function_value);
                        module.llvm.builder.position_at_end(function_entry_block);

                        var arguments: [2]*llvm.Argument = undefined;
                        llvm_function_value.get_arguments(&arguments);

                        const return_value_alloca = module.create_alloca(.{
                            .type = string_to_enum.enum_type,
                            .name = "retval",
                        });
                        const return_boolean_alloca = module.create_alloca(.{
                            .type = uint8,
                            .name = "retbool",
                        });
                        const index_alloca = module.create_alloca(.{
                            .type = uint64,
                            .name = "idx",
                        });
                        _ = module.create_store(.{
                            .type = uint64,
                            .source_value = uint64.llvm.abi.?.get_zero().to_value(),
                            .destination_value = index_alloca,
                        });
                        const slice_pointer = arguments[0].to_value();
                        const slice_length = arguments[1].to_value();
                        _ = module.llvm.builder.create_branch(loop_entry_block);

                        module.llvm.builder.position_at_end(loop_entry_block);
                        const index_load = module.create_load(.{
                            .type = uint64,
                            .value = index_alloca,
                        });
                        const loop_cmp = module.llvm.builder.create_integer_compare(.ult, index_load, uint64.llvm.abi.?.to_integer().get_constant(array_element_count, 0).to_value());
                        _ = module.llvm.builder.create_conditional_branch(loop_cmp, loop_body_block, loop_exit_block);

                        module.llvm.builder.position_at_end(loop_body_block);

                        const body_index_load = module.create_load(.{
                            .type = uint64,
                            .value = index_alloca,
                        });
                        const uint64_zero = uint64.llvm.abi.?.get_zero().to_value();

                        const array_element_pointer = module.llvm.builder.create_gep(.{
                            .type = name_array_global.variable.type.?.llvm.memory.?,
                            .aggregate = name_array_global.variable.storage.?.llvm.?,
                            .indices = &.{ uint64_zero, body_index_load },
                        });

                        const element_length_pointer = module.llvm.builder.create_struct_gep(slice_struct_type.llvm.abi.?.to_struct(), array_element_pointer, 1);
                        const element_length = module.create_load(.{
                            .type = uint64,
                            .value = element_length_pointer,
                        });

                        const length_comparison = module.llvm.builder.create_integer_compare(.eq, slice_length, element_length);

                        const length_match_block = module.llvm.context.create_basic_block("length.match", llvm_function_value);
                        const length_mismatch_block = module.llvm.context.create_basic_block("length.mismatch", llvm_function_value);
                        _ = module.llvm.builder.create_conditional_branch(length_comparison, length_match_block, length_mismatch_block);

                        module.llvm.builder.position_at_end(length_match_block);
                        const s32 = module.integer_type(32, true);
                        s32.resolve(module);
                        const memcmp = if (module.llvm.memcmp) |memcmp| memcmp else b: {
                            if (module.llvm.module.get_named_function("memcmp")) |memcmp| {
                                module.llvm.memcmp = memcmp;
                                break :b memcmp;
                            } else {
                                const memcmp = module.llvm.module.create_function(.{
                                    .name = "memcmp",
                                    .linkage = .ExternalLinkage,
                                    .type = llvm.Type.Function.get(s32.llvm.abi.?, &.{ module.llvm.pointer_type, module.llvm.pointer_type, uint64.llvm.abi.? }, false),
                                });
                                module.llvm.memcmp = memcmp;
                                break :b memcmp;
                            }
                        };

                        const length_index_load = module.create_load(.{
                            .type = uint64,
                            .value = index_alloca,
                        });
                        const length_array_element_pointer = module.llvm.builder.create_gep(.{
                            .type = name_array_global.variable.type.?.llvm.memory.?,
                            .aggregate = name_array_global.variable.storage.?.llvm.?,
                            .indices = &.{ uint64_zero, length_index_load },
                        });
                        const element_pointer_pointer = module.llvm.builder.create_struct_gep(slice_struct_type.llvm.abi.?.to_struct(), length_array_element_pointer, 0);
                        const element_pointer = module.create_load(.{
                            .type = module.get_pointer_type(.{ .type = uint8 }),
                            .value = element_pointer_pointer,
                        });
                        const memcmp_return_result = module.llvm.builder.create_call(memcmp.get_type(), memcmp.to_value(), &.{ slice_pointer, element_pointer, slice_length });
                        const content_comparison = module.llvm.builder.create_integer_compare(.eq, memcmp_return_result, s32.llvm.abi.?.get_zero().to_value());
                        const content_match_block = module.llvm.context.create_basic_block("content.match", llvm_function_value);
                        _ = module.llvm.builder.create_conditional_branch(content_comparison, content_match_block, length_mismatch_block);

                        module.llvm.builder.position_at_end(content_match_block);
                        const content_index_load = module.create_load(.{
                            .type = uint64,
                            .value = index_alloca,
                        });
                        const value_array_element_pointer = module.llvm.builder.create_gep(.{
                            .type = value_array_variable_type.to_type(),
                            .aggregate = value_array_variable.to_value(),
                            .indices = &.{ uint64_zero, content_index_load },
                        });
                        const enum_value_load = module.create_load(.{
                            .type = string_to_enum.enum_type,
                            .value = value_array_element_pointer,
                        });
                        _ = module.create_store(.{
                            .type = string_to_enum.enum_type,
                            .source_value = enum_value_load,
                            .destination_value = return_value_alloca,
                        });
                        _ = module.create_store(.{
                            .type = uint8,
                            .source_value = uint8.llvm.abi.?.to_integer().get_constant(1, 0).to_value(),
                            .destination_value = return_boolean_alloca,
                        });
                        _ = module.llvm.builder.create_branch(return_block);

                        module.llvm.builder.position_at_end(length_mismatch_block);
                        const inc_index_load = module.create_load(.{
                            .type = uint64,
                            .value = index_alloca,
                        });
                        const inc = module.llvm.builder.create_add(inc_index_load, uint64.llvm.abi.?.to_integer().get_constant(1, 0).to_value());
                        _ = module.create_store(.{
                            .type = uint64,
                            .source_value = inc,
                            .destination_value = index_alloca,
                        });
                        _ = module.llvm.builder.create_branch(loop_entry_block);

                        module.llvm.builder.position_at_end(loop_exit_block);
                        _ = module.create_store(.{
                            .type = string_to_enum.enum_type,
                            .source_value = string_to_enum.enum_type.llvm.memory.?.get_zero().to_value(),
                            .destination_value = return_value_alloca,
                        });
                        _ = module.create_store(.{
                            .type = uint8,
                            .source_value = uint8.llvm.memory.?.get_zero().to_value(),
                            .destination_value = return_boolean_alloca,
                        });
                        _ = module.llvm.builder.create_branch(return_block);

                        module.llvm.builder.position_at_end(return_block);

                        const value_load = module.create_load(.{
                            .type = string_to_enum.enum_type,
                            .value = return_value_alloca,
                            .type_kind = .memory,
                        });
                        var return_value = module.llvm.builder.create_insert_value(struct_type.llvm.memory.?.get_poison(), value_load, 0);
                        const bool_load = module.create_load(.{
                            .type = uint8,
                            .value = return_boolean_alloca,
                        });
                        return_value = module.llvm.builder.create_insert_value(return_value, bool_load, 1);

                        module.llvm.builder.create_ret(return_value);

                        string_to_enum.enum_type.bb.enumerator.string_to_enum = .{
                            .function = llvm_function_value,
                            .struct_type = struct_type,
                        };
                    }

                    const s2e = string_to_enum.enum_type.bb.enumerator.string_to_enum orelse unreachable;

                    const result_type = s2e.struct_type;
                    module.typecheck(analysis, result_type);

                    const string_type = module.get_slice_type(.{ .type = module.integer_type(8, false) });

                    module.analyze_value_type(string_to_enum.string_value, .{ .type = string_type });

                    break :blk result_type;
                },
                .truncate => |value_to_truncate| blk: {
                    // TODO: better typechecking
                    const expected_type = analysis.type orelse module.report_error();
                    module.analyze_value_type(value_to_truncate, .{});
                    if (expected_type.get_bit_size() >= value_to_truncate.type.?.get_bit_size()) {
                        module.report_error();
                    }
                    break :blk expected_type;
                },
                .trap => module.noreturn_type,
                .va_arg => |va_arg| blk: {
                    module.analyze_value_type(va_arg.list, .{
                        .type = module.get_pointer_type(.{ .type = module.get_va_list_type() }),
                    });
                    const result_type = va_arg.type;
                    module.typecheck(analysis, result_type);
                    break :blk result_type;
                },
                .va_end => |va_list| blk: {
                    module.analyze_value_type(va_list, .{
                        .type = module.get_pointer_type(.{ .type = module.get_va_list_type() }),
                    });
                    const result_type = module.void_type;
                    module.typecheck(analysis, result_type);
                    break :blk result_type;
                },
                .va_start => blk: {
                    const result_type = module.get_va_list_type();
                    module.typecheck(analysis, result_type);
                    break :blk result_type;
                },
                else => @trap(),
            },
            .dereference => |dereferenced_value| blk: {
                module.analyze_value_type(dereferenced_value, .{});

                const dereference_type = switch (value.kind) {
                    .left => @trap(),
                    .right => dereferenced_value.type.?.bb.pointer.type,
                };

                module.typecheck(analysis, dereference_type);

                break :blk dereference_type;
            },
            .slice_expression => |slice_expression| blk: {
                if (slice_expression.array_like.kind != .left) {
                    module.report_error();
                }
                module.analyze_value_type(slice_expression.array_like, .{});

                const pointer_type = slice_expression.array_like.type.?;
                if (pointer_type.bb != .pointer) {
                    module.report_error();
                }

                const sliceable_type = pointer_type.bb.pointer.type;

                const element_type = switch (sliceable_type.bb) {
                    .pointer => |pointer| pointer.type,
                    .structure => |structure| b: {
                        if (!structure.is_slice) {
                            module.report_error();
                        }
                        break :b structure.fields[0].type.bb.pointer.type;
                    },
                    .array => |array| array.element_type,
                    else => @trap(),
                };

                const slice_type = module.get_slice_type(.{ .type = element_type });

                module.typecheck(analysis, slice_type);

                const index_type = module.integer_type(64, false);

                if (slice_expression.start) |start| {
                    module.analyze_value_type(start, .{ .type = index_type });

                    if (start.type.?.bb != .integer) {
                        module.report_error();
                    }
                }

                if (slice_expression.end) |end| {
                    module.analyze_value_type(end, .{ .type = index_type });

                    if (end.type.?.bb != .integer) {
                        module.report_error();
                    }
                }

                break :blk slice_type;
            },
            .field_access => |field_access| blk: {
                module.analyze_value_type(field_access.aggregate, .{});
                const field_name = field_access.field;

                const field_type = switch (field_access.aggregate.kind) {
                    .left => left: {
                        if (field_access.aggregate.type.?.bb != .pointer) {
                            module.report_error();
                        }
                        const pty = field_access.aggregate.type.?.bb.pointer.type;
                        const ty = module.fully_resolve_alias(switch (pty.bb) {
                            .pointer => |pointer| pointer.type,
                            else => pty,
                        });

                        const result_type = switch (ty.bb) {
                            .structure => |structure| s: {
                                const field_type = for (structure.fields) |*field| {
                                    if (lib.string.equal(field_name, field.name)) {
                                        break field.type;
                                    }
                                } else {
                                    module.report_error();
                                };

                                break :s switch (value.kind) {
                                    .left => module.get_pointer_type(.{ .type = field_type }),
                                    .right => field_type,
                                };
                            },
                            .@"union" => |union_type| s: {
                                const field_type = for (union_type.fields) |*field| {
                                    if (lib.string.equal(field_name, field.name)) {
                                        break field.type;
                                    }
                                } else {
                                    module.report_error();
                                };

                                break :s switch (value.kind) {
                                    .left => module.get_pointer_type(.{ .type = field_type }),
                                    .right => field_type,
                                };
                            },
                            .bits => |bits| b: {
                                const field_type = for (bits.fields) |*field| {
                                    if (lib.string.equal(field_name, field.name)) {
                                        break field.type;
                                    }
                                } else {
                                    module.report_error();
                                };
                                break :b switch (value.kind) {
                                    .left => module.report_error(),
                                    .right => field_type,
                                };
                            },
                            .array => a: {
                                if (analysis.type) |expected_type| {
                                    if (expected_type.bb != .integer) {
                                        module.report_error();
                                    }
                                    // TODO: see if the count fits into the integer type
                                    break :a expected_type;
                                } else {
                                    @trap();
                                }
                            },
                            .pointer => module.report_error(),
                            else => @trap(),
                        };
                        break :left result_type;
                    },
                    .right => module.report_error(),
                };

                module.typecheck(analysis, field_type);

                break :blk field_type;
            },
            .array_expression => |array_expression| blk: {
                module.analyze_value_type(array_expression.index, .{
                    .type = module.integer_type(64, false),
                });

                // Overwrite side of the expression
                array_expression.array_like.kind = .left;
                module.analyze_value_type(array_expression.array_like, .{});
                const element_type = switch (array_expression.array_like.kind) {
                    .left => switch (array_expression.array_like.type.?.bb) {
                        .pointer => |pointer| switch (pointer.type.bb) {
                            .array => |array| array.element_type,
                            .structure => |structure| b: {
                                if (!structure.is_slice) {
                                    module.report_error();
                                }
                                break :b structure.fields[0].type.bb.pointer.type;
                            },
                            .pointer => |p| p.type,
                            else => @trap(),
                        },
                        else => module.report_error(),
                    },
                    .right => @trap(),
                };

                const result_type = switch (value.kind) {
                    .left => module.get_pointer_type(.{ .type = element_type }),
                    .right => element_type,
                };

                module.typecheck(analysis, result_type);

                break :blk result_type;
            },
            .aggregate_initialization => |*aggregate_initialization| switch (module.fully_resolve_alias(analysis.type orelse module.report_error()).bb) {
                .bits => |bits| blk: {
                    var is_ordered = true;
                    var is_constant = true;
                    for (aggregate_initialization.names, aggregate_initialization.values, 0..) |field_name, field_value, initialization_index| {
                        const declaration_index = for (bits.fields, 0..) |field, declaration_index| {
                            if (lib.string.equal(field.name, field_name)) {
                                break declaration_index;
                            }
                        } else module.report_error();
                        is_ordered = is_ordered and declaration_index == initialization_index;
                        const field = &bits.fields[declaration_index];
                        const declaration_type = field.type;
                        module.analyze_value_type(field_value, .{ .type = declaration_type });
                        is_constant = is_constant and field_value.is_constant();
                    }

                    aggregate_initialization.is_constant = is_constant;

                    break :blk analysis.type.?;
                },
                .structure => |structure| blk: {
                    var is_ordered = true;
                    var is_constant = true;
                    for (aggregate_initialization.names, aggregate_initialization.values, 0..) |field_name, field_value, initialization_index| {
                        const declaration_index = for (structure.fields, 0..) |field, declaration_index| {
                            if (lib.string.equal(field.name, field_name)) {
                                break declaration_index;
                            }
                        } else module.report_error();
                        is_ordered = is_ordered and declaration_index == initialization_index;
                        const field = &structure.fields[declaration_index];
                        const declaration_type = field.type;
                        module.analyze_value_type(field_value, .{ .type = declaration_type });
                        is_constant = is_constant and field_value.is_constant();
                    }

                    aggregate_initialization.is_constant = is_constant and is_ordered;

                    break :blk analysis.type.?;
                },
                .@"union" => |union_type| blk: {
                    if (aggregate_initialization.values.len != 1) {
                        module.report_error();
                    }

                    const initialization_value = aggregate_initialization.values[0];
                    assert(aggregate_initialization.names.len == 1);
                    const initialization_name = aggregate_initialization.names[0];

                    const field = for (union_type.fields) |*field| {
                        if (lib.string.equal(field.name, initialization_name)) {
                            break field;
                        }
                    } else module.report_error();

                    module.analyze_value_type(initialization_value, .{ .type = field.type });

                    break :blk analysis.type.?;
                },
                else => @trap(),
            },
            .enum_literal => |enum_literal| blk: {
                const expected_type = analysis.type orelse module.report_error();
                _ = enum_literal;
                if (expected_type.bb != .enumerator) {
                    module.report_error();
                }
                break :blk expected_type;
            },
            .array_initialization => |*array_initialization| blk: {
                if (analysis.type) |expected_type| switch (expected_type.bb) {
                    .array => |*array| {
                        if (array.element_count == 0) {
                            array.element_count = array_initialization.values.len;
                            assert(lib.string.equal(expected_type.name, ""));
                            expected_type.name = array_type_name(module.arena, array.element_type, array.element_count);
                        } else {
                            if (array.element_count != array_initialization.values.len) {
                                module.report_error();
                            }
                        }

                        var is_constant = true;
                        for (array_initialization.values) |v| {
                            module.analyze_value_type(v, .{
                                .type = array.element_type,
                            });
                            is_constant = is_constant and v.is_constant();
                        }

                        array_initialization.is_constant = is_constant;

                        break :blk switch (value.kind) {
                            .left => module.report_error(), // TODO: possible?
                            .right => expected_type,
                        };
                    },
                    else => module.report_error(),
                } else {
                    if (array_initialization.values.len == 0) {
                        module.report_error();
                    }

                    var expected_type: ?*Type = null;
                    var is_constant = true;

                    for (array_initialization.values) |v| {
                        module.analyze_value_type(v, .{
                            .type = expected_type,
                        });

                        is_constant = is_constant and v.is_constant();

                        if (expected_type) |ty| {
                            if (ty != v.type.?) {
                                module.report_error();
                            }
                        } else {
                            expected_type = v.type.?;
                        }
                    }

                    const element_type = expected_type orelse module.report_error();
                    const element_count = array_initialization.values.len;

                    const array_type = module.get_array_type(element_type, element_count);

                    break :blk switch (value.kind) {
                        .left => module.get_pointer_type(.{ .type = array_type }),
                        .right => array_type,
                    };
                }
            },
            // TODO: further typechecking
            .undefined => analysis.type orelse module.report_error(),
            .string_literal => blk: {
                const slice_type = module.get_slice_type(.{ .type = module.integer_type(8, false) });
                module.typecheck(analysis, slice_type);
                break :blk slice_type;
            },
            // TODO: further typecheck: avoid void, noreturn, etc
            .zero => analysis.type orelse module.report_error(),
            .macro_instantiation => |*macro_instantiation| blk: {
                const current_function = module.current_function orelse module.report_error();
                module.current_function = null;
                defer module.current_function = current_function;

                const current_macro_instantiation = module.current_macro_instantiation;
                assert(current_macro_instantiation == null);
                module.current_macro_instantiation = value;
                defer module.current_macro_instantiation = current_macro_instantiation;

                const declaration = macro_instantiation.declaration;

                macro_instantiation.declaration_arguments = module.arena.allocate(*Local, declaration.arguments.len);

                const local_to_unit = true;
                const is_definition = true;
                const flags: llvm.DI.Flags = .{};
                const subprogram = if (module.has_debug_info) module.llvm.di_builder.create_function(module.scope.llvm.?, macro_instantiation.declaration.name, macro_instantiation.declaration.name, module.llvm.file, macro_instantiation.function_scope.line, null, local_to_unit, is_definition, macro_instantiation.function_scope.line, flags, module.build_mode.is_optimized()) else undefined;
                macro_instantiation.function_scope.llvm = @ptrCast(subprogram);

                for (declaration.arguments, macro_instantiation.declaration_arguments) |old_argument, *new_argument| {
                    const argument = module.locals.add();
                    argument.* = .{
                        .variable = .{
                            .initial_value = undefined,
                            .type = old_argument.variable.type,
                            .scope = &macro_instantiation.function_scope,
                            .name = old_argument.variable.name,
                            .line = old_argument.variable.line,
                            .column = old_argument.variable.column,
                        },
                        .argument_index = old_argument.argument_index,
                    };
                    new_argument.* = argument;
                }

                for (macro_instantiation.type_arguments, declaration.type_arguments) |*instantiation_type_argument_pointer, declaration_type_argument| {
                    assert(declaration_type_argument.bb == .unresolved);
                    const original_instantiation_type_argument = instantiation_type_argument_pointer.*;
                    const instantiation_type_argument = module.types.append(.{
                        .name = declaration_type_argument.name,
                        .bb = .{
                            .alias = .{
                                .type = original_instantiation_type_argument,
                                .line = macro_instantiation.function_scope.line,
                                .scope = &macro_instantiation.function_scope,
                            },
                        },
                    });
                    instantiation_type_argument_pointer.* = instantiation_type_argument;
                }

                macro_instantiation.return_type = module.resolve_type(declaration.return_type);

                for (macro_instantiation.declaration_arguments) |argument| {
                    argument.variable.type = module.resolve_type(argument.variable.type.?);
                }

                if (macro_instantiation.instantiation_arguments.len != declaration.arguments.len) {
                    module.report_error();
                }

                const argument_count = macro_instantiation.declaration_arguments.len;
                if (module.has_debug_info) {
                    for (macro_instantiation.instantiation_arguments, macro_instantiation.declaration_arguments) |instantiation_argument, declaration_argument| {
                        module.analyze_value_type(instantiation_argument, .{ .type = declaration_argument.variable.type.? });
                    }

                    var debug_argument_type_buffer: [64 + 1]*llvm.DI.Type = undefined;
                    const semantic_debug_argument_types = debug_argument_type_buffer[0 .. argument_count + 1];
                    macro_instantiation.return_type.resolve(module);
                    semantic_debug_argument_types[0] = macro_instantiation.return_type.llvm.debug.?;

                    for (macro_instantiation.declaration_arguments, semantic_debug_argument_types[1..][0..argument_count]) |declaration_argument, *debug_argument_type| {
                        declaration_argument.variable.type.?.resolve(module);
                        debug_argument_type.* = declaration_argument.variable.type.?.llvm.debug.?;
                    }

                    module.llvm.builder.set_current_debug_location(null);
                    const subroutine_type_flags = llvm.DI.Flags{};
                    const subroutine_type = module.llvm.di_builder.create_subroutine_type(module.llvm.file, semantic_debug_argument_types, subroutine_type_flags);
                    assert(macro_instantiation.function_scope.llvm != null);
                    subprogram.replace_type(subroutine_type);
                }

                value.bb.macro_instantiation.block = module.lexical_blocks.add();
                module.copy_block(&macro_instantiation.function_scope, .{
                    .source = declaration.block,
                    .destination = value.bb.macro_instantiation.block,
                });

                const result_type = macro_instantiation.return_type;
                result_type.resolve(module);
                module.typecheck(analysis, result_type);

                if (!module.has_debug_info) {
                    for (macro_instantiation.declaration_arguments, macro_instantiation.instantiation_arguments) |declaration_argument, instantiation_argument| {
                        module.analyze_value_type(instantiation_argument, .{ .type = declaration_argument.variable.type });
                    }
                }

                break :blk result_type;
            },
            else => @trap(),
        };

        value.type = value_type;
    }

    pub fn get_enum_name_array_global(module: *Module, enum_type: *Type) *Global {
        switch (enum_type.bb) {
            .enumerator => |*enumerator| {
                if (enumerator.name_array_global) |name_array| {
                    return name_array;
                } else {
                    const fields = enumerator.fields;
                    var name_before: ?*llvm.GlobalVariable = null;
                    var name_constant_buffer: [64]*llvm.Constant = undefined;
                    const uint8 = module.integer_type(8, false);
                    const uint64 = module.integer_type(64, false);
                    uint8.resolve(module);
                    uint64.resolve(module);

                    for (fields, 0..) |field, field_index| {
                        const null_terminate = true;
                        const name_global = module.llvm.module.create_global_variable(.{
                            .type = uint8.llvm.abi.?.get_array_type(field.name.len + @intFromBool(null_terminate)).to_type(),
                            .linkage = .InternalLinkage,
                            .name = module.arena.join_string(&.{ "string.", enum_type.name, ".", field.name }),
                            .initial_value = module.llvm.context.get_constant_string(field.name, null_terminate),
                            .is_constant = true,
                            .before = name_before,
                        });
                        name_before = name_global;

                        const slice_constant = module.llvm.context.get_anonymous_constant_struct(&.{
                            name_global.to_constant(),
                            uint64.llvm.abi.?.to_integer().get_constant(field.name.len, 0).to_constant(),
                        }, false);
                        name_constant_buffer[field_index] = slice_constant;
                    }

                    const slice_struct_type = module.get_slice_type(.{ .type = uint8 });
                    const array_element_count = fields.len;

                    const name_array = slice_struct_type.llvm.abi.?.get_constant_array(name_constant_buffer[0..array_element_count]);

                    const name_array_variable_type = slice_struct_type.llvm.abi.?.get_array_type(array_element_count);

                    const name_array_variable = module.llvm.module.create_global_variable(.{
                        .type = name_array_variable_type.to_type(),
                        .linkage = .InternalLinkage,
                        .initial_value = name_array,
                        .name = "name.array.enum",
                    });
                    name_array_variable.to_value().set_alignment(slice_struct_type.get_byte_alignment());

                    const global_type = module.get_array_type(slice_struct_type, array_element_count);
                    global_type.resolve(module);

                    const storage_type = module.get_pointer_type(.{ .type = global_type });
                    storage_type.resolve(module);

                    const global_storage = module.values.add();
                    global_storage.* = .{
                        .bb = .global,
                        .type = storage_type,
                        .llvm = name_array_variable.to_value(),
                        .kind = .left,
                    };

                    const global = module.globals.add();
                    global.* = .{
                        .variable = .{
                            .storage = global_storage,
                            .initial_value = undefined,
                            .type = global_type,
                            .scope = &module.scope,
                            .name = module.arena.join_string(&.{ "name.array.enum.", enum_type.name }),
                            .line = 0,
                            .column = 0,
                        },
                        .linkage = .internal,
                    };

                    enumerator.name_array_global = global;

                    return global;
                }
            },
            else => unreachable,
        }
    }

    pub fn emit_slice_expression(module: *Module, value: *Value) struct { *llvm.Value, *llvm.Value } {
        const value_type = value.type.?;
        assert(value_type.is_slice());

        const slice_pointer_type = value_type.bb.structure.fields[0].type;
        const slice_element_type = slice_pointer_type.bb.pointer.type;

        const index_type = module.integer_type(64, false);
        index_type.resolve(module);
        const llvm_integer_index_type = index_type.llvm.abi.?.to_integer();
        const index_zero = llvm_integer_index_type.get_constant(0, 0).to_value();

        switch (value.bb) {
            .slice_expression => |slice_expression| {
                assert(slice_expression.array_like.kind == .left);
                module.emit_value(slice_expression.array_like, .memory);

                const pointer_type = slice_expression.array_like.type.?;
                assert(pointer_type.bb == .pointer);
                const sliceable_type = pointer_type.bb.pointer.type;
                const has_start = if (slice_expression.start) |start| switch (start.bb) {
                    .constant_integer => |constant_integer| constant_integer.value != 0,
                    else => true,
                } else false;

                if (slice_expression.start) |start| {
                    module.emit_value(start, .memory);
                }

                if (slice_expression.end) |end| {
                    module.emit_value(end, .memory);
                }

                switch (sliceable_type.bb) {
                    .pointer => |pointer| {
                        const pointer_load = module.create_load(.{
                            .type = sliceable_type,
                            .value = slice_expression.array_like.llvm.?,
                        });
                        const slice_pointer = switch (has_start) {
                            true => module.llvm.builder.create_gep(.{
                                .type = pointer.type.llvm.memory.?,
                                .aggregate = pointer_load,
                                .indices = &.{slice_expression.start.?.llvm.?},
                            }),
                            false => pointer_load,
                        };
                        const slice_length = if (has_start) module.llvm.builder.create_sub(slice_expression.end.?.llvm.?, slice_expression.start.?.llvm.?) else slice_expression.end.?.llvm.?;
                        return .{ slice_pointer, slice_length };
                    },
                    .structure => |structure| {
                        assert(structure.is_slice);

                        const slice_load = module.create_load(.{
                            .type = sliceable_type,
                            .value = slice_expression.array_like.llvm.?,
                        });
                        const old_slice_pointer = module.llvm.builder.create_extract_value(slice_load, 0);

                        const slice_pointer = switch (has_start) {
                            true => module.llvm.builder.create_gep(.{
                                .type = slice_element_type.llvm.memory.?,
                                .aggregate = old_slice_pointer,
                                .indices = &.{slice_expression.start.?.llvm.?},
                            }),
                            false => old_slice_pointer,
                        };

                        const slice_end = if (slice_expression.end) |end| end.llvm.? else module.llvm.builder.create_extract_value(slice_load, 1);
                        const slice_length = if (has_start) module.llvm.builder.create_sub(slice_end, slice_expression.start.?.llvm.?) else slice_end;

                        return .{ slice_pointer, slice_length };
                    },
                    .array => |array| {
                        assert(array.element_type == slice_element_type);
                        const slice_pointer = switch (has_start) {
                            true => module.llvm.builder.create_gep(.{
                                .type = sliceable_type.llvm.memory.?,
                                .aggregate = slice_expression.array_like.llvm.?,
                                .indices = &.{ index_zero, slice_expression.start.?.llvm.? },
                            }),
                            false => slice_expression.array_like.llvm.?,
                        };

                        const slice_length = if (has_start) {
                            @trap();
                        } else if (slice_expression.end) |end| end.llvm.? else llvm_integer_index_type.get_constant(array.element_count, 0).to_value();

                        return .{ slice_pointer, slice_length };
                    },
                    else => @trap(),
                }
            },
            else => unreachable,
        }
    }

    pub fn emit_value(module: *Module, value: *Value, type_kind: Type.Kind) void {
        const value_type = value.type orelse unreachable;
        const resolved_type = module.fully_resolve_alias(value_type);
        assert(value.llvm == null);
        value_type.resolve(module);

        const must_be_constant = module.current_function == null and module.current_macro_instantiation == null;

        const llvm_value: *llvm.Value = switch (value.bb) {
            .constant_integer => |constant_integer| value_type.get_llvm(type_kind).to_integer().get_constant(constant_integer.value, @intFromBool(constant_integer.signed)).to_value(),
            .unary => |unary| switch (unary.id) {
                .@"-" => blk: {
                    const unary_value = unary.value.llvm orelse b: {
                        module.emit_value(unary.value, type_kind);
                        break :b unary.value.llvm orelse unreachable;
                    };
                    break :blk module.negate_llvm_value(unary_value, unary.value.is_constant());
                },
                .@"&" => blk: {
                    assert(value_type == unary.value.type);
                    module.emit_value(unary.value, type_kind);
                    break :blk unary.value.llvm orelse unreachable;
                },
                .@"!" => switch (unary.value.type == value_type) {
                    true => b: {
                        module.emit_value(unary.value, type_kind);
                        break :b module.llvm.builder.create_not(unary.value.llvm.?);
                    },
                    false => switch (unary.value.type.?.bb) {
                        .pointer => b: {
                            module.emit_value(unary.value, type_kind);
                            break :b module.llvm.builder.create_integer_compare(.eq, unary.value.llvm.?, unary.value.type.?.llvm.abi.?.get_zero().to_value());
                        },
                        else => @trap(),
                    },
                },
                .@"~" => b: {
                    module.emit_value(unary.value, type_kind);
                    break :b module.llvm.builder.create_not(unary.value.llvm.?);
                },
                else => @trap(),
            },
            .binary => |binary| blk: {
                if (binary.id.is_shortcircuiting()) {
                    const ShortcircuitingOperation = enum {
                        @"and",
                        @"or",
                    };
                    const op: ShortcircuitingOperation = switch (binary.id) {
                        .@"and?" => .@"and",
                        .@"or?" => .@"or",
                        else => unreachable,
                    };
                    const left = if (binary.left.llvm) |left_llvm| left_llvm else b: {
                        module.emit_value(binary.left, .abi);
                        break :b binary.left.llvm orelse unreachable;
                    };
                    const left_condition = switch (binary.left.type.?.bb) {
                        .integer => |integer| switch (integer.bit_count) {
                            1 => left,
                            else => @trap(),
                        },
                        else => @trap(),
                    };
                    const llvm_function = module.current_function.?.variable.storage.?.llvm.?.to_function();
                    const current_bb = module.llvm.builder.get_insert_block().?;
                    const right_block = module.llvm.context.create_basic_block(switch (op) {
                        inline else => |o| @tagName(o) ++ ".right",
                    }, llvm_function);
                    const end_block = module.llvm.context.create_basic_block(switch (op) {
                        inline else => |o| @tagName(o) ++ ".end",
                    }, llvm_function);
                    _ = module.llvm.builder.create_conditional_branch(left_condition, switch (op) {
                        .@"and" => right_block,
                        .@"or" => end_block,
                    }, switch (op) {
                        .@"and" => end_block,
                        .@"or" => right_block,
                    });

                    module.llvm.builder.position_at_end(right_block);
                    const right = if (binary.right.llvm) |right_llvm| right_llvm else b: {
                        module.emit_value(binary.right, .abi);
                        break :b binary.right.llvm orelse unreachable;
                    };
                    const right_condition = switch (binary.left.type.?.bb) {
                        .integer => |integer| switch (integer.bit_count) {
                            1 => right,
                            else => @trap(),
                        },
                        else => @trap(),
                    };
                    _ = module.llvm.builder.create_branch(end_block);
                    module.llvm.builder.position_at_end(end_block);
                    const boolean_type = module.integer_type(1, false).llvm.abi.?;

                    const phi = module.llvm.builder.create_phi(boolean_type);
                    phi.add_incoming(&.{ switch (op) {
                        .@"and" => boolean_type.get_zero().to_value(),
                        .@"or" => boolean_type.to_integer().get_constant(1, 0).to_value(),
                    }, right_condition }, &.{ current_bb, right_block });

                    break :blk switch (type_kind) {
                        .abi => phi.to_value(),
                        .memory => @trap(),
                    };
                } else {
                    const left = if (binary.left.llvm) |left_llvm| left_llvm else b: {
                        module.emit_value(binary.left, .abi);
                        break :b binary.left.llvm orelse unreachable;
                    };
                    const right = if (binary.right.llvm) |right_llvm| right_llvm else b: {
                        module.emit_value(binary.right, .abi);
                        break :b binary.right.llvm orelse unreachable;
                    };
                    const result = switch (resolved_type.bb) {
                        .integer => |integer| switch (binary.id) {
                            .@"+" => module.llvm.builder.create_add(left, right),
                            .@"-" => module.llvm.builder.create_sub(left, right),
                            .@"*" => module.llvm.builder.create_mul(left, right),
                            .@"/" => switch (integer.signed) {
                                true => module.llvm.builder.create_sdiv(left, right),
                                false => module.llvm.builder.create_udiv(left, right),
                            },
                            .@"%" => switch (integer.signed) {
                                true => module.llvm.builder.create_srem(left, right),
                                false => module.llvm.builder.create_urem(left, right),
                            },
                            .@"&", .@"and" => module.llvm.builder.create_and(left, right),
                            .@"|", .@"or" => module.llvm.builder.create_or(left, right),
                            .@"^" => module.llvm.builder.create_xor(left, right),
                            .@"<<" => module.llvm.builder.create_shl(left, right),
                            .@">>" => switch (integer.signed) {
                                true => module.llvm.builder.create_ashr(left, right),
                                false => module.llvm.builder.create_lshr(left, right),
                            },
                            .@"==" => module.llvm.builder.create_integer_compare(.eq, left, right),
                            .@"!=" => module.llvm.builder.create_integer_compare(.ne, left, right),
                            .@">" => switch (integer.signed) {
                                true => module.llvm.builder.create_integer_compare(.sgt, left, right),
                                false => module.llvm.builder.create_integer_compare(.ugt, left, right),
                            },
                            .@"<" => switch (integer.signed) {
                                true => module.llvm.builder.create_integer_compare(.slt, left, right),
                                false => module.llvm.builder.create_integer_compare(.ult, left, right),
                            },
                            .@">=" => switch (integer.signed) {
                                true => module.llvm.builder.create_integer_compare(.sge, left, right),
                                false => module.llvm.builder.create_integer_compare(.uge, left, right),
                            },
                            .@"<=" => switch (integer.signed) {
                                true => module.llvm.builder.create_integer_compare(.sle, left, right),
                                false => module.llvm.builder.create_integer_compare(.ule, left, right),
                            },
                            else => module.report_error(),
                        },
                        .pointer => |pointer| switch (b: {
                            pointer.type.resolve(module);
                            break :b binary.id;
                        }) {
                            .@"+" => module.llvm.builder.create_gep(.{
                                .type = pointer.type.llvm.abi.?,
                                .aggregate = left,
                                .indices = &.{right},
                            }),
                            .@"-" => module.llvm.builder.create_gep(.{
                                .type = pointer.type.llvm.abi.?,
                                .aggregate = left,
                                .indices = &.{module.negate_llvm_value(right, binary.right.is_constant())},
                            }),
                            else => module.report_error(),
                        },
                        else => @trap(),
                    };
                    break :blk result;
                }
            },
            .variable_reference => |variable| switch (value.kind) {
                .left => switch (variable.storage.?.type == value_type) {
                    true => variable.storage.?.llvm.?,
                    false => switch (value_type.bb) {
                        .structure => |structure| switch (structure.is_slice) {
                            true => switch (variable.storage.?.type.?.bb) {
                                .pointer => |pointer| switch (pointer.type.bb) {
                                    .array => |array| blk: {
                                        value.kind = .right; // TODO: TODO: TODO: WARN: is this wise?
                                        const slice_poison = value_type.llvm.memory.?.get_poison();
                                        const uint64 = module.integer_type(64, false);
                                        uint64.resolve(module);
                                        const pointer_insert = module.llvm.builder.create_insert_value(slice_poison, variable.storage.?.llvm.?, 0);
                                        const length_insert = module.llvm.builder.create_insert_value(pointer_insert, uint64.llvm.abi.?.to_integer().get_constant(array.element_count, @intFromBool(false)).to_value(), 1);
                                        const slice_value = length_insert;
                                        break :blk slice_value;
                                    },
                                    else => @trap(),
                                },
                                else => @trap(),
                            },
                            false => @trap(),
                        },
                        else => module.report_error(),
                    },
                },
                .right => switch (variable.type == value_type) {
                    true => switch (must_be_constant) {
                        true => b: {
                            if (variable.scope.kind != .global) {
                                module.report_error();
                            }
                            break :b variable.initial_value.llvm.?;
                        },
                        false => switch (value_type.get_evaluation_kind()) {
                            .scalar => module.create_load(.{
                                .type = value_type,
                                .value = variable.storage.?.llvm.?,
                                .alignment = variable.storage.?.type.?.bb.pointer.alignment,
                            }),
                            // TODO: this might be wrong
                            .aggregate => module.create_load(.{
                                .type = value_type,
                                .value = variable.storage.?.llvm.?,
                                .alignment = variable.storage.?.type.?.bb.pointer.alignment,
                            }),
                            .complex => @trap(),
                        },
                    },
                    false => module.report_error(),
                },
            },
            .intrinsic => |intrinsic| switch (intrinsic) {
                .alignof => |ty| blk: {
                    const alignment = ty.get_byte_alignment();
                    const constant_integer = value_type.llvm.abi.?.to_integer().get_constant(alignment, @intFromBool(false));
                    break :blk constant_integer.to_value();
                },
                .byte_size => |ty| blk: {
                    const byte_size = ty.get_byte_size();
                    const constant_integer = value_type.llvm.abi.?.to_integer().get_constant(byte_size, @intFromBool(false));
                    break :blk constant_integer.to_value();
                },
                .enum_name => |enum_value| blk: {
                    const enum_type = enum_value.type.?;
                    const enum_to_string = enum_type.bb.enumerator.enum_to_string.?;
                    module.emit_value(enum_value, .abi);
                    const call = module.llvm.builder.create_call(enum_to_string.get_type(), enum_to_string.to_value(), &.{enum_value.llvm.?});
                    call.to_instruction().to_call_base().set_calling_convention(.fast);
                    break :blk call;
                },
                .extend => |extended_value| blk: {
                    if (extended_value.llvm == null) {
                        module.emit_value(extended_value, type_kind);
                    }
                    const llvm_value = extended_value.llvm orelse unreachable;
                    const destination_type = value_type.llvm.abi.?;
                    const extension_type = switch (extended_value.type.?.bb) {
                        .alias => |alias| alias.type,
                        else => extended_value.type.?,
                    };
                    const extension_instruction = switch (extension_type.bb.integer.signed) {
                        true => module.llvm.builder.create_sign_extend(llvm_value, destination_type),
                        false => module.llvm.builder.create_zero_extend(llvm_value, destination_type),
                    };
                    break :blk extension_instruction;
                },
                .integer_max => |max_type| blk: {
                    max_type.resolve(module);
                    const bit_count = max_type.bb.integer.bit_count;
                    const max_value = if (bit_count == 64) ~@as(u64, 0) else (@as(u64, 1) << @intCast(bit_count - @intFromBool(max_type.bb.integer.signed))) - 1;
                    const constant_integer = value_type.llvm.abi.?.to_integer().get_constant(max_value, @intFromBool(false));
                    break :blk constant_integer.to_value();
                },
                .int_from_enum => |enum_value| blk: {
                    module.emit_value(enum_value, type_kind);
                    break :blk enum_value.llvm.?;
                },
                .int_from_pointer => |pointer_value| blk: {
                    module.emit_value(pointer_value, type_kind);
                    const int = module.llvm.builder.create_ptr_to_int(pointer_value.llvm.?, value_type.llvm.abi.?);
                    break :blk int;
                },
                .pointer_cast => |pointer_value| blk: {
                    module.emit_value(pointer_value, type_kind);
                    break :blk pointer_value.llvm.?;
                },
                .select => |select| blk: {
                    module.emit_value(select.condition, type_kind);
                    const condition = switch (select.condition.type.?.bb) {
                        .integer => |integer| switch (integer.bit_count) {
                            1 => select.condition.llvm.?,
                            else => @trap(),
                        },
                        else => @trap(),
                    };
                    module.emit_value(select.true_value, type_kind);
                    module.emit_value(select.false_value, type_kind);
                    const result = module.llvm.builder.create_select(condition, select.true_value.llvm.?, select.false_value.llvm.?);
                    break :blk result;
                },
                .string_to_enum => |string_to_enum| blk: {
                    module.emit_value(string_to_enum.string_value, type_kind);
                    const s2e = string_to_enum.enum_type.bb.enumerator.string_to_enum orelse unreachable;
                    const first_field = module.llvm.builder.create_extract_value(string_to_enum.string_value.llvm.?, 0);
                    const second_field = module.llvm.builder.create_extract_value(string_to_enum.string_value.llvm.?, 1);
                    const call = module.llvm.builder.create_call(s2e.function.get_type(), s2e.function.to_value(), &.{ first_field, second_field });
                    call.to_instruction().to_call_base().set_calling_convention(.fast);
                    break :blk call;
                },
                .trap => blk: {
                    // TODO: lookup in advance
                    const intrinsic_id = module.llvm.intrinsic_table.trap;
                    const argument_types: []const *llvm.Type = &.{};
                    const argument_values: []const *llvm.Value = &.{};
                    const intrinsic_function = module.llvm.module.get_intrinsic_declaration(intrinsic_id, argument_types);
                    const intrinsic_function_type = module.llvm.context.get_intrinsic_type(intrinsic_id, argument_types);
                    const llvm_call = module.llvm.builder.create_call(intrinsic_function_type, intrinsic_function, argument_values);
                    _ = module.llvm.builder.create_unreachable();
                    module.llvm.builder.clear_insertion_position();

                    break :blk llvm_call;
                },
                .truncate => |value_to_truncate| blk: {
                    if (value_to_truncate.llvm == null) {
                        module.emit_value(value_to_truncate, type_kind);
                    }
                    const llvm_value = value_to_truncate.llvm orelse unreachable;
                    const truncate = module.llvm.builder.create_truncate(llvm_value, value_type.llvm.abi.?);
                    break :blk truncate;
                },
                .va_arg => module.emit_va_arg(value, null, null),
                .va_end => |va_list| blk: {
                    module.emit_value(va_list, .memory);

                    const intrinsic_id = module.llvm.intrinsic_table.va_end;
                    const argument_types: []const *llvm.Type = &.{module.llvm.pointer_type};
                    const intrinsic_function = module.llvm.module.get_intrinsic_declaration(intrinsic_id, argument_types);
                    const intrinsic_function_type = module.llvm.context.get_intrinsic_type(intrinsic_id, argument_types);
                    const argument_values: []const *llvm.Value = &.{va_list.llvm.?};
                    const llvm_value = module.llvm.builder.create_call(intrinsic_function_type, intrinsic_function, argument_values);
                    break :blk llvm_value;
                },
                else => @trap(),
            },
            .dereference => |dereferenceable_value| blk: {
                module.emit_value(dereferenceable_value, .memory);
                const result = switch (value.kind) {
                    .left => @trap(),
                    .right => module.create_load(.{
                        .type = dereferenceable_value.type.?.bb.pointer.type,
                        .value = dereferenceable_value.llvm.?,
                        .alignment = dereferenceable_value.type.?.bb.pointer.alignment,
                    }),
                };
                break :blk result;
            },
            .call => module.emit_call(value, null, null),
            .array_initialization => |array_initialization| switch (array_initialization.is_constant) {
                true => blk: {
                    assert(value.kind == .right);
                    var llvm_value_buffer: [64]*llvm.Constant = undefined;
                    const element_count = array_initialization.values.len;
                    const llvm_values = llvm_value_buffer[0..element_count];

                    for (array_initialization.values, llvm_values) |v, *llvm_value| {
                        module.emit_value(v, .memory);
                        llvm_value.* = v.llvm.?.to_constant();
                    }

                    value_type.bb.array.element_type.resolve(module);

                    const array_value = value_type.bb.array.element_type.llvm.memory.?.get_constant_array(llvm_values);
                    break :blk array_value.to_value();
                },
                false => switch (value.kind) {
                    .left => blk: {
                        const array_type = value_type.bb.pointer.type;
                        const alloca = module.create_alloca(.{
                            .type = array_type,
                        });

                        const pointer_to_element_type = module.get_pointer_type(.{ .type = array_type.bb.array.element_type });
                        const uint64 = module.integer_type(64, false).llvm.abi.?.to_integer();
                        const u64_zero = uint64.get_constant(0, 0).to_value();

                        for (array_initialization.values, 0..) |v, i| {
                            const alloca_gep = module.llvm.builder.create_gep(.{
                                .type = array_type.llvm.memory.?,
                                .aggregate = alloca,
                                .indices = &.{ u64_zero, uint64.get_constant(i, 0).to_value() },
                            });
                            module.emit_assignment(alloca_gep, pointer_to_element_type, v);
                        }

                        break :blk alloca;
                    },
                    .right => @trap(),
                },
            },
            .array_expression => |array_expression| switch (array_expression.array_like.kind) {
                .left => switch (array_expression.array_like.type.?.bb) {
                    .pointer => |pointer| switch (pointer.type.bb) {
                        .array => |array| blk: {
                            module.emit_value(array_expression.array_like, .memory);
                            module.emit_value(array_expression.index, .memory);
                            const uint64 = module.integer_type(64, false);
                            uint64.resolve(module);
                            const zero_index = uint64.llvm.abi.?.to_integer().get_constant(0, @intFromBool(false)).to_value();
                            const gep = module.llvm.builder.create_gep(.{
                                .type = pointer.type.llvm.memory.?,
                                .aggregate = array_expression.array_like.llvm.?,
                                .indices = &.{ zero_index, array_expression.index.llvm.? },
                            });

                            const v = switch (value.kind) {
                                .left => gep,
                                .right => module.create_load(.{ .type = array.element_type, .value = gep }),
                            };

                            break :blk v;
                        },
                        .structure => |structure| blk: {
                            assert(structure.is_slice);
                            module.emit_value(array_expression.array_like, .memory);
                            module.emit_value(array_expression.index, .memory);
                            const pointer_type = structure.fields[0].type;
                            const element_type = pointer_type.bb.pointer.type;
                            element_type.resolve(module);
                            const pointer_load = module.create_load(.{ .type = structure.fields[0].type, .value = array_expression.array_like.llvm.? });
                            const gep = module.llvm.builder.create_gep(.{
                                .type = element_type.llvm.memory.?,
                                .aggregate = pointer_load,
                                .indices = &.{array_expression.index.llvm.?},
                            });

                            break :blk switch (value.kind) {
                                .left => gep,
                                .right => module.create_load(.{
                                    .type = element_type,
                                    .value = gep,
                                }),
                            };
                        },
                        .pointer => |real_pointer| blk: {
                            module.emit_value(array_expression.array_like, .memory);
                            module.emit_value(array_expression.index, .memory);
                            // TODO: consider not emitting the and doing straight GEP?
                            const pointer_load = module.create_load(.{ .type = pointer.type, .value = array_expression.array_like.llvm.? });
                            const element_type = real_pointer.type;
                            const gep = module.llvm.builder.create_gep(.{
                                .type = element_type.llvm.memory.?,
                                .aggregate = pointer_load,
                                .indices = &.{array_expression.index.llvm.?},
                            });
                            break :blk switch (value.kind) {
                                .left => gep,
                                .right => module.create_load(.{
                                    .type = element_type,
                                    .value = gep,
                                }),
                            };
                        },
                        else => @trap(),
                    },
                    else => unreachable,
                },
                .right => switch (array_expression.array_like.type.?.bb) {
                    .pointer => |pointer| blk: {
                        module.emit_value(array_expression.array_like, .memory);
                        module.emit_value(array_expression.index, .memory);
                        const gep = module.llvm.builder.create_gep(.{
                            .type = pointer.type.llvm.memory.?,
                            .aggregate = array_expression.array_like.llvm.?,
                            .indices = &.{array_expression.index.llvm.?},
                        });
                        const v = switch (value.kind) {
                            .left => gep,
                            .right => module.create_load(.{ .type = pointer.type, .value = gep }),
                        };

                        break :blk v;
                    },
                    .structure => |structure| switch (structure.is_slice) {
                        true => blk: {
                            module.emit_value(array_expression.array_like, .memory);
                            module.emit_value(array_expression.index, .memory);
                            const pointer_extract = module.llvm.builder.create_extract_value(array_expression.array_like.llvm.?, 0);
                            const element_type = structure.fields[0].type.bb.pointer.type;
                            const gep = module.llvm.builder.create_gep(.{
                                .type = element_type.llvm.memory.?,
                                .aggregate = pointer_extract,
                                .indices = &.{array_expression.index.llvm.?},
                            });
                            const v = switch (value.kind) {
                                .left => gep,
                                .right => module.create_load(.{ .type = element_type, .value = gep }),
                            };

                            break :blk v;
                        },
                        false => module.report_error(),
                    },
                    else => @trap(),
                },
            },
            .enum_literal => |enum_literal_name| blk: {
                const enum_int_value = for (value_type.bb.enumerator.fields) |*field| {
                    if (lib.string.equal(enum_literal_name, field.name)) {
                        break field.value;
                    }
                } else module.report_error();
                const llvm_value = value_type.get_llvm(type_kind).to_integer().get_constant(enum_int_value, @intFromBool(false));
                break :blk llvm_value.to_value();
            },
            .field_access => |field_access| blk: {
                module.emit_value(field_access.aggregate, .memory);
                const field_name = field_access.field;
                switch (field_access.aggregate.kind) {
                    .left => {
                        const base_type = field_access.aggregate.type.?;
                        assert(base_type.bb == .pointer);
                        const pointer_type = switch (base_type.bb.pointer.type.bb) {
                            .pointer => base_type.bb.pointer.type,
                            else => base_type,
                        };
                        const ty = pointer_type.bb.pointer.type;
                        ty.resolve(module);
                        const child_resolved_type = module.fully_resolve_alias(ty);
                        const v = switch (pointer_type == base_type) {
                            false => module.create_load(.{ .type = pointer_type, .value = field_access.aggregate.llvm.? }),
                            true => field_access.aggregate.llvm.?,
                        };

                        switch (child_resolved_type.bb) {
                            .structure => |structure| {
                                const field_index: u32 = for (structure.fields, 0..) |field, field_index| {
                                    if (lib.string.equal(field_name, field.name)) {
                                        break @intCast(field_index);
                                    }
                                } else module.report_error();

                                const gep = module.llvm.builder.create_struct_gep(ty.llvm.memory.?.to_struct(), v, field_index);
                                break :blk switch (value.kind) {
                                    .left => gep,
                                    .right => module.create_load(.{
                                        .type = structure.fields[field_index].type,
                                        .value = gep,
                                    }),
                                };
                            },
                            .@"union" => |union_type| {
                                const field_value_type = for (union_type.fields) |field| {
                                    if (lib.string.equal(field_name, field.name)) {
                                        break field.type;
                                    }
                                } else unreachable;

                                const biggest_field_type = union_type.fields[union_type.biggest_field].type;

                                const struct_type = if (field_value_type.is_abi_equal(biggest_field_type, module)) ty.llvm.memory.?.to_struct() else module.llvm.context.get_struct_type(&.{field_value_type.llvm.memory.?});
                                const gep = module.llvm.builder.create_struct_gep(struct_type, v, 0);
                                break :blk switch (value.kind) {
                                    .left => gep,
                                    .right => module.create_load(.{
                                        .type = field_value_type,
                                        .value = gep,
                                    }),
                                };
                            },
                            .bits => |bits| {
                                const field_index: u32 = for (bits.fields, 0..) |field, field_index| {
                                    if (lib.string.equal(field_name, field.name)) {
                                        break @intCast(field_index);
                                    }
                                } else module.report_error();
                                const field = bits.fields[field_index];
                                field.type.resolve(module);

                                const load = module.create_load(.{ .type = ty, .alignment = pointer_type.bb.pointer.alignment, .value = v });
                                const shift = module.llvm.builder.create_lshr(load, bits.backing_type.llvm.abi.?.to_integer().get_constant(field.bit_offset, 0).to_value());
                                const trunc = module.llvm.builder.create_truncate(shift, field.type.llvm.abi.?);
                                break :blk trunc;
                            },
                            .array => |array| break :blk value_type.get_llvm(type_kind).to_integer().get_constant(array.element_count, 0).to_value(),
                            else => @trap(),
                        }
                    },
                    .right => switch (field_access.aggregate.type.?.bb) {
                        else => @trap(),
                    },
                }
            },
            .aggregate_initialization => |aggregate_initialization| switch (module.fully_resolve_alias(value_type).bb) {
                .bits => |bits| switch (aggregate_initialization.is_constant) {
                    true => blk: {
                        var bits_value: u64 = 0;
                        for (aggregate_initialization.names, aggregate_initialization.values) |field_name, field_value| {
                            const declaration_index = for (bits.fields, 0..) |field, declaration_index| {
                                if (lib.string.equal(field_name, field.name)) {
                                    break declaration_index;
                                }
                            } else unreachable;
                            const field = &bits.fields[declaration_index];

                            const fv = switch (field_value.bb) {
                                .constant_integer => |ci| ci.value,
                                else => @trap(),
                            };
                            bits_value |= fv << @intCast(field.bit_offset);
                        }

                        bits.backing_type.resolve(module);
                        const llvm_value = bits.backing_type.llvm.abi.?.to_integer().get_constant(bits_value, @intFromBool(false));
                        break :blk llvm_value.to_value();
                    },
                    false => blk: {
                        bits.backing_type.resolve(module);
                        const llvm_type = bits.backing_type.llvm.abi.?;
                        const zero_value = llvm_type.get_zero();
                        var result = zero_value.to_value();
                        for (aggregate_initialization.names, aggregate_initialization.values) |field_name, field_value| {
                            const declaration_index = for (bits.fields, 0..) |field, declaration_index| {
                                if (lib.string.equal(field_name, field.name)) {
                                    break declaration_index;
                                }
                            } else unreachable;
                            const field = &bits.fields[declaration_index];
                            module.emit_value(field_value, .memory);
                            const extended = module.llvm.builder.create_zero_extend(field_value.llvm.?, llvm_type);
                            const shl = module.llvm.builder.create_shl(extended, llvm_type.to_integer().get_constant(field.bit_offset, 0).to_value());
                            const or_value = module.llvm.builder.create_or(result, shl);
                            result = or_value;
                        }
                        break :blk result;
                    },
                },
                .structure => |structure| switch (aggregate_initialization.is_constant) {
                    true => blk: {
                        var constant_buffer: [64]*llvm.Constant = undefined;
                        const constants = constant_buffer[0..structure.fields.len];

                        for (aggregate_initialization.values, constants[0..aggregate_initialization.values.len]) |field_value, *constant| {
                            module.emit_value(field_value, .memory);
                            constant.* = field_value.llvm.?.to_constant();
                        }

                        if (aggregate_initialization.zero) {
                            if (aggregate_initialization.values.len == structure.fields.len) {
                                module.report_error();
                            }

                            for (constants[aggregate_initialization.values.len..], structure.fields[aggregate_initialization.values.len..]) |*constant, *field| {
                                field.type.resolve(module);
                                constant.* = field.type.llvm.memory.?.get_zero();
                            }
                        }
                        const constant_struct = value_type.llvm.abi.?.to_struct().get_constant(constants);
                        break :blk constant_struct.to_value();
                    },
                    false => {
                        @trap();
                    },
                },
                .pointer => module.report_error(),
                else => @trap(),
            },
            .zero => value_type.llvm.abi.?.get_zero().to_value(),
            .@"unreachable" => b: {
                const unreachable_value = module.llvm.builder.create_unreachable();
                module.llvm.builder.clear_insertion_position();
                break :b unreachable_value;
            },
            .slice_expression => blk: {
                assert(value.kind == .right);
                const slice_values = module.emit_slice_expression(value);
                const slice_poison = value_type.llvm.memory.?.get_poison();
                const slice_pointer = module.llvm.builder.create_insert_value(slice_poison, slice_values[0], 0);
                const slice_length = module.llvm.builder.create_insert_value(slice_pointer, slice_values[1], 1);
                const slice_value = slice_length;
                break :blk slice_value;
            },
            .undefined => value_type.llvm.abi.?.get_poison(),
            .string_literal => |string_literal| blk: {
                const null_terminate = true;
                const constant_string = module.llvm.context.get_constant_string(string_literal, null_terminate);

                const u8_type = module.integer_type(8, false);
                u8_type.resolve(module);
                const global_variable = module.llvm.module.create_global_variable(.{
                    .linkage = .InternalLinkage,
                    .name = "conststring",
                    .initial_value = constant_string,
                    .type = u8_type.llvm.abi.?.get_array_type(string_literal.len + @intFromBool(null_terminate)).to_type(),
                });
                global_variable.set_unnamed_address(.global);

                const slice_type = module.get_slice_type(.{
                    .type = u8_type,
                });
                assert(value_type == slice_type);
                slice_type.resolve(module);
                const slice_poison = slice_type.llvm.abi.?.get_poison();
                const slice_pointer = module.llvm.builder.create_insert_value(slice_poison, global_variable.to_value(), 0);
                const uint64 = module.integer_type(64, false);
                uint64.resolve(module);
                const slice_length = module.llvm.builder.create_insert_value(slice_pointer, uint64.llvm.abi.?.to_integer().get_constant(string_literal.len, 0).to_value(), 1);
                const slice_value = slice_length;
                break :blk slice_value;
            },
            .macro_instantiation => |*macro_instantiation| blk: {
                const current_function = module.current_function orelse module.report_error();
                module.current_function = null;
                defer module.current_function = current_function;

                const current_macro_instantiation = module.current_macro_instantiation;
                assert(current_macro_instantiation == null);
                module.current_macro_instantiation = value;
                defer module.current_macro_instantiation = current_macro_instantiation;

                for (macro_instantiation.instantiation_arguments) |call_argument| {
                    module.emit_value(call_argument, .abi);
                }

                const caller_debug_location = if (module.has_debug_info) llvm.DI.create_debug_location(module.llvm.context, macro_instantiation.instantiation_line, macro_instantiation.instantiation_column, macro_instantiation.function_scope.parent.?.llvm.?, null) else undefined;
                defer if (module.has_debug_info) {
                    module.llvm.builder.set_current_debug_location(caller_debug_location);
                };
                module.inline_at_debug_location = caller_debug_location;
                defer module.inline_at_debug_location = null;

                const llvm_function = current_function.variable.storage.?.llvm.?.to_function();
                const macro_entry_block = module.llvm.context.create_basic_block("macro.entry", llvm_function);
                _ = module.llvm.builder.create_branch(macro_entry_block);
                module.llvm.builder.position_at_end(macro_entry_block);

                const valid_return_value = switch (macro_instantiation.return_type.bb) {
                    .void, .noreturn => false,
                    else => true,
                };

                macro_instantiation.return_alloca = if (valid_return_value) module.create_alloca(.{
                    .type = macro_instantiation.return_type,
                    .name = "macro.return",
                }) else undefined;

                const macro_return_block = module.llvm.context.create_basic_block("macro.return_block", llvm_function);
                macro_instantiation.return_block = macro_return_block;

                for (macro_instantiation.instantiation_arguments, macro_instantiation.declaration_arguments) |call_argument, declaration_argument| {
                    module.emit_local_storage(declaration_argument);
                    const storage = declaration_argument.variable.storage.?.llvm.?;

                    switch (declaration_argument.variable.type.?.get_evaluation_kind()) {
                        .scalar => {
                            _ = module.create_store(.{
                                .source_value = call_argument.llvm.?,
                                .destination_value = storage,
                                .type = declaration_argument.variable.type.?,
                            });
                        },
                        .aggregate => @trap(),
                        .complex => @trap(),
                    }
                }

                module.analyze_block(macro_instantiation.block);

                if (module.llvm.builder.get_insert_block() != null) {
                    _ = module.llvm.builder.create_branch(macro_return_block);
                }

                module.llvm.builder.position_at_end(macro_return_block);

                const load = switch (valid_return_value) {
                    true => module.create_load(.{
                        .type = macro_instantiation.return_type,
                        .value = macro_instantiation.return_alloca,
                        .type_kind = type_kind,
                    }),
                    false => return,
                };
                break :blk load;
            },
            else => @trap(),
        };

        value.llvm = llvm_value;
    }

    pub fn analyze_statement(module: *Module, scope: *Scope, statement: *Statement, last_line: *u32, last_column: *u32, last_statement_debug_location: **llvm.DI.Location) void {
        const parent_function_global = if (module.current_function) |cf| cf else if (module.current_macro_instantiation) |mi| mi.bb.macro_instantiation.function else module.report_error();
        const llvm_function = parent_function_global.variable.storage.?.llvm.?.to_function();
        if (module.has_debug_info) {
            if (statement.line != last_line.* or statement.column != last_column.*) {
                const inlined_at: ?*llvm.DI.Metadata = @ptrCast(module.inline_at_debug_location);
                last_statement_debug_location.* = llvm.DI.create_debug_location(module.llvm.context, statement.line, statement.column, scope.llvm.?, inlined_at);
                module.llvm.builder.set_current_debug_location(last_statement_debug_location.*);
                last_line.* = statement.line;
                last_column.* = statement.column;
            }
        }

        switch (statement.bb) {
            .@"return" => |rv| {
                if (module.current_function != null) {
                    const function_type = parent_function_global.variable.storage.?.type.?.bb.pointer.type.bb.function;
                    const return_abi = function_type.return_abi;

                    switch (return_abi.semantic_type.bb) {
                        .void => {
                            if (rv != null) {
                                module.report_error();
                            }
                        },
                        .noreturn => module.report_error(),
                        else => {
                            const return_value = rv orelse module.report_error();
                            module.analyze(return_value, .{
                                .type = return_abi.semantic_type,
                            }, .memory);

                            if (module.has_debug_info) {
                                module.llvm.builder.set_current_debug_location(last_statement_debug_location.*);
                            }

                            // Clang equivalent: CodeGenFunction::EmitReturnStmt
                            const return_alloca = module.current_function.?.variable.storage.?.bb.function.return_alloca orelse module.report_error();

                            switch (return_abi.semantic_type.get_evaluation_kind()) {
                                .scalar => {
                                    switch (return_abi.flags.kind) {
                                        .indirect => {
                                            @trap();
                                        },
                                        else => {
                                            // assert(!return_value.?.lvalue);
                                            assert(return_value.type.?.is_abi_equal(return_abi.semantic_type, module));
                                            _ = module.create_store(.{
                                                .source_value = return_value.llvm.?,
                                                .destination_value = return_alloca,
                                                .type = return_abi.semantic_type,
                                            });
                                        },
                                    }
                                },
                                // TODO: handcoded code, might be wrong
                                .aggregate => switch (return_value.kind) {
                                    .left => @trap(),
                                    .right => {
                                        assert(return_value.type.?.is_abi_equal(return_abi.semantic_type, module));
                                        _ = module.create_store(.{
                                            .source_value = return_value.llvm.?,
                                            .destination_value = return_alloca,
                                            .type = return_abi.semantic_type,
                                        });
                                    },
                                    // switch (return_value.lvalue) {
                                    //     true => {
                                    //         const abi_alignment = return_abi.semantic_type.get_byte_alignment();
                                    //         const abi_size = return_abi.semantic_type.get_byte_size();
                                    //         switch (return_abi.flags.kind) {
                                    //             .indirect => {
                                    //                 _ = module.llvm.builder.create_memcpy(
                                    //                     unreachable, //return_alloca,
                                    //                     abi_alignment, return_value.llvm, abi_alignment, module.integer_type(64, false).llvm.handle.to_integer().get_constant(abi_size, @intFromBool(false)).to_value());
                                    //             },
                                    //             else => {
                                    //                 switch (return_abi.semantic_type.get_evaluation_kind()) {
                                    //                     .aggregate => {
                                    //                         // TODO: this is 100% wrong, fix
                                    //                         assert(abi_alignment == return_abi.semantic_type.get_byte_alignment());
                                    //                         assert(abi_size == return_abi.semantic_type.get_byte_size());
                                    //                         _ = module.llvm.builder.create_memcpy(
                                    //                             unreachable, //return_alloca,
                                    //                             abi_alignment, return_value.llvm, abi_alignment, module.integer_type(64, false).llvm.handle.to_integer().get_constant(abi_size, @intFromBool(false)).to_value());
                                    //                     },
                                    //                     .scalar => {
                                    //                         const destination_type = return_abi.semantic_type;
                                    //                         const source_type = return_abi.semantic_type;
                                    //                         assert(return_value.type == source_type);
                                    //                         const ret_val = switch (return_value.type.bb) {
                                    //                             .pointer => return_value.llvm,
                                    //                             // TODO: this feels hacky
                                    //                             else => switch (return_value.lvalue) {
                                    //                                 true => module.create_load(.{ .type = return_value.type, .value = return_value.llvm }),
                                    //                                 false => return_value.llvm,
                                    //                             },
                                    //                         };
                                    //                         _ = module.create_store(.{ .source_value = ret_val, .source_type = source_type,
                                    //                             .destination_value = unreachable, //return_alloca,
                                    //                             .destination_type = destination_type });
                                    //                     },
                                    //                     .complex => @trap(),
                                    //                 }
                                    //             },
                                    //         }
                                    //     },
                                    //     false => {
                                    //     },
                                    // }
                                },
                                .complex => @trap(),
                            }
                        },
                    }

                    const return_block = module.current_function.?.variable.storage.?.bb.function.return_block orelse module.report_error();

                    _ = module.llvm.builder.create_branch(return_block);
                    _ = module.llvm.builder.clear_insertion_position();
                } else if (module.current_macro_instantiation) |m| {
                    const macro_instantiation = &m.bb.macro_instantiation;
                    module.analyze_value_type(rv.?, .{ .type = macro_instantiation.return_type });
                    module.emit_assignment(macro_instantiation.return_alloca, module.get_pointer_type(.{ .type = macro_instantiation.return_type }), rv.?);
                    _ = module.llvm.builder.create_branch(macro_instantiation.return_block);
                    module.llvm.builder.clear_insertion_position();
                } else {
                    module.report_error();
                }
            },
            .local => |local| {
                const expected_type = local.variable.type;
                assert(local.variable.storage == null);
                module.analyze_value_type(local.variable.initial_value, .{ .type = local.variable.type });
                local.variable.resolve_type(local.variable.initial_value.type.?);
                if (expected_type) |lvt| assert(lvt == local.variable.type);
                module.emit_local_storage(local);

                module.emit_assignment(local.variable.storage.?.llvm.?, local.variable.storage.?.type.?, local.variable.initial_value);
            },
            .assignment => |assignment| {
                module.analyze(assignment.left, .{}, .memory);
                switch (assignment.kind) {
                    .@"=" => {
                        module.analyze_value_type(assignment.right, .{ .type = assignment.left.type.?.bb.pointer.type });
                        module.emit_assignment(assignment.left.llvm.?, assignment.left.type.?, assignment.right);
                    },
                    else => |kind| {
                        const pointer_type = assignment.left.type.?.bb.pointer;
                        const element_type = pointer_type.type;
                        assert(element_type.get_evaluation_kind() == .scalar);
                        const load = module.create_load(.{ .type = element_type, .value = assignment.left.llvm.?, .alignment = pointer_type.alignment });
                        module.analyze(assignment.right, .{ .type = element_type }, .memory);
                        const a = load;
                        const b = assignment.right.llvm.?;
                        const right = switch (kind) {
                            .@"+=" => switch (element_type.bb) {
                                .integer => module.llvm.builder.create_add(a, b),
                                .pointer => |pointer| module.llvm.builder.create_gep(.{
                                    .type = pointer.type.llvm.abi.?,
                                    .aggregate = a,
                                    .indices = &.{b},
                                }),
                                else => module.report_error(),
                            },
                            .@"-=" => switch (element_type.bb) {
                                .integer => module.llvm.builder.create_sub(a, b),
                                .pointer => |pointer| module.llvm.builder.create_gep(.{
                                    .type = pointer.type.llvm.abi.?,
                                    .aggregate = a,
                                    .indices = &.{module.negate_llvm_value(b, assignment.right.is_constant())},
                                }),
                                else => module.report_error(),
                            },
                            .@"*=" => switch (element_type.bb) {
                                .integer => module.llvm.builder.create_mul(a, b),
                                else => module.report_error(),
                            },
                            .@"/=" => switch (element_type.bb) {
                                .integer => |integer| switch (integer.signed) {
                                    true => module.llvm.builder.create_sdiv(a, b),
                                    false => module.llvm.builder.create_udiv(a, b),
                                },
                                else => module.report_error(),
                            },
                            .@"%=" => switch (element_type.bb) {
                                .integer => |integer| switch (integer.signed) {
                                    true => module.llvm.builder.create_srem(a, b),
                                    false => module.llvm.builder.create_urem(a, b),
                                },
                                else => module.report_error(),
                            },
                            .@"&=" => switch (element_type.bb) {
                                .integer => module.llvm.builder.create_and(a, b),
                                else => module.report_error(),
                            },
                            .@"|=" => switch (element_type.bb) {
                                .integer => module.llvm.builder.create_or(a, b),
                                else => module.report_error(),
                            },
                            .@"^=" => switch (element_type.bb) {
                                .integer => module.llvm.builder.create_xor(a, b),
                                else => module.report_error(),
                            },
                            .@">>=" => switch (element_type.bb) {
                                .integer => |integer| switch (integer.signed) {
                                    true => module.llvm.builder.create_ashr(a, b),
                                    false => module.llvm.builder.create_lshr(a, b),
                                },
                                else => module.report_error(),
                            },
                            .@"<<=" => switch (element_type.bb) {
                                .integer => module.llvm.builder.create_shl(a, b),
                                else => module.report_error(),
                            },
                            else => @trap(),
                        };

                        _ = module.create_store(.{
                            .source_value = right,
                            .destination_value = assignment.left.llvm.?,
                            .type = element_type,
                            .alignment = pointer_type.alignment,
                        });
                    },
                }
            },
            .expression => |expression_value| {
                module.analyze(expression_value, .{}, .memory);
            },
            .@"if" => |if_statement| {
                const taken_block = module.llvm.context.create_basic_block("if.true", llvm_function);
                const not_taken_block = module.llvm.context.create_basic_block("if.false", llvm_function);
                const exit_block = module.llvm.context.create_basic_block("if.end", llvm_function);

                module.analyze(if_statement.condition, .{}, .abi);
                const llvm_condition = switch (if_statement.condition.type.?.bb) {
                    .integer => |integer| if (integer.bit_count != 1) module.llvm.builder.create_integer_compare(.ne, if_statement.condition.llvm.?, if_statement.condition.type.?.llvm.abi.?.get_zero().to_value()) else if_statement.condition.llvm.?,
                    .pointer => module.llvm.builder.create_integer_compare(.ne, if_statement.condition.llvm.?, if_statement.condition.type.?.llvm.abi.?.get_zero().to_value()),
                    else => @trap(),
                };

                _ = module.llvm.builder.create_conditional_branch(llvm_condition, taken_block, not_taken_block);
                module.llvm.builder.position_at_end(taken_block);

                module.analyze_statement(scope, if_statement.if_statement, last_line, last_line, last_statement_debug_location);
                if (module.llvm.builder.get_insert_block() != null) {
                    _ = module.llvm.builder.create_branch(exit_block);
                }

                module.llvm.builder.position_at_end(not_taken_block);
                if (if_statement.else_statement) |else_statement| {
                    module.analyze_statement(scope, else_statement, last_line, last_line, last_statement_debug_location);
                }

                if (module.llvm.builder.get_insert_block() != null) {
                    _ = module.llvm.builder.create_branch(exit_block);
                }

                module.llvm.builder.position_at_end(exit_block);
            },
            .@"while" => |while_loop| {
                const loop_entry_block = module.llvm.context.create_basic_block("while.entry", llvm_function);
                _ = module.llvm.builder.create_branch(loop_entry_block);
                module.llvm.builder.position_at_end(loop_entry_block);

                const loop_body_block = module.llvm.context.create_basic_block("while.body", llvm_function);

                const previous_continue_block = module.continue_block;
                defer module.continue_block = previous_continue_block;
                const loop_continue_block = module.llvm.context.create_basic_block("while.continue", llvm_function);
                module.continue_block = loop_continue_block;

                const previous_exit_block = module.exit_block;
                defer module.exit_block = previous_exit_block;
                const loop_end_block = module.llvm.context.create_basic_block("while.end", llvm_function);
                module.exit_block = loop_end_block;

                if (while_loop.condition.is_constant()) {
                    switch (while_loop.condition.bb) {
                        .constant_integer => |constant_integer| {
                            if (constant_integer.value == 0) {
                                module.report_error();
                            }
                        },
                        else => @trap(),
                    }
                    _ = module.llvm.builder.create_branch(loop_body_block);
                } else {
                    module.analyze(while_loop.condition, .{}, .abi);

                    const boolean_type = module.integer_type(1, false);
                    const condition_value = switch (while_loop.condition.type == boolean_type) {
                        true => while_loop.condition.llvm.?,
                        false => switch (while_loop.condition.type.?.bb) {
                            .integer => module.llvm.builder.create_integer_compare(.ne, while_loop.condition.llvm.?, while_loop.condition.type.?.llvm.abi.?.to_integer().get_constant(0, @intFromBool(false)).to_value()),
                            else => @trap(),
                        },
                    };

                    _ = module.llvm.builder.create_conditional_branch(condition_value, loop_body_block, loop_end_block);
                }

                module.llvm.builder.position_at_end(loop_body_block);

                module.analyze_block(while_loop.block);

                if (module.llvm.builder.get_insert_block() != null) {
                    _ = module.llvm.builder.create_branch(loop_continue_block);
                }

                module.llvm.builder.position_at_end(loop_continue_block);
                _ = module.llvm.builder.create_branch(loop_entry_block);

                if (loop_body_block.to_value().use_empty()) {
                    @trap();
                }

                if (loop_end_block.to_value().use_empty()) {
                    @trap();
                }

                module.llvm.builder.position_at_end(loop_end_block);
            },
            .@"switch" => |switch_statement| {
                const exit_block = module.llvm.context.create_basic_block("exit_block", llvm_function);

                module.analyze(switch_statement.discriminant, .{}, .abi);
                const switch_discriminant_type = switch_statement.discriminant.type.?;

                switch (switch_discriminant_type.bb) {
                    .enumerator => |enumerator| {
                        _ = enumerator;
                        var else_clause_index: ?usize = null;
                        var total_discriminant_cases: u32 = 0;
                        for (switch_statement.clauses, 0..) |*clause, clause_index| {
                            clause.basic_block = module.llvm.context.create_basic_block(if (clause.values.len == 0) "switch.else_case_block" else "switch.case_block", llvm_function);
                            total_discriminant_cases += @intCast(clause.values.len);
                            if (clause.values.len == 0) {
                                if (else_clause_index != null) {
                                    module.report_error();
                                }
                                else_clause_index = clause_index;
                            } else {
                                for (clause.values) |v| {
                                    module.analyze(v, .{ .type = switch_discriminant_type }, .abi);
                                    if (!v.is_constant()) {
                                        module.report_error();
                                    }
                                }
                            }
                        }

                        const else_block = if (else_clause_index) |i| switch_statement.clauses[i].basic_block else module.llvm.context.create_basic_block("switch.else_case_block", llvm_function);
                        const switch_instruction = module.llvm.builder.create_switch(switch_statement.discriminant.llvm.?, else_block, total_discriminant_cases);

                        var all_blocks_terminated = true;

                        for (switch_statement.clauses) |clause| {
                            for (clause.values) |v| {
                                switch_instruction.add_case(v.llvm.?, clause.basic_block);
                            }

                            module.llvm.builder.position_at_end(clause.basic_block);
                            module.analyze_block(clause.block);
                            if (module.llvm.builder.get_insert_block() != null) {
                                all_blocks_terminated = false;
                                _ = module.llvm.builder.create_branch(exit_block);
                                module.llvm.builder.clear_insertion_position();
                            }
                        }

                        if (else_clause_index == null) {
                            module.llvm.builder.position_at_end(else_block);
                            _ = module.llvm.builder.create_unreachable();
                            module.llvm.builder.clear_insertion_position();
                        }

                        if (!all_blocks_terminated) {
                            module.llvm.builder.position_at_end(exit_block);
                        }
                    },
                    else => @trap(),
                }
            },
            .block => |child_block| module.analyze_block(child_block),
            .for_each => |*for_loop| {
                if (module.has_debug_info) {
                    const lexical_block = module.llvm.di_builder.create_lexical_block(for_loop.scope.parent.?.llvm.?, module.llvm.file, for_loop.scope.line, for_loop.scope.column);
                    for_loop.scope.llvm = lexical_block.to_scope();
                }

                const index_type = module.integer_type(64, false);
                index_type.resolve(module);

                const loop_entry_block = module.llvm.context.create_basic_block("foreach.entry", llvm_function);
                const loop_body_block = module.llvm.context.create_basic_block("foreach.body", llvm_function);

                const previous_continue_block = module.continue_block;
                defer module.continue_block = previous_continue_block;
                const loop_continue_block = module.llvm.context.create_basic_block("foreach.continue", llvm_function);
                module.continue_block = loop_continue_block;

                const previous_exit_block = module.exit_block;
                defer module.exit_block = previous_exit_block;
                const loop_exit_block = module.llvm.context.create_basic_block("foreach.exit", llvm_function);
                module.exit_block = loop_exit_block;

                switch (for_loop.kind) {
                    .slice => {
                        const index_zero = index_type.llvm.abi.?.get_zero().to_value();

                        for (for_loop.locals, for_loop.left_values, for_loop.right_values) |local, kind, right| {
                            assert(right.kind == .left);
                            module.analyze_value_type(right, .{});
                            const pointer_type = right.type.?;
                            if (pointer_type.bb != .pointer) {
                                module.report_error();
                            }
                            const aggregate_type = pointer_type.bb.pointer.type;
                            const child_type = switch (aggregate_type.bb) {
                                .array => |array| array.element_type,
                                .structure => |structure| b: {
                                    assert(structure.is_slice);
                                    break :b structure.fields[0].type.bb.pointer.type;
                                },
                                else => @trap(),
                            };
                            assert(local.variable.type == null);
                            const local_type = switch (kind) {
                                .left => module.get_pointer_type(.{ .type = child_type }),
                                .right => child_type,
                            };
                            local.variable.type = local_type;
                            module.emit_local_storage(local);
                            module.emit_value(right, .memory);
                        }

                        const length_value = for (for_loop.right_values) |right| {
                            const pointer_type = right.type.?;
                            if (pointer_type.bb != .pointer) {
                                module.report_error();
                            }
                            const aggregate_type = pointer_type.bb.pointer.type;
                            const length = switch (aggregate_type.bb) {
                                .array => |array| index_type.llvm.abi.?.to_integer().get_constant(array.element_count, 0).to_value(),
                                .structure => |structure| b: {
                                    assert(structure.is_slice);
                                    const gep = module.llvm.builder.create_struct_gep(aggregate_type.llvm.abi.?.to_struct(), right.llvm.?, 1);
                                    const load = module.create_load(.{
                                        .type = index_type,
                                        .value = gep,
                                    });
                                    break :b load;
                                },
                                else => @trap(),
                            };
                            break length;
                        } else unreachable;

                        const index_alloca = module.create_alloca(.{ .type = index_type, .name = "foreach.index" });
                        _ = module.create_store(.{ .type = index_type, .source_value = index_zero, .destination_value = index_alloca });

                        _ = module.llvm.builder.create_branch(loop_entry_block);
                        module.llvm.builder.position_at_end(loop_entry_block);

                        const header_index_load = module.create_load(.{ .type = index_type, .value = index_alloca });
                        const index_compare = module.llvm.builder.create_integer_compare(.ult, header_index_load, length_value);
                        _ = module.llvm.builder.create_conditional_branch(index_compare, loop_body_block, loop_exit_block);

                        module.llvm.builder.position_at_end(loop_body_block);
                        const body_index_load = module.create_load(.{ .type = index_type, .value = index_alloca });

                        for (for_loop.locals, for_loop.left_values, for_loop.right_values) |local, kind, right| {
                            const aggregate_type = right.type.?.bb.pointer.type;
                            const element_pointer_value = switch (aggregate_type.bb) {
                                .array => module.llvm.builder.create_gep(.{
                                    .type = right.type.?.bb.pointer.type.llvm.memory.?,
                                    .aggregate = right.llvm.?,
                                    .indices = &.{ index_zero, body_index_load },
                                }),
                                .structure => |structure| b: {
                                    assert(structure.is_slice);
                                    const load = module.create_load(.{
                                        .type = aggregate_type,
                                        .value = right.llvm.?,
                                        .alignment = right.type.?.bb.pointer.alignment,
                                    });
                                    const extract_pointer = module.llvm.builder.create_extract_value(load, 0);
                                    const gep = module.llvm.builder.create_gep(.{
                                        .type = structure.fields[0].type.bb.pointer.type.llvm.memory.?,
                                        .aggregate = extract_pointer,
                                        .indices = &.{body_index_load},
                                    });
                                    break :b gep;
                                },
                                else => @trap(),
                            };

                            switch (kind) {
                                .left => {
                                    _ = module.create_store(.{
                                        .type = local.variable.type.?,
                                        .source_value = element_pointer_value,
                                        .destination_value = local.variable.storage.?.llvm.?,
                                    });
                                },
                                .right => switch (local.variable.type.?.get_evaluation_kind() == .scalar or (aggregate_type.bb == .structure and aggregate_type.bb.structure.is_slice)) {
                                    true => {
                                        const load = module.create_load(.{
                                            .type = local.variable.type.?,
                                            .value = element_pointer_value,
                                        });
                                        _ = module.create_store(.{
                                            .type = local.variable.type.?,
                                            .source_value = load,
                                            .destination_value = local.variable.storage.?.llvm.?,
                                        });
                                    },
                                    false => {
                                        @trap();
                                    },
                                },
                            }
                        }

                        module.analyze_statement(&for_loop.scope, for_loop.predicate, last_line, last_column, last_statement_debug_location);

                        if (module.llvm.builder.get_insert_block() != null) {
                            _ = module.llvm.builder.create_branch(loop_continue_block);
                        }

                        module.llvm.builder.position_at_end(loop_continue_block);
                        const continue_index_load = module.create_load(.{ .type = index_type, .value = index_alloca });
                        const add = module.llvm.builder.create_add(continue_index_load, index_type.llvm.abi.?.to_integer().get_constant(1, 0).to_value());
                        _ = module.create_store(.{ .type = index_type, .source_value = add, .destination_value = index_alloca });
                        _ = module.llvm.builder.create_branch(loop_entry_block);

                        module.llvm.builder.position_at_end(loop_exit_block);
                    },
                    .range => {
                        assert(for_loop.locals.len == 1);
                        assert(for_loop.left_values.len == 1);
                        if (for_loop.right_values.len == 2) {
                            const start = for_loop.right_values[0];
                            const end = for_loop.right_values[1];
                            const local_type = switch (start.bb) {
                                .constant_integer => |start_constant_integer| switch (end.bb) {
                                    .constant_integer => |end_constant_integer| module.integer_type(64, !(!start_constant_integer.signed and !end_constant_integer.signed)),
                                    else => blk: {
                                        module.analyze_value_type(end, .{});
                                        start.type = end.type;
                                        break :blk end.type.?;
                                    },
                                },
                                else => @trap(),
                            };

                            for (for_loop.right_values) |right_value| {
                                if (right_value.type == null) {
                                    module.analyze_value_type(right_value, .{ .type = local_type });
                                }
                            }

                            const local = for_loop.locals[0];
                            local.variable.type = local_type;
                            module.emit_local_storage(local);
                            module.emit_value(start, .memory);

                            const index_alloca = local.variable.storage.?.llvm.?;

                            _ = module.create_store(.{ .type = local_type, .source_value = start.llvm.?, .destination_value = index_alloca });

                            _ = module.llvm.builder.create_branch(loop_entry_block);
                            module.llvm.builder.position_at_end(loop_entry_block);

                            const header_index_load = module.create_load(.{ .type = local_type, .value = index_alloca });
                            module.emit_value(end, .abi);
                            const length_value = end.llvm.?;
                            const index_compare = module.llvm.builder.create_integer_compare(.ult, header_index_load, length_value);
                            _ = module.llvm.builder.create_conditional_branch(index_compare, loop_body_block, loop_exit_block);

                            module.llvm.builder.position_at_end(loop_body_block);
                            module.analyze_statement(&for_loop.scope, for_loop.predicate, last_line, last_column, last_statement_debug_location);

                            if (module.llvm.builder.get_insert_block() != null) {
                                _ = module.llvm.builder.create_branch(loop_continue_block);
                            }

                            module.llvm.builder.position_at_end(loop_continue_block);
                            const continue_index_load = module.create_load(.{ .type = local_type, .value = index_alloca });
                            const add = module.llvm.builder.create_add(continue_index_load, local_type.llvm.abi.?.to_integer().get_constant(1, 0).to_value());
                            _ = module.create_store(.{ .type = local_type, .source_value = add, .destination_value = index_alloca });
                            _ = module.llvm.builder.create_branch(loop_entry_block);

                            module.llvm.builder.position_at_end(loop_exit_block);
                        } else {
                            // TODO: case for reverse range
                            @trap();
                        }
                    },
                }
            },
            .break_statement => {
                const exit_block = module.exit_block orelse module.report_error();
                _ = module.llvm.builder.create_branch(exit_block);
                module.llvm.builder.clear_insertion_position();
            },
            .continue_statement => {
                const continue_block = module.continue_block orelse module.report_error();
                _ = module.llvm.builder.create_branch(continue_block);
                module.llvm.builder.clear_insertion_position();
            },
        }
    }

    pub fn analyze_block(module: *Module, block: *LexicalBlock) void {
        if (module.has_debug_info) {
            const lexical_block = module.llvm.di_builder.create_lexical_block(block.scope.parent.?.llvm.?, module.llvm.file, block.scope.line, block.scope.column);
            block.scope.llvm = lexical_block.to_scope();
        }

        var last_line: u32 = 0;
        var last_column: u32 = 0;
        var last_statement_debug_location: *llvm.DI.Location = undefined;

        for (block.statements.get_slice()) |statement| {
            module.analyze_statement(&block.scope, statement, &last_line, &last_column, &last_statement_debug_location);
        }
    }

    fn emit_assignment(module: *Module, left_llvm: *llvm.Value, left_type: *Type, right: *Value) void {
        assert(right.llvm == null);
        const pointer_type = left_type;
        const v_type = right.type.?;
        v_type.resolve(module);
        pointer_type.resolve(module);
        const resolved_value_type = module.fully_resolve_alias(v_type);
        const resolved_pointer_type = module.fully_resolve_alias(pointer_type);
        assert(resolved_pointer_type.bb == .pointer);
        assert(resolved_pointer_type.bb.pointer.type == resolved_value_type);

        switch (resolved_value_type.get_evaluation_kind()) {
            .scalar => {
                module.emit_value(right, .memory);
                _ = module.create_store(.{
                    .source_value = right.llvm.?,
                    .destination_value = left_llvm,
                    .type = v_type,
                    .alignment = pointer_type.bb.pointer.alignment,
                });
            },
            .aggregate => switch (right.bb) {
                .array_initialization => |array_initialization| switch (array_initialization.is_constant) {
                    true => {
                        module.emit_value(right, .memory);
                        const global_variable = module.llvm.module.create_global_variable(.{
                            .linkage = .InternalLinkage,
                            .name = "constarray", // TODO: format properly
                            .initial_value = right.llvm.?.to_constant(),
                            .type = v_type.llvm.memory.?,
                        });
                        global_variable.set_unnamed_address(.global);
                        const element_type = v_type.bb.array.element_type;
                        const alignment = element_type.get_byte_alignment();
                        global_variable.to_value().set_alignment(alignment);
                        const uint64 = module.integer_type(64, false);
                        uint64.resolve(module);
                        _ = module.llvm.builder.create_memcpy(left_llvm, pointer_type.bb.pointer.alignment.?, global_variable.to_value(), alignment, uint64.llvm.abi.?.to_integer().get_constant(array_initialization.values.len * pointer_type.bb.pointer.type.bb.array.element_type.get_byte_size(), @intFromBool(false)).to_value());
                    },
                    false => {
                        assert(v_type.bb == .array);
                        const uint64 = module.integer_type(64, false);
                        uint64.resolve(module);
                        const u64_zero = uint64.llvm.abi.?.to_integer().get_constant(0, 0).to_value();
                        const pointer_to_element_type = module.get_pointer_type(.{ .type = v_type.bb.array.element_type });
                        for (array_initialization.values, 0..) |v, i| {
                            const alloca_gep = module.llvm.builder.create_gep(.{
                                .type = v_type.llvm.memory.?,
                                .aggregate = left_llvm,
                                .indices = &.{ u64_zero, uint64.llvm.abi.?.to_integer().get_constant(i, 0).to_value() },
                            });
                            module.emit_assignment(alloca_gep, pointer_to_element_type, v);
                        }
                    },
                },
                .aggregate_initialization => |aggregate_initialization| switch (aggregate_initialization.is_constant) {
                    true => {
                        module.emit_value(right, .memory);
                        const global_variable = module.llvm.module.create_global_variable(.{
                            .linkage = .InternalLinkage,
                            .name = "conststruct", // TODO: format properly
                            .initial_value = right.llvm.?.to_constant(),
                            .type = v_type.llvm.abi.?,
                        });
                        global_variable.set_unnamed_address(.global);
                        const alignment = v_type.get_byte_alignment();
                        global_variable.to_value().set_alignment(alignment);
                        const uint64 = module.integer_type(64, false);
                        uint64.resolve(module);
                        _ = module.llvm.builder.create_memcpy(left_llvm, pointer_type.bb.pointer.get_alignment(), global_variable.to_value(), alignment, uint64.llvm.abi.?.to_integer().get_constant(v_type.get_byte_size(), @intFromBool(false)).to_value());
                    },
                    false => switch (resolved_value_type.bb) {
                        .structure => {
                            var max_field_index: u64 = 0;
                            var field_mask: u64 = 0;
                            const fields = resolved_value_type.bb.structure.fields;
                            assert(fields.len <= 64);

                            for (aggregate_initialization.values, aggregate_initialization.names) |initialization_value, initialization_name| {
                                const field_index = for (fields, 0..) |*field, field_index| {
                                    if (lib.string.equal(field.name, initialization_name)) {
                                        break field_index;
                                    }
                                } else module.report_error();
                                field_mask |= @as(@TypeOf(field_mask), 1) << @intCast(field_index);
                                max_field_index = @max(field_index, max_field_index);
                                const field = &fields[field_index];
                                const destination_pointer = module.llvm.builder.create_struct_gep(v_type.llvm.abi.?.to_struct(), left_llvm, @intCast(field_index));
                                module.emit_assignment(destination_pointer, module.get_pointer_type(.{ .type = field.type }), initialization_value);
                            }

                            if (aggregate_initialization.zero) {
                                const buffer_field_count: u64 = @bitSizeOf(@TypeOf(field_mask));
                                const raw_end_uninitialized_field_count = @clz(field_mask);
                                const unused_buffer_field_count = buffer_field_count - fields.len;
                                const end_uninitialized_field_count = raw_end_uninitialized_field_count - unused_buffer_field_count;
                                const initialized_field_count = @popCount(field_mask);
                                const uninitialized_field_count = fields.len - initialized_field_count;
                                if (uninitialized_field_count != end_uninitialized_field_count) {
                                    @trap();
                                }

                                if (end_uninitialized_field_count == 0) {
                                    module.report_error();
                                }

                                const field_index_offset = fields.len - end_uninitialized_field_count;
                                const destination_pointer = module.llvm.builder.create_struct_gep(v_type.llvm.abi.?.to_struct(), left_llvm, @intCast(field_index_offset));
                                const start_field = &fields[field_index_offset];
                                const memset_size = v_type.get_byte_size() - start_field.byte_offset;
                                const uint8 = module.integer_type(8, false);
                                uint8.resolve(module);
                                const uint64 = module.integer_type(64, false);
                                uint64.resolve(module);
                                _ = module.llvm.builder.create_memset(destination_pointer, uint8.llvm.abi.?.get_zero().to_value(), uint64.llvm.abi.?.to_integer().get_constant(memset_size, 0).to_value(), pointer_type.bb.pointer.alignment.?);
                            }
                        },
                        .@"union" => |union_type| {
                            assert(aggregate_initialization.names.len == 1);
                            assert(aggregate_initialization.values.len == 1);
                            const biggest_field_type = union_type.fields[union_type.biggest_field].type;
                            const value = aggregate_initialization.values[0];
                            const field_value_type = value.type.?;
                            const field_type_size = field_value_type.get_byte_size();

                            const struct_type = if (field_value_type.is_abi_equal(biggest_field_type, module)) v_type.llvm.memory.?.to_struct() else module.llvm.context.get_struct_type(&.{field_value_type.llvm.memory.?});

                            const destination_pointer = module.llvm.builder.create_struct_gep(struct_type, left_llvm, 0);
                            const field_pointer_type = module.get_pointer_type(.{ .type = field_value_type });
                            module.emit_assignment(destination_pointer, field_pointer_type, value);
                            if (field_type_size < union_type.byte_size) {
                                @trap();
                            } else if (field_type_size > union_type.byte_size) {
                                unreachable;
                            }
                        },
                        else => unreachable,
                    },
                },
                .string_literal => |string_literal| {
                    const null_terminate = true;
                    const constant_string = module.llvm.context.get_constant_string(string_literal, null_terminate);

                    const u8_type = module.integer_type(8, false);
                    u8_type.resolve(module);
                    const global_variable = module.llvm.module.create_global_variable(.{
                        .linkage = .InternalLinkage,
                        .name = "conststring",
                        .initial_value = constant_string,
                        .type = u8_type.llvm.abi.?.get_array_type(string_literal.len + @intFromBool(null_terminate)).to_type(),
                    });
                    global_variable.set_unnamed_address(.global);

                    const slice_type = module.get_slice_type(.{
                        .type = u8_type,
                    });

                    switch (resolved_value_type.bb) {
                        .structure => |structure| switch (structure.is_slice) {
                            true => switch (slice_type == resolved_value_type) {
                                true => {
                                    const pointer_to_pointer = module.llvm.builder.create_struct_gep(slice_type.llvm.abi.?.to_struct(), left_llvm, 0);
                                    const slice_pointer_type = slice_type.bb.structure.fields[0].type;
                                    _ = module.create_store(.{
                                        .destination_value = pointer_to_pointer,
                                        .source_value = global_variable.to_value(),
                                        .type = slice_pointer_type,
                                    });
                                    const pointer_to_length = module.llvm.builder.create_struct_gep(slice_type.llvm.abi.?.to_struct(), left_llvm, 1);
                                    const slice_length_type = slice_type.bb.structure.fields[1].type;
                                    const slice_length_value = slice_length_type.llvm.abi.?.to_integer().get_constant(string_literal.len, @intFromBool(false)).to_value();
                                    _ = module.create_store(.{
                                        .destination_value = pointer_to_length,
                                        .source_value = slice_length_value,
                                        .type = slice_length_type,
                                    });
                                },
                                false => module.report_error(),
                            },
                            false => module.report_error(),
                        },
                        else => @trap(),
                    }
                },
                .intrinsic => |intrinsic| switch (intrinsic) {
                    .enum_name => {
                        module.emit_value(right, .memory);
                        _ = module.create_store(.{
                            .type = right.type.?,
                            .source_value = right.llvm.?,
                            .destination_value = left_llvm,
                        });
                    },
                    .select => {
                        if (right.type.?.get_evaluation_kind() == .scalar or right.type.?.is_slice()) {
                            module.emit_value(right, .memory);
                            _ = module.create_store(.{
                                .type = right.type.?,
                                .source_value = right.llvm.?,
                                .destination_value = left_llvm,
                            });
                        } else {
                            @trap();
                        }
                    },
                    .string_to_enum => |string_to_enum| {
                        module.emit_value(string_to_enum.string_value, .memory);
                        const s2e = string_to_enum.enum_type.bb.enumerator.string_to_enum orelse unreachable;
                        const first_field = module.llvm.builder.create_extract_value(string_to_enum.string_value.llvm.?, 0);
                        const second_field = module.llvm.builder.create_extract_value(string_to_enum.string_value.llvm.?, 1);
                        const call = module.llvm.builder.create_call(s2e.function.get_type(), s2e.function.to_value(), &.{ first_field, second_field });
                        call.to_instruction().to_call_base().set_calling_convention(.fast);
                        _ = module.create_store(.{
                            .source_value = call,
                            .destination_value = left_llvm,
                            .type = s2e.struct_type,
                            .alignment = pointer_type.bb.pointer.alignment,
                        });
                    },
                    .va_start => {
                        assert(resolved_value_type == module.get_va_list_type());
                        assert(pointer_type.bb.pointer.type == module.get_va_list_type());
                        const intrinsic_id = module.llvm.intrinsic_table.va_start;
                        const argument_types: []const *llvm.Type = &.{module.llvm.pointer_type};
                        const intrinsic_function = module.llvm.module.get_intrinsic_declaration(intrinsic_id, argument_types);
                        const intrinsic_function_type = module.llvm.context.get_intrinsic_type(intrinsic_id, argument_types);
                        const argument_values: []const *llvm.Value = &.{left_llvm};
                        _ = module.llvm.builder.create_call(intrinsic_function_type, intrinsic_function, argument_values);
                    },
                    .va_arg => {
                        const result = module.emit_va_arg(right, left_llvm, left_type);
                        switch (result == left_llvm) {
                            true => {},
                            false => switch (resolved_value_type.get_evaluation_kind()) {
                                .scalar => {
                                    @trap();
                                },
                                .aggregate => @trap(),
                                .complex => @trap(),
                            },
                        }
                    },
                    else => @trap(),
                },
                .call => {
                    const result = module.emit_call(right, left_llvm, left_type);
                    assert(result == left_llvm);
                    // if (result != left.llvm) {
                    //     const call_ret_type_ev_kind = right.type.?.get_evaluation_kind();
                    //     switch (call_ret_type_ev_kind) {
                    //         .aggregate => switch (right.kind) {
                    //             .left => @trap(),
                    //             .right => @trap(),
                    //         },
                    //         else => @trap(),
                    //     }
                    //     @trap();
                    // }
                },
                .slice_expression => {
                    const slice_values = module.emit_slice_expression(right);
                    const slice_pointer_type = resolved_value_type.bb.structure.fields[0].type;
                    _ = module.create_store(.{
                        .source_value = slice_values[0],
                        .destination_value = left_llvm,
                        .type = slice_pointer_type,
                        .alignment = pointer_type.bb.pointer.alignment,
                    });
                    const slice_length_destination = module.llvm.builder.create_struct_gep(resolved_value_type.llvm.abi.?.to_struct(), left_llvm, 1);
                    _ = module.create_store(.{
                        .source_value = slice_values[1],
                        .destination_value = slice_length_destination,
                        .type = module.integer_type(64, false),
                    });
                },
                .zero => {
                    const u8_type = module.integer_type(8, false);
                    u8_type.resolve(module);
                    const u64_type = module.integer_type(64, false);
                    u64_type.resolve(module);
                    _ = module.llvm.builder.create_memset(left_llvm, u8_type.llvm.abi.?.get_zero().to_value(), u64_type.llvm.abi.?.to_integer().get_constant(resolved_value_type.get_byte_size(), 0).to_value(), pointer_type.bb.pointer.alignment.?);
                },
                .variable_reference => |variable| switch (right.kind) {
                    .left => @trap(),
                    .right => {
                        const uint64 = module.integer_type(64, false);
                        _ = module.llvm.builder.create_memcpy(left_llvm, pointer_type.bb.pointer.alignment.?, variable.storage.?.llvm.?, variable.storage.?.type.?.bb.pointer.alignment.?, uint64.llvm.abi.?.to_integer().get_constant(resolved_value_type.get_byte_size(), @intFromBool(false)).to_value());
                    },
                },
                .field_access => |field_access| {
                    const struct_type = field_access.aggregate.type.?.bb.pointer.type;
                    const fields = struct_type.bb.structure.fields;
                    const field_index: u32 = for (fields, 0..) |*field, field_index| {
                        if (lib.string.equal(field_access.field, field.name)) {
                            break @intCast(field_index);
                        }
                    } else module.report_error();
                    module.emit_value(field_access.aggregate, .memory);
                    const gep = module.llvm.builder.create_struct_gep(struct_type.llvm.abi.?.to_struct(), field_access.aggregate.llvm.?, field_index);
                    const uint64 = module.integer_type(64, false);
                    _ = module.llvm.builder.create_memcpy(left_llvm, pointer_type.bb.pointer.alignment.?, gep, resolved_value_type.get_byte_alignment(), uint64.llvm.abi.?.to_integer().get_constant(resolved_value_type.get_byte_size(), @intFromBool(false)).to_value());
                },
                .undefined => {},
                else => @trap(),
            },
            .complex => @trap(),
        }
    }

    pub fn emit_local_storage(module: *Module, local: *Local) void {
        assert(local.variable.storage == null);
        const resolved_type = local.variable.type.?;
        resolved_type.resolve(module);

        const pointer_type = module.get_pointer_type(.{ .type = resolved_type });
        const storage = module.values.add();
        storage.* = .{
            .type = pointer_type,
            .bb = .local,
            .llvm = module.create_alloca(.{
                .type = pointer_type.bb.pointer.type,
                .alignment = pointer_type.bb.pointer.alignment,
                .name = local.variable.name,
            }),
        };

        if (module.has_debug_info) {
            const debug_type = resolved_type.llvm.debug.?;
            const always_preserve = true;
            const flags = llvm.DI.Flags{};
            const inlined_at: ?*llvm.DI.Metadata = @ptrCast(module.inline_at_debug_location); // TODO

            const scope = local.variable.scope.llvm.?;
            const local_variable = if (local.argument_index) |argument_index| module.llvm.di_builder.create_parameter_variable(scope, local.variable.name, @intCast(argument_index + 1), module.llvm.file, local.variable.line, local.variable.type.?.llvm.debug.?, always_preserve, flags) else module.llvm.di_builder.create_auto_variable(scope, local.variable.name, module.llvm.file, local.variable.line, debug_type, always_preserve, flags, 0);
            const debug_location = llvm.DI.create_debug_location(module.llvm.context, local.variable.line, local.variable.column, scope, inlined_at);
            module.llvm.builder.set_current_debug_location(debug_location);
            _ = module.llvm.di_builder.insert_declare_record_at_end(storage.llvm.?, local_variable, module.llvm.di_builder.null_expression(), debug_location, module.llvm.builder.get_insert_block().?);
        }

        local.variable.storage = storage;
    }

    pub fn align_integer_type(module: *Module, ty: *Type) *Type {
        assert(ty.bb == .integer or ty.bb == .enumerator);
        const bit_count = ty.get_bit_size();
        const abi_bit_count: u32 = @intCast(@max(8, lib.next_power_of_two(bit_count)));
        if (bit_count != abi_bit_count) {
            const is_signed = ty.is_signed();
            return module.integer_type(abi_bit_count, is_signed);
        } else {
            return ty;
        }
    }

    const LoadOptions = struct {
        type: *Type,
        value: *llvm.Value,
        alignment: ?c_uint = null,
        type_kind: Type.Kind = .abi,
    };

    pub fn create_load(module: *Module, options: LoadOptions) *llvm.Value {
        options.type.resolve(module);
        const alignment: c_uint = if (options.alignment) |a| a else @intCast(options.type.get_byte_alignment());
        const v = module.llvm.builder.create_load(options.type.llvm.memory.?, options.value);
        v.set_alignment(alignment);

        return switch (options.type_kind) {
            .abi => switch (options.type.llvm.memory == options.type.llvm.abi) {
                true => v,
                false => module.llvm.builder.create_int_cast(v, options.type.llvm.abi.?, options.type.is_signed()),
            },
            .memory => v,
        };
    }

    const AllocaOptions = struct {
        type: *Type,
        name: []const u8 = "",
        alignment: ?c_uint = null,
    };

    pub fn create_alloca(module: *Module, options: AllocaOptions) *llvm.Value {
        const abi_type = options.type;
        abi_type.resolve(module);
        const alignment: c_uint = if (options.alignment) |a| a else @intCast(abi_type.get_byte_alignment());
        const v = module.llvm.builder.create_alloca(abi_type.llvm.memory.?, options.name);
        v.set_alignment(alignment);
        return v;
    }

    const StoreOptions = struct {
        source_value: *llvm.Value,
        destination_value: *llvm.Value,
        type: *Type,
        alignment: ?c_uint = null,
    };

    pub fn create_store(module: *Module, options: StoreOptions) *llvm.Value {
        options.type.resolve(module);
        const source_value = switch (options.type.llvm.abi == options.type.llvm.memory) {
            true => options.source_value,
            false => module.llvm.builder.create_int_cast(options.source_value, options.type.llvm.memory.?, options.type.is_signed()),
        };
        const alignment = if (options.alignment) |a| a else options.type.get_byte_alignment();
        const v = module.llvm.builder.create_store(source_value, options.destination_value);
        v.set_alignment(alignment);
        return v;
    }

    const IntCast = struct {
        type: *llvm.Type,
        value: *llvm.Value,
    };

    pub fn raw_int_cast(module: *Module, options: IntCast) *llvm.Value {
        assert(options.source_type != options.destination_type);
        const source_size = options.source_type.get_bit_size();
        const destination_size = options.destination_type.get_bit_size();
        options.destination_type.resolve(module);
        const llvm_destination_type = options.destination_type.llvm.abi.?;
        const result = switch (source_size < destination_size) {
            true => switch (options.source_type.is_signed()) {
                true => module.llvm.builder.create_sign_extend(options.value, llvm_destination_type),
                false => module.llvm.builder.create_zero_extend(options.value, llvm_destination_type),
            },
            false => module.llvm.builder.create_truncate(options.value, llvm_destination_type),
        };
        return result;
    }

    fn negate_llvm_value(module: *Module, value: *llvm.Value, is_constant: bool) *llvm.Value {
        return switch (is_constant) {
            true => value.to_constant().negate().to_value(),
            false => module.llvm.builder.create_neg(value),
        };
    }

    pub fn dump(module: *Module) void {
        lib.print_string(module.llvm.module.to_string());
    }

    pub fn enter_struct_pointer_for_coerced_access(module: *Module, source_value: *llvm.Value, source_ty: *Type, destination_size: u64) struct {
        value: *llvm.Value,
        type: *Type,
    } {
        _ = module;
        var source_pointer = source_value;
        var source_type = source_ty;
        assert(source_type.bb == .structure and source_type.bb.structure.fields.len > 0);
        const first_field_type = source_type.bb.structure.fields[0].type;
        const first_field_size = first_field_type.get_byte_size();
        const source_size = source_type.get_byte_size();

        source_pointer = switch (first_field_size < destination_size and first_field_size < source_size) {
            true => source_pointer,
            false => @trap(), // TODO: make sure `source_type` is also updated here
        };

        return .{ .value = source_pointer, .type = source_type };
    }

    pub fn create_coerced_store(module: *Module, source_value: *llvm.Value, source_type: *Type, destination: *llvm.Value, destination_ty: *Type, destination_size: u64, destination_volatile: bool) void {
        _ = destination_volatile;
        var destination_type = destination_ty;
        var destination_pointer = destination;
        const source_size = source_type.get_byte_size();
        if (!source_type.is_abi_equal(destination_type, module)) {
            const r = module.enter_struct_pointer_for_coerced_access(destination_pointer, destination_type, source_size);
            destination_pointer = r.value;
            destination_type = r.type;
        }

        const is_scalable = false; // TODO
        if (is_scalable or source_size <= destination_size) {
            const destination_alignment = destination_type.get_byte_alignment();
            if (source_type.bb == .integer and destination_type.bb == .pointer and source_size == lib.align_forward_u64(destination_size, destination_alignment)) {
                @trap();
            } else if (source_type.bb == .structure) {
                for (source_type.bb.structure.fields, 0..) |field, field_index| {
                    // TODO: volatile
                    const gep = module.llvm.builder.create_struct_gep(source_type.llvm.abi.?.to_struct(), destination_pointer, @intCast(field_index));
                    const field_value = module.llvm.builder.create_extract_value(source_value, @intCast(field_index));
                    _ = module.create_store(.{
                        .source_value = field_value,
                        .type = field.type,
                        .destination_value = gep,
                        .alignment = destination_alignment,
                    });
                }
            } else {
                _ = module.create_store(.{
                    .source_value = source_value,
                    .type = destination_type,
                    .destination_value = destination_pointer,
                    .alignment = destination_alignment,
                });
            }
            // TODO: is this valid for pointers too?
        } else if (source_type.is_integer_backing()) {
            const destination_integer_type = module.integer_type(@intCast(destination_size * 8), false);
            const value = module.coerce_int_or_pointer_to_int_or_pointer(source_value, source_type, destination_integer_type);
            _ = module.create_store(.{
                .type = destination_integer_type,
                .source_value = value,
                .destination_value = destination_pointer,
            });
        } else {
            // Coercion through memory
            const original_destination_alignment = destination_type.get_byte_alignment();
            const source_alloca_alignment = @max(original_destination_alignment, source_type.get_byte_alignment());
            const source_alloca = module.create_alloca(.{ .type = source_type, .alignment = source_alloca_alignment, .name = "coerce" });
            _ = module.create_store(.{
                .source_value = source_value,
                .destination_value = source_alloca,
                .type = source_type,
                .alignment = source_alloca_alignment,
            });
            const uint64 = module.integer_type(64, false);
            _ = module.llvm.builder.create_memcpy(destination_pointer, original_destination_alignment, source_alloca, source_alloca_alignment, uint64.llvm.abi.?.to_integer().get_constant(destination_size, @intFromBool(false)).to_value());
        }
    }

    pub fn create_coerced_load(module: *Module, source: *llvm.Value, source_ty: *Type, destination_type: *Type) *llvm.Value {
        var source_pointer = source;
        var source_type = source_ty;

        const result = switch (source_type.is_abi_equal(destination_type, module)) {
            true => module.create_load(.{
                .type = destination_type,
                .value = source_pointer,
            }),
            false => res: {
                const destination_size = destination_type.get_byte_size();
                if (source_type.bb == .structure) {
                    const src = module.enter_struct_pointer_for_coerced_access(source_pointer, source_type, destination_size);
                    source_pointer = src.value;
                    source_type = src.type;
                }

                if (source_type.is_integer_backing() and destination_type.is_integer_backing()) {
                    const load = module.create_load(.{
                        .type = destination_type,
                        .value = source_pointer,
                    });
                    const result = module.coerce_int_or_pointer_to_int_or_pointer(load, source_type, destination_type);
                    return result;
                } else {
                    const source_size = source_type.get_byte_size();

                    const is_source_type_scalable = false;
                    const is_destination_type_scalable = false;
                    if (!is_source_type_scalable and !is_destination_type_scalable and source_size >= destination_size) {
                        const load = module.create_load(.{ .type = destination_type, .value = source, .alignment = source_type.get_byte_alignment() });
                        break :res load;
                    } else {
                        const is_destination_scalable_vector_type = false;
                        if (is_destination_scalable_vector_type) {
                            @trap();
                        }

                        // Coercion through memory
                        const original_destination_alignment = destination_type.get_byte_alignment();
                        const source_alignment = source_type.get_byte_alignment();
                        const destination_alignment = @max(original_destination_alignment, source_alignment);
                        const destination_alloca = module.create_alloca(.{ .type = destination_type, .name = "coerce", .alignment = destination_alignment });
                        const uint64 = module.integer_type(64, false);
                        _ = module.llvm.builder.create_memcpy(destination_alloca, destination_alignment, source, source_alignment, uint64.llvm.abi.?.to_integer().get_constant(source_size, @intFromBool(false)).to_value());
                        const load = module.create_load(.{ .type = destination_type, .value = destination_alloca, .alignment = destination_alignment });
                        return load;
                    }
                }
            },
        };
        return result;
    }

    pub fn coerce_int_or_pointer_to_int_or_pointer(module: *Module, source: *llvm.Value, source_ty: *Type, destination_ty: *Type) *llvm.Value {
        const source_type = source_ty;
        var destination_type = destination_ty;
        switch (source_type == destination_type) {
            true => return source,
            false => {
                if (source_type.bb == .pointer and destination_type.bb == .pointer) {
                    @trap();
                } else {
                    if (source_type.bb == .pointer) {
                        @trap();
                    }

                    if (destination_type.bb == .pointer) {
                        destination_type = module.integer_type(64, false);
                    }

                    if (source_type != destination_type) {
                        @trap();
                    }

                    // This is the original destination type
                    if (destination_ty.bb == .pointer) {
                        @trap();
                    }

                    @trap();
                }
            },
        }
    }

    fn resolve_type(module: *Module, ty: *Type) *Type {
        const result_type = switch (ty.bb) {
            .unresolved => blk: {
                const macro_instantiation_value = module.current_macro_instantiation orelse module.report_error();
                const macro_instantiation = &macro_instantiation_value.bb.macro_instantiation;

                const result_type = for (macro_instantiation.type_arguments, macro_instantiation.declaration.type_arguments) |instantiation_type_argument, declaration_type_argument| {
                    if (declaration_type_argument == ty) {
                        assert(lib.string.equal(declaration_type_argument.name, instantiation_type_argument.name));
                        break instantiation_type_argument;
                    }
                } else module.report_error();

                break :blk result_type;
            },
            .pointer => |pointer| blk: {
                const old_child_type = pointer.type;
                const new_child_type = module.resolve_type(pointer.type);
                if (old_child_type == new_child_type) {
                    break :blk ty;
                } else {
                    const p = module.get_pointer_type(.{ .type = new_child_type, .alignment = pointer.alignment });
                    break :blk p;
                }
            },
            .structure => |structure| blk: {
                var is_the_same = true;
                var new_field_type_buffer: [64]*Type = undefined;
                for (structure.fields, new_field_type_buffer[0..structure.fields.len]) |*field, *new_field_type| {
                    const old_field_type = field.type;
                    const new = module.resolve_type(old_field_type);
                    new_field_type.* = new;
                    is_the_same = is_the_same and old_field_type == new;
                }

                if (is_the_same) {
                    break :blk ty;
                } else {
                    @trap();
                }
            },
            .integer => ty,
            .array => |array| blk: {
                const old_element_type = array.element_type;
                const new_element_type = module.resolve_type(old_element_type);
                if (old_element_type == new_element_type) {
                    break :blk ty;
                } else {
                    @trap();
                }
            },
            .alias => |alias| blk: {
                const old_aliased_type = alias.type;
                const new_aliased_type = module.resolve_type(old_aliased_type);
                if (old_aliased_type == new_aliased_type) {
                    break :blk ty;
                } else {
                    // TODO: create new type
                    @trap();
                }
            },
            .@"union" => |union_type| blk: {
                var is_the_same = true;
                var new_field_type_buffer: [64]*Type = undefined;
                for (union_type.fields, new_field_type_buffer[0..union_type.fields.len]) |*field, *new_field_type| {
                    const old_field_type = field.type;
                    const new = module.resolve_type(old_field_type);
                    new_field_type.* = new;
                    is_the_same = is_the_same and old_field_type == new;
                }

                if (is_the_same) {
                    break :blk ty;
                } else {
                    @trap();
                }
            },
            .enumerator => |*enumerator| blk: {
                const old_backing_type = enumerator.backing_type;
                const new_backing_type = module.resolve_type(old_backing_type);

                if (old_backing_type == new_backing_type) {
                    break :blk ty;
                } else {
                    @trap();
                }
            },
            .void => ty,
            else => @trap(),
        };

        assert(result_type.bb != .unresolved);

        return result_type;
    }
};

pub const Options = struct {
    content: []const u8,
    path: [:0]const u8,
    executable: [:0]const u8,
    name: []const u8,
    objects: []const [:0]const u8,
    target: Target,
    build_mode: BuildMode,
    has_debug_info: bool,
    silent: bool,
};

const Token = union(Id) {
    none,
    end_of_statement,
    integer: Integer,
    identifier: []const u8,
    string_literal: []const u8,
    value_keyword: Value.Keyword,
    value_intrinsic: Value.Intrinsic.Id,
    // Assignment operators
    @"=",
    @"+=",
    @"-=",
    @"*=",
    @"/=",
    @"%=",
    @"&=",
    @"|=",
    @"^=",
    @"<<=",
    @">>=",
    // Comparison operators
    @"==",
    @"!=",
    @"<",
    @">",
    @"<=",
    @">=",
    // Logical AND
    @"and",
    @"and?",
    // Logical OR
    @"or",
    @"or?",
    // Add-like operators
    @"+",
    @"-",
    // Div-like operators
    @"*",
    @"/",
    @"%",
    // Bitwise operators
    @"&",
    @"|",
    @"^",
    // Shifting operators
    @"<<",
    @">>",
    // Logical NOT operator
    @"!",
    // Bitwise NOT operator
    @"~",
    // Pointer dereference
    @".&",
    // Parenthesis
    @"(",
    @")",
    // Bracket
    @"[",
    @"]",
    // Brace
    @"{",
    @"}",

    @",",
    @".",
    @"..",
    @"...",

    const Id = enum {
        none,
        end_of_statement,
        integer,
        identifier,
        string_literal,
        value_keyword,
        value_intrinsic,
        // Assignment operators
        @"=",
        @"+=",
        @"-=",
        @"*=",
        @"/=",
        @"%=",
        @"&=",
        @"|=",
        @"^=",
        @"<<=",
        @">>=",
        // Comparison operators
        @"==",
        @"!=",
        @"<",
        @">",
        @"<=",
        @">=",
        // Logical AND
        @"and",
        @"and?",
        // Logical OR
        @"or",
        @"or?",
        // Add-like operators
        @"+",
        @"-",
        // Div-like operators
        @"*",
        @"/",
        @"%",
        // Bitwise operators
        @"&",
        @"|",
        @"^",
        // Shifting operators
        @"<<",
        @">>",
        // Logical NOT operator
        @"!",
        // Bitwise NOT operator
        @"~",
        // Pointer dereference
        @".&",
        // Parenthesis
        @"(",
        @")",
        // Bracket
        @"[",
        @"]",
        // Brace
        @"{",
        @"}",

        @",",
        @".",
        @"..",
        @"...",
    };

    const Integer = struct {
        value: u64,
        kind: Integer.Kind,

        const Kind = enum {
            hexadecimal,
            decimal,
            octal,
            binary,
        };
    };
};

pub const Abi = struct {
    const Kind = enum(u3) {
        ignore,
        direct,
        extend,
        indirect,
        indirect_aliased,
        expand,
        coerce_and_expand,
        in_alloca,
    };

    const RegisterCount = union {
        system_v: Abi.SystemV.RegisterCount,
    };

    const Flags = struct {
        kind: Abi.Kind,
        padding_in_reg: bool = false,
        in_alloca_sret: bool = false,
        in_alloca_indirect: bool = false,
        indirect_by_value: bool = false,
        indirect_realign: bool = false,
        sret_after_this: bool = false,
        in_reg: bool = false,
        can_be_flattened: bool = false,
        sign_extension: bool = false,
    };

    const Information = struct {
        semantic_type: *Type,
        coerce_to_type: ?*Type = null,
        padding: union {
            type: ?*Type,
            unpadded_coerce_and_expand_type: ?*Type,
        } = .{ .type = null },
        padding_arg_index: u16 = 0,
        attributes: union {
            direct: DirectAttributes,
            indirect: IndirectAttributes,
            alloca_field_index: u32,
        } = .{
            .direct = .{
                .offset = 0,
                .alignment = 0,
            },
        },
        flags: Abi.Flags,
        abi_start: u16 = 0,
        abi_count: u16 = 0,

        const DirectAttributes = struct {
            offset: u32,
            alignment: u32,
        };

        const IndirectAttributes = struct {
            alignment: u32,
            address_space: u32,
        };

        const Direct = struct {
            semantic_type: *Type,
            type: *Type,
            padding: ?*Type = null,
            offset: u32 = 0,
            alignment: u32 = 0,
            can_be_flattened: bool = true,
        };

        pub fn get_direct(module: *Module, direct: Direct) Information {
            var result = Information{
                .semantic_type = direct.semantic_type,
                .flags = .{
                    .kind = .direct,
                },
            };
            _ = direct.semantic_type.resolve(module);
            _ = direct.semantic_type.resolve(module);
            if (direct.padding) |p| _ = p.resolve(module);
            result.set_coerce_to_type(direct.type);
            result.set_padding_type(direct.padding);
            result.set_direct_offset(direct.offset);
            result.set_direct_alignment(direct.alignment);
            result.set_can_be_flattened(direct.can_be_flattened);
            return result;
        }

        pub const Ignore = struct {
            semantic_type: *Type,
        };

        pub fn get_ignore(module: *Module, ignore: Ignore) Information {
            _ = ignore.semantic_type.resolve(module);
            return Information{
                .semantic_type = ignore.semantic_type,
                .flags = .{
                    .kind = .ignore,
                },
            };
        }

        const Extend = struct {
            semantic_type: *Type,
            type: ?*Type = null,
            sign: bool,
        };

        pub fn get_extend(extend: Extend) Information {
            assert(extend.semantic_type.is_integral_or_enumeration_type());
            var result = Information{
                .semantic_type = extend.semantic_type,
                .flags = .{
                    .kind = .extend,
                },
            };
            result.set_coerce_to_type(if (extend.type) |t| t else extend.semantic_type);
            result.set_padding_type(null);
            result.set_direct_offset(0);
            result.set_direct_alignment(0);
            result.flags.sign_extension = extend.sign;
            return result;
        }

        const NaturalAlignIndirect = struct {
            semantic_type: *Type,
            padding_type: ?*Type = null,
            by_value: bool = true,
            realign: bool = false,
        };

        pub fn get_natural_align_indirect(nai: NaturalAlignIndirect) Abi.Information {
            const alignment = nai.semantic_type.get_byte_alignment();
            return get_indirect(.{
                .semantic_type = nai.semantic_type,
                .alignment = alignment,
                .by_value = nai.by_value,
                .realign = nai.realign,
                .padding_type = nai.padding_type,
            });
        }

        pub const Indirect = struct {
            semantic_type: *Type,
            padding_type: ?*Type = null,
            alignment: u32,
            by_value: bool = true,
            realign: bool = false,
        };

        pub fn get_indirect(indirect: Indirect) Abi.Information {
            var result = Abi.Information{
                .semantic_type = indirect.semantic_type,
                .attributes = .{
                    .indirect = .{
                        .address_space = 0,
                        .alignment = 0,
                    },
                },
                .flags = .{
                    .kind = .indirect,
                },
            };
            result.set_indirect_align(indirect.alignment);
            result.set_indirect_by_value(indirect.by_value);
            result.set_indirect_realign(indirect.realign);
            result.set_sret_after_this(false);
            result.set_padding_type(indirect.padding_type);
            return result;
        }

        fn set_sret_after_this(abi: *Abi.Information, sret_after_this: bool) void {
            assert(abi.flags.kind == .indirect);
            abi.flags.sret_after_this = sret_after_this;
        }

        fn set_indirect_realign(abi: *Abi.Information, realign: bool) void {
            assert(abi.flags.kind == .indirect);
            abi.flags.indirect_realign = realign;
        }

        fn set_indirect_by_value(abi: *Abi.Information, by_value: bool) void {
            assert(abi.flags.kind == .indirect);
            abi.flags.indirect_by_value = by_value;
        }

        fn set_indirect_align(abi: *Abi.Information, alignment: u32) void {
            assert(abi.flags.kind == .indirect or abi.flags.kind == .indirect_aliased);
            abi.attributes.indirect.alignment = alignment;
        }

        fn set_coerce_to_type(info: *Information, coerce_to_type: *Type) void {
            assert(info.can_have_coerce_to_type());
            info.coerce_to_type = coerce_to_type;
        }

        fn get_coerce_to_type(info: *const Information) *Type {
            assert(info.can_have_coerce_to_type());
            return info.coerce_to_type.?;
        }

        fn can_have_coerce_to_type(info: *const Information) bool {
            return switch (info.flags.kind) {
                .direct, .extend, .coerce_and_expand => true,
                else => false,
            };
        }

        fn set_padding_type(info: *Information, padding_type: ?*Type) void {
            assert(info.can_have_padding_type());
            info.padding = .{
                .type = padding_type,
            };
        }

        fn can_have_padding_type(info: *const Information) bool {
            return switch (info.flags.kind) {
                .direct, .extend, .indirect, .indirect_aliased, .expand => true,
                else => false,
            };
        }

        fn get_padding_type(info: *const Information) ?*Type {
            return if (info.can_have_padding_type()) info.padding.type else null;
        }

        fn set_direct_offset(info: *Information, offset: u32) void {
            assert(info.flags.kind == .direct or info.flags.kind == .extend);
            info.attributes.direct.offset = offset;
        }

        fn set_direct_alignment(info: *Information, alignment: u32) void {
            assert(info.flags.kind == .direct or info.flags.kind == .extend);
            info.attributes.direct.alignment = alignment;
        }

        fn set_can_be_flattened(info: *Information, can_be_flattened: bool) void {
            assert(info.flags.kind == .direct);
            info.flags.can_be_flattened = can_be_flattened;
        }

        fn get_can_be_flattened(info: *const Information) bool {
            assert(info.flags.kind == .direct);
            return info.flags.can_be_flattened;
        }
    };

    pub const SystemV = struct {
        pub const RegisterCount = struct {
            gpr: u32,
            sse: u32,
        };

        pub const Class = enum {
            integer,
            sse,
            sseup,
            x87,
            x87up,
            complex_x87,
            none,
            memory,

            fn merge(accumulator: Class, field: Class) Class {
                // AMD64-ABI 3.2.3p2: Rule 4. Each field of an object is
                // classified recursively so that always two fields are
                // considered. The resulting class is calculated according to
                // the classes of the fields in the eightbyte:
                //
                // (a) If both classes are equal, this is the resulting class.
                //
                // (b) If one of the classes is NO_CLASS, the resulting class is
                // the other class.
                //
                // (c) If one of the classes is MEMORY, the result is the MEMORY
                // class.
                //
                // (d) If one of the classes is INTEGER, the result is the
                // INTEGER.
                //
                // (e) If one of the classes is X87, X87UP, COMPLEX_X87 class,
                // MEMORY is used as class.
                //
                // (f) Otherwise class SSE is used.

                // Accum should never be memory (we should have returned) or
                // ComplexX87 (because this cannot be passed in a structure).

                assert(accumulator != .memory and accumulator != .complex_x87);
                if (accumulator == field or field == .none) {
                    return accumulator;
                }

                if (field == .memory) {
                    return .memory;
                }

                if (accumulator == .none) {
                    return field;
                }

                if (accumulator == .integer or field == .integer) {
                    return .integer;
                }

                if (field == .x87 or field == .x87up or field == .complex_x87 or accumulator == .x87 or accumulator == .x87up) {
                    return .memory;
                }

                return .sse;
            }
        };

        const ClassifyOptions = struct {
            base_offset: u64,
            is_named_argument: bool,
            is_register_call: bool = false,
        };

        fn classify(ty: *Type, options: ClassifyOptions) [2]Class {
            var result = [2]Class{ .none, .none };

            const is_memory = options.base_offset >= 8;
            const current_index = @intFromBool(is_memory);
            const not_current_index = @intFromBool(!is_memory);
            assert(current_index != not_current_index);
            result[current_index] = .memory;

            switch (ty.bb) {
                .void, .noreturn => result[current_index] = .none,
                .bits => |bits| return classify(bits.backing_type, options),
                .enumerator => |enumerator| return classify(enumerator.backing_type, options),
                .pointer => result[current_index] = .integer,
                .integer => |integer| {
                    if (integer.bit_count <= 64) {
                        result[current_index] = .integer;
                    } else if (integer.bit_count == 128) {
                        @trap();
                    } else {
                        @trap();
                    }
                },
                .structure => |struct_type| {
                    if (struct_type.byte_size <= 64) {
                        const has_variable_array = false;
                        if (!has_variable_array) {
                            // const struct_type = ty.get_payload(.@"struct");
                            result[current_index] = .none;
                            const is_union = false;
                            var member_offset: u32 = 0;
                            for (struct_type.fields) |field| {
                                const offset = options.base_offset + member_offset;
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

                                const member_classes = classify(field.type, .{
                                    .base_offset = offset,
                                    .is_named_argument = false,
                                });
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
                        if (options.base_offset % ty.get_byte_alignment() == 0) {
                            result[current_index] = .none;

                            const vector_size = 16;
                            if (ty.get_byte_size() > 16 and (ty.get_byte_size() != array_type.element_type.get_byte_size() or ty.get_byte_size() > vector_size)) {
                                unreachable;
                            } else {
                                var offset = options.base_offset;

                                for (0..array_type.element_count) |_| {
                                    const element_classes = classify(array_type.element_type, .{
                                        .base_offset = offset,
                                        .is_named_argument = false,
                                    });
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
                .alias => |alias| return classify(alias.type, options),
                else => @trap(),
            }

            return result;
        }

        fn classify_post_merge(aggregate_size: u64, classes: [2]Class) [2]Class {
            // AMD64-ABI 3.2.3p2: Rule 5. Then a post merger cleanup is done:
            //
            // (a) If one of the classes is Memory, the whole argument is passed in
            //     memory.
            //
            // (b) If X87UP is not preceded by X87, the whole argument is passed in
            //     memory.
            //
            // (c) If the size of the aggregate exceeds two eightbytes and the first
            //     eightbyte isn't SSE or any other eightbyte isn't SSEUP, the whole
            //     argument is passed in memory. NOTE: This is necessary to keep the
            //     ABI working for processors that don't support the __m256 type.
            //
            // (d) If SSEUP is not preceded by SSE or SSEUP, it is converted to SSE.
            //
            // Some of these are enforced by the merging logic.  Others can arise
            // only with unions; for example:
            //   union { _Complex double; unsigned; }
            //
            // Note that clauses (b) and (c) were added in 0.98.

            var result = classes;
            if (result[1] == .memory) {
                result[0] = .memory;
            }

            if (result[1] == .x87up) {
                @trap();
            }

            if (aggregate_size > 16 and (result[0] != .sse or result[1] != .sseup)) {
                result[0] = .memory;
            }

            if (result[1] == .sseup and result[0] != .sse) {
                result[0] = .sse;
            }

            return result;
        }

        fn get_int_type_at_offset(module: *Module, ty: *Type, offset: u32, source_type: *Type, source_offset: u32) *Type {
            switch (ty.bb) {
                .enumerator => |enumerator| {
                    return get_int_type_at_offset(module, enumerator.backing_type, offset, if (source_type == ty) enumerator.backing_type else source_type, source_offset);
                },
                .bits => |bits| {
                    return get_int_type_at_offset(module, bits.backing_type, offset, if (source_type == ty) bits.backing_type else source_type, source_offset);
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
                        else => {
                            const original_byte_count = ty.get_byte_size();
                            assert(original_byte_count != source_offset);
                            const byte_count = @min(original_byte_count - source_offset, 8);
                            const bit_count = byte_count * 8;
                            return module.integer_type(@intCast(bit_count), integer_type.signed);
                        },
                    }
                },
                .pointer => return if (offset == 0) ty else @trap(),
                .structure => {
                    if (get_member_at_offset(ty, offset)) |field| {
                        // TODO: this is a addition of mine, since we don't allow arbitrary-bit fields inside structs
                        const field_type = switch (field.type.bb) {
                            .integer, .enumerator => module.align_integer_type(field.type),
                            else => field.type,
                        };
                        return get_int_type_at_offset(module, field_type, @intCast(offset - field.byte_offset), source_type, source_offset);
                    }
                    unreachable;
                },
                .array => |array_type| {
                    const element_type = array_type.element_type;
                    const element_size = element_type.get_byte_size();
                    const element_offset = (offset / element_size) * element_size;
                    return get_int_type_at_offset(module, element_type, @intCast(offset - element_offset), source_type, source_offset);
                },
                .alias => |alias| return get_int_type_at_offset(module, alias.type, offset, if (ty == source_type) alias.type else source_type, source_offset),
                else => |t| @panic(@tagName(t)),
            }

            if (source_type.get_byte_size() - source_offset > 8) {
                return module.integer_type(64, false);
            } else {
                const byte_count = source_type.get_byte_size() - source_offset;
                const bit_count = byte_count * 8;
                return module.integer_type(@intCast(bit_count), false);
            }
        }

        fn get_member_at_offset(ty: *Type, offset: u32) ?*const Type.Struct.Field {
            if (ty.get_byte_size() <= offset) {
                return null;
            }

            var offset_it: u32 = 0;
            var last_match: ?*const Type.Struct.Field = null;

            const struct_type = &ty.bb.structure;
            for (struct_type.fields) |*field| {
                if (offset_it > offset) {
                    break;
                }

                last_match = field;
                offset_it = @intCast(lib.align_forward_u64(offset_it + field.type.get_byte_size(), ty.get_byte_alignment()));
            }

            assert(last_match != null);
            return last_match;
        }

        fn contains_no_user_data(ty: *Type, start: u64, end: u64) bool {
            if (ty.get_byte_size() <= start) {
                return true;
            }

            switch (ty.bb) {
                .structure => |*struct_type| {
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
                    for (0..array_type.element_count) |i| {
                        const offset = i * array_type.element_type.get_byte_size();
                        if (offset >= end) break;
                        const element_start = if (offset < start) start - offset else 0;
                        if (!contains_no_user_data(array_type.element_type, element_start, end - offset)) return false;
                    }

                    return true;
                },
                else => return false,
            }
        }

        const ArgumentOptions = struct {
            available_gpr: u32,
            is_named_argument: bool,
            is_reg_call: bool,
        };

        pub fn classify_argument_type(module: *Module, argument_type: *Type, options: ArgumentOptions) struct { Abi.Information, Abi.SystemV.RegisterCount } {
            const classes = classify(argument_type, .{
                .base_offset = 0,
                .is_named_argument = options.is_named_argument,
            });
            assert(classes[1] != .memory or classes[0] == .memory);
            assert(classes[1] != .sseup or classes[0] == .sse);
            var needed_registers = Abi.SystemV.RegisterCount{
                .gpr = 0,
                .sse = 0,
            };

            var low: ?*Type = null;
            switch (classes[0]) {
                .integer => {
                    needed_registers.gpr += 1;

                    const low_ty = Abi.SystemV.get_int_type_at_offset(module, argument_type, 0, argument_type, 0);
                    low = low_ty;

                    if (classes[1] == .none and low_ty.bb == .integer) {
                        // TODO:
                        // if (argument_type.bb == .enumerator) {
                        //     @trap();
                        // }

                        if (argument_type.is_integral_or_enumeration_type() and argument_type.is_promotable_integer_type_for_abi()) {
                            return .{
                                Abi.Information.get_extend(.{
                                    .semantic_type = argument_type,
                                    .sign = argument_type.is_signed(),
                                }),
                                needed_registers,
                            };
                        }
                    }
                },
                .memory, .x87, .complex_x87 => {
                    // TODO: CXX ABI: RAA_Indirect
                    return .{ get_indirect_result(module, argument_type, options.available_gpr), needed_registers };
                },
                else => @trap(),
            }

            var high: ?*Type = null;
            switch (classes[1]) {
                .none => {},
                .integer => {
                    needed_registers.gpr += 1;
                    const high_ty = Abi.SystemV.get_int_type_at_offset(module, argument_type, 8, argument_type, 8);
                    high = high_ty;

                    if (classes[0] == .none) {
                        @trap();
                    }
                },
                else => @trap(),
            }

            const result_type = if (high) |hi| get_by_val_argument_pair(module, low orelse unreachable, hi) else low orelse unreachable;
            return .{
                Abi.Information.get_direct(module, .{
                    .semantic_type = argument_type,
                    .type = result_type,
                }),
                needed_registers,
            };
        }

        const ClassifyArgument = struct {
            type: *Type,
            abi_start: u16,
            is_reg_call: bool = false,
            is_named_argument: bool,
        };

        pub fn classify_argument(module: *Module, available_registers: *Abi.RegisterCount, llvm_abi_argument_type_buffer: []*llvm.Type, abi_argument_type_buffer: []*Type, options: ClassifyArgument) Abi.Information {
            const semantic_argument_type = options.type;
            const result = if (options.is_reg_call) @trap() else Abi.SystemV.classify_argument_type(module, semantic_argument_type, .{
                .is_named_argument = options.is_named_argument,
                .is_reg_call = options.is_reg_call,
                .available_gpr = available_registers.system_v.gpr,
            });
            const abi = result[0];
            const needed_registers = result[1];

            var argument_type_abi = switch (available_registers.system_v.gpr >= needed_registers.gpr and available_registers.system_v.sse >= needed_registers.sse) {
                true => blk: {
                    available_registers.system_v.gpr -= needed_registers.gpr;
                    available_registers.system_v.sse -= needed_registers.sse;
                    break :blk abi;
                },
                false => Abi.SystemV.get_indirect_result(module, semantic_argument_type, available_registers.system_v.gpr),
            };

            if (argument_type_abi.get_padding_type() != null) {
                @trap();
            }

            argument_type_abi.abi_start = options.abi_start;

            const count = switch (argument_type_abi.flags.kind) {
                .direct, .extend => blk: {
                    const coerce_to_type = argument_type_abi.get_coerce_to_type();
                    coerce_to_type.resolve(module);
                    const flattened_struct = argument_type_abi.flags.kind == .direct and argument_type_abi.get_can_be_flattened() and coerce_to_type.bb == .structure;

                    const count: u16 = switch (flattened_struct) {
                        false => 1,
                        true => @intCast(argument_type_abi.get_coerce_to_type().bb.structure.fields.len),
                    };

                    switch (flattened_struct) {
                        false => {
                            llvm_abi_argument_type_buffer[argument_type_abi.abi_start] = coerce_to_type.llvm.abi.?;
                            abi_argument_type_buffer[argument_type_abi.abi_start] = coerce_to_type;
                        },
                        true => {
                            for (coerce_to_type.bb.structure.fields, 0..) |field, field_index| {
                                field.type.resolve(module);
                                const index = argument_type_abi.abi_start + field_index;
                                llvm_abi_argument_type_buffer[index] = field.type.llvm.abi.?;
                                abi_argument_type_buffer[index] = field.type;
                            }
                        },
                    }

                    break :blk count;
                },
                .indirect => blk: {
                    const indirect_type = module.get_pointer_type(.{ .type = argument_type_abi.semantic_type });
                    abi_argument_type_buffer[argument_type_abi.abi_start] = indirect_type;
                    indirect_type.resolve(module);
                    llvm_abi_argument_type_buffer[argument_type_abi.abi_start] = indirect_type.llvm.abi.?;
                    break :blk 1;
                },
                else => |t| @panic(@tagName(t)),
            };

            argument_type_abi.abi_count = count;

            return argument_type_abi;
        }

        pub fn get_by_val_argument_pair(module: *Module, low: *Type, high: *Type) *Type {
            const low_size = low.get_byte_allocation_size();
            const high_alignment = high.get_byte_alignment();
            const high_start = lib.align_forward_u64(low_size, high_alignment);
            assert(high_start != 0 and high_start <= 8);

            const new_low = if (high_start != 8) {
                @trap();
            } else low;
            const result = module.get_anonymous_struct_pair(.{ new_low, high });
            assert(result.bb.structure.fields[1].byte_offset == 8);
            return result;
        }

        pub fn classify_return_type(module: *Module, return_type: *Type) Abi.Information {
            const classes = classify(return_type, .{
                .base_offset = 0,
                .is_named_argument = true,
            });
            assert(classes[1] != .memory or classes[0] == .memory);
            assert(classes[1] != .sseup or classes[0] == .sse);

            var low: ?*Type = null;

            switch (classes[0]) {
                .none => {
                    if (classes[1] == .none) {
                        return Abi.Information.get_ignore(module, .{
                            .semantic_type = return_type,
                        });
                    }

                    @trap();
                },
                .integer => {
                    const low_ty = Abi.SystemV.get_int_type_at_offset(module, return_type, 0, return_type, 0);
                    low = low_ty;

                    if (classes[1] == .none and low_ty.bb == .integer) {
                        if (return_type.bb == .enumerator) {
                            @trap();
                        }

                        if (return_type.is_integral_or_enumeration_type() and return_type.is_promotable_integer_type_for_abi()) {
                            return Abi.Information.get_extend(.{
                                .semantic_type = return_type,
                                .sign = return_type.is_signed(),
                            });
                        }
                    }
                },
                .memory => {
                    return Abi.SystemV.get_indirect_return_result(.{ .type = return_type });
                },
                else => @trap(),
            }

            var high: ?*Type = null;

            switch (classes[1]) {
                .none => {},
                .integer => {
                    const high_offset = 8;
                    const high_ty = Abi.SystemV.get_int_type_at_offset(module, return_type, high_offset, return_type, high_offset);
                    high = high_ty;
                    if (classes[0] == .none) {
                        return Abi.Information.get_direct(module, .{
                            .semantic_type = return_type,
                            .type = high_ty,
                            .offset = high_offset,
                        });
                    }
                },
                else => @trap(),
            }

            if (high) |hi| {
                low = Abi.SystemV.get_byval_argument_pair(module, .{ low orelse unreachable, hi });
            }

            return Abi.Information.get_direct(module, .{
                .semantic_type = return_type,
                .type = low orelse unreachable,
            });
        }

        pub fn get_byval_argument_pair(module: *Module, pair: [2]*Type) *Type {
            const low_size = pair[0].get_byte_size();
            const high_alignment = pair[1].get_byte_alignment();
            const high_offset = lib.align_forward_u64(low_size, high_alignment);
            assert(high_offset != 0 and high_offset <= 8);
            const low = if (high_offset != 8)
                if ((pair[0].bb == .float and pair[0].bb.float.kind == .half) or (pair[0].bb == .float and pair[0].bb.float.kind == .float)) {
                    @trap();
                } else {
                    assert(pair[0].is_integer_backing());
                    @trap();
                }
            else
                pair[0];
            const high = pair[1];
            const struct_type = module.get_anonymous_struct_pair(.{ low, high });
            assert(struct_type.bb.structure.fields[1].byte_offset == 8);

            return struct_type;
        }

        const IndirectReturn = struct {
            type: *Type,
        };

        pub fn get_indirect_return_result(indirect: IndirectReturn) Abi.Information {
            if (indirect.type.is_aggregate_type_for_abi()) {
                return Abi.Information.get_natural_align_indirect(.{
                    .semantic_type = indirect.type,
                });
            } else {
                @trap();
            }
        }

        pub fn get_indirect_result(module: *Module, ty: *Type, free_gpr: u32) Abi.Information {
            if (!ty.is_aggregate_type_for_abi() and !is_illegal_vector_type(ty) and !ty.is_arbitrary_bit_integer()) {
                return switch (ty.is_promotable_integer_type_for_abi()) {
                    true => @trap(),
                    false => Abi.Information.get_direct(module, .{
                        .semantic_type = ty,
                        .type = ty,
                    }),
                };
            } else {
                // TODO CXX ABI
                const alignment = @max(ty.get_byte_alignment(), 8);
                const size = ty.get_byte_size();
                return switch (free_gpr == 0 and alignment == 8 and size <= 8) {
                    true => @trap(),
                    false => Abi.Information.get_indirect(.{
                        .semantic_type = ty,
                        .alignment = alignment,
                    }),
                };
            }
        }

        pub fn is_illegal_vector_type(ty: *Type) bool {
            return switch (ty.bb) {
                .vector => @trap(),
                else => false,
            };
        }

        pub fn emit_va_arg_from_memory(module: *Module, va_list_pointer: *llvm.Value, va_list_struct: *Type, arg_type: *Type) *llvm.Value {
            const overflow_arg_area_pointer = module.llvm.builder.create_struct_gep(va_list_struct.llvm.abi.?.to_struct(), va_list_pointer, 2);
            const overflow_arg_area_type = va_list_struct.bb.structure.fields[2].type;
            const overflow_arg_area = module.create_load(.{ .type = overflow_arg_area_type, .value = overflow_arg_area_pointer });
            if (arg_type.get_byte_alignment() > 8) {
                @trap();
            }
            const arg_type_size = arg_type.get_byte_size();
            const raw_offset = lib.align_forward_u64(arg_type_size, 8);
            const offset = module.integer_type(32, false).llvm.abi.?.to_integer().get_constant(raw_offset, @intFromBool(false));
            const new_overflow_arg_area = module.llvm.builder.create_gep(.{
                .type = module.integer_type(8, false).llvm.abi.?,
                .aggregate = overflow_arg_area,
                .indices = &.{offset.to_value()},
                .inbounds = false,
            });
            _ = module.create_store(.{ .type = overflow_arg_area_type, .source_value = new_overflow_arg_area, .destination_value = overflow_arg_area_pointer });
            return overflow_arg_area;
        }
    };
};

pub fn compile(arena: *Arena, options: Options) void {
    var types = Type.Buffer.initialize();
    const void_type = types.append(.{
        .name = "void",
        .bb = .void,
    });

    for ([2]bool{ false, true }) |sign| {
        for (1..64 + 1) |bit_count| {
            const name_buffer = [3]u8{ if (sign) 's' else 'u', @intCast(if (bit_count < 10) bit_count % 10 + '0' else bit_count / 10 + '0'), if (bit_count > 9) @intCast(bit_count % 10 + '0') else 0 };
            const name_length = @as(u64, 2) + @intFromBool(bit_count > 9);

            const name = arena.duplicate_string(name_buffer[0..name_length]);

            const ty = types.append(.{
                .name = name,
                .bb = .{
                    .integer = .{
                        .bit_count = @intCast(bit_count),
                        .signed = sign,
                    },
                },
            });
            _ = ty;
        }
    }

    for ([2]bool{ false, true }) |sign| {
        const name = if (sign) "s128" else "u128";
        const ty = types.append(.{
            .name = name,
            .bb = .{
                .integer = .{
                    .bit_count = 128,
                    .signed = sign,
                },
            },
        });
        _ = ty;
    }

    const noreturn_type = types.append(.{
        .name = "noreturn",
        .bb = .noreturn,
    });

    const globals = Global.Buffer.initialize();
    var values = Value.Buffer.initialize();
    const void_value = values.add();
    void_value.* = .{
        .bb = .infer_or_ignore,
        .type = void_type,
    };

    var module = Module{
        .arena = arena,
        .content = options.content,
        .has_debug_info = options.has_debug_info,
        .offset = 0,
        .line_offset = 0,
        .line_character_offset = 0,
        .types = types,
        .globals = globals,
        .locals = .initialize(),
        .values = values,
        .macros = .initialize(),
        .pointer_types = .initialize(),
        .slice_types = .initialize(),
        .pair_struct_types = .initialize(),
        .array_types = .initialize(),
        .lexical_blocks = .initialize(),
        .statements = .initialize(),
        .void_type = void_type,
        .noreturn_type = noreturn_type,
        .void_value = void_value,
        .scope = .{
            .kind = .global,
            .column = 0,
            .line = 0,
            .parent = null,
        },
        .name = options.name,
        .path = options.path,
        .executable = options.executable,
        .objects = options.objects,
        .target = options.target,
        .build_mode = options.build_mode,
        .silent = options.silent,
    };

    module.parse();
    module.emit();
}
