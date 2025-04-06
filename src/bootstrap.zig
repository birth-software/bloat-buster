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
    is_argument: bool,

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

pub const Type = struct {
    bb: union(enum) {
        void,
        noreturn,
        integer: Type.Integer,
        enumerator,
        float,
        bits,
        pointer: Type.Pointer,
        function: Type.Function,
        array,
        structure: Type.Struct,
        vector,
    },
    name: []const u8,
    llvm: struct {
        handle: ?*llvm.Type = null,
        debug: ?*llvm.DI.Type = null,
    } = .{},

    pub const Integer = struct {
        bit_count: u32,
        signed: bool,
    };

    pub const Pointer = struct {
        type: *Type,
        alignment: u32,
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
        fields: []Field,
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
            // .bits => |bits| bits.backing_type.is_signed(),
            else => @trap(),
        };
    }

    pub fn is_integral_or_enumeration_type(ty: *Type) bool {
        return switch (ty.bb) {
            .integer => true,
            // .bits => true,
            // .structure => false,
            else => @trap(),
        };
    }

    pub fn is_arbitrary_bit_integer(ty: *Type) bool {
        return switch (ty.bb) {
            .integer => |integer| switch (integer.bit_count) {
                8, 16, 32, 64, 128 => false,
                else => true,
            },
            .bits => @trap(),
            // .bits => |bits| bits.backing_type.is_arbitrary_bit_integer(),
            else => false,
        };
    }

    pub fn is_promotable_integer_type_for_abi(ty: *Type) bool {
        return switch (ty.bb) {
            .integer => |integer| integer.bit_count < 32,
            // .bits => |bits| bits.backing_type.is_promotable_integer_type_for_abi(),
            else => @trap(),
        };
    }

    pub fn get_byte_alignment(ty: *const Type) u32 {
        const result: u32 = switch (ty.bb) {
            .void => unreachable,
            .integer => |integer| @intCast(@min(@divExact(@max(8, lib.next_power_of_two(integer.bit_count)), 8), 16)),
            .pointer => 8,
            .function => 1,
            else => @trap(),
        };
        return result;
    }

    pub fn get_bit_alignment(ty: *const Type) u32 {
        _ = ty;
        @trap();
    }

    pub fn get_byte_size(ty: *const Type) u64 {
        const byte_size: u64 = switch (ty.bb) {
            .integer => |integer| @max(8, lib.next_power_of_two(integer.bit_count)),
            else => @trap(),
        };
        return byte_size;
    }
    pub fn get_bit_size(ty: *const Type) u64 {
        _ = ty;
        @trap();
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
            .structure, .array => .aggregate,
            .integer, .bits, .pointer, .enumerator => .scalar,
            else => @trap(),
        };
    }

    pub fn is_abi_equal(ty: *const Type, other: *const Type) bool {
        return ty == other or ty.llvm.handle.? == other.llvm.handle.?;
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
    },
    line: u32,
    column: u32,
};

const Unary = struct {
    value: *Value,
    id: Id,

    const Id = enum {
        @"-",
        @"+",
        @"&",
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
    };
};

fn negate_llvm_value(value: *llvm.Value, is_constant: bool) *llvm.Value {
    return switch (is_constant) {
        true => value.to_constant().negate().to_value(),
        false => @trap(),
    };
}

pub const Value = struct {
    bb: union(enum) {
        function: Function,
        constant_integer: ConstantInteger,
        unary: Unary,
        binary: Binary,
        variable_reference: *Variable,
        local,
    },
    type: ?*Type = null,
    llvm: ?*llvm.Value = null,

    fn is_constant(value: *Value) bool {
        return switch (value.bb) {
            .constant_integer => true,
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

    const Intrinsic = enum {
        byte_size,
        cast,
        cast_to,
        extend,
        integer_max,
        int_from_enum,
        int_from_pointer,
        pointer_cast,
        select,
        trap,
        truncate,
        va_start,
        va_end,
        va_copy,
        va_arg,
    };

    const Builder = struct {
        kind: Kind = .right,
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

        fn with_kind(vb: Builder, kind: Kind) Builder {
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
    @"fn",
    @"struct",
    bits,
    @"enum",
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
    kind: Kind,
    parent: ?*Scope = null,

    pub const Kind = enum {
        global,
        function,
        local,
    };
};

pub const LexicalBlock = struct {
    locals: lib.VirtualBuffer(*Local),
    statements: lib.VirtualBuffer(*Statement),
    scope: Scope,
};

pub const Function = struct {
    arguments: Local.Buffer,
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
    pointer_types: IndexBuffer,
    void_type: *Type,
    noreturn_type: *Type,
    lexical_blocks: lib.VirtualBuffer(LexicalBlock),
    statements: lib.VirtualBuffer(Statement),
    current_function: ?*Global = null,
    current_scope: *Scope,
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

    const AttributeBuildOptions = struct {
        return_type_abi: Abi.Information,
        abi_argument_types: []const *Type,
        argument_type_abis: []const Abi.Information,
        abi_return_type: *Type,
        attributes: Function.Attributes,
        call_site: bool,
    };

    pub fn build_attribute_list(module: *Module, options: AttributeBuildOptions) *llvm.Attribute.List {
        const return_attributes = llvm.Attribute.Argument{
            .semantic_type = options.return_type_abi.semantic_type.llvm.handle.?,
            .abi_type = options.abi_return_type.llvm.handle.?,
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
                .semantic_type = options.return_type_abi.semantic_type.llvm.handle.?,
                .abi_type = options.abi_argument_types[abi_index].llvm.handle.?,
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
                argument_attribute.* = .{
                    .semantic_type = argument_type_abi.semantic_type.llvm.handle.?,
                    .abi_type = options.abi_argument_types[abi_index].llvm.handle.?,
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
                .definition_frame_pointer_kind = .none,
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
            .alignment = if (pointer.alignment) |a| a else pointer.type.get_byte_alignment(),
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
                    @trap();
                    // return module.noreturn_type;
                } else {
                    const ty = module.types.find_by_name(identifier) orelse @trap();
                    return ty;
                }
            },
            else => @trap(),
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
        @"while",
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

        assert(count == r.len);
        break :blk r;
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
                const token: Token = if (lib.string.to_enum(Value.Keyword, identifier)) |value_keyword| .{ .value_keyword = value_keyword } else .{ .identifier = identifier };
                break :blk token;
            },
            '#' => if (is_identifier_start_ch(module.content[module.offset + 1])) blk: {
                module.offset += 1;
                const value_intrinsic_identifier = module.parse_identifier();
                const value_intrinsic = lib.string.to_enum(Value.Intrinsic, value_intrinsic_identifier) orelse module.report_error();
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
                    else => .decimal,
                };
                const value: u64 = switch (token_integer_kind) {
                    .decimal => switch (next_ch) {
                        0...9 => module.report_error(),
                        else => b: {
                            module.offset += 1;
                            break :b 0;
                        },
                    },
                    else => @trap(),
                };

                if (module.content[module.offset] == '.') {
                    @trap();
                } else {
                    break :blk .{ .integer = .{ .value = value, .kind = token_integer_kind } };
                }
            },
            '1'...'9' => blk: {
                const decimal = module.parse_decimal();
                if (module.content[module.offset] == '.') {
                    @trap();
                } else {
                    break :blk .{ .integer = .{ .value = decimal, .kind = .decimal } };
                }
            },
            '+', '-', '*', '/', '%', '&', '|', '^' => |c| blk: {
                const next_ch = module.content[start_index + 1];
                const token_id: Token.Id = switch (next_ch) {
                    '=' => @trap(),
                    else => switch (c) {
                        '+' => .@"+",
                        '-' => .@"-",
                        '*' => .@"*",
                        '/' => .@"/",
                        '%' => .@"%",
                        '&' => .@"&",
                        '|' => .@"|",
                        '^' => .@"^",
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
                    '&' => .@".&",
                    else => @trap(),
                };

                module.offset += switch (token_id) {
                    .@".&" => 2,
                    else => @trap(),
                };
                const token = switch (token_id) {
                    else => unreachable,
                    inline .@".&",
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
            '(' => blk: {
                module.offset += 1;
                break :blk .@"(";
            },
            ')' => blk: {
                module.offset += 1;
                break :blk .@")";
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

        const Function = fn (noalias module: *Module, value_builder: Value.Builder) *Value;
    };

    fn parse_value(module: *Module, value_builder: Value.Builder) *Value {
        assert(value_builder.precedence == .none);
        assert(value_builder.left == null);
        const value = module.parse_precedence(value_builder.with_precedence(.assignment));
        return value;
    }

    fn parse_precedence(module: *Module, value_builder: Value.Builder) *Value {
        assert(value_builder.token == .none);
        const token = module.tokenize();
        const rule = &rules[@intFromEnum(token)];
        if (rule.before) |before| {
            const left = before(module, value_builder.with_precedence(.none).with_token(token));
            const result = module.parse_precedence_left(value_builder.with_left(left));
            return result;
        } else {
            module.report_error();
        }
    }

    fn parse_precedence_left(module: *Module, value_builder: Value.Builder) *Value {
        var result = value_builder.left;
        _ = &result;
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
            const new = after_rule(module, value_builder.with_token(token).with_precedence(.none).with_left(old));
            result = new;
        }

        return result.?;
    }

    fn parse_block(module: *Module) *LexicalBlock {
        const parent_scope = module.current_scope;
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
        module.current_scope = &block.scope;
        defer module.current_scope = parent_scope;

        module.expect_character(left_brace);

        while (true) {
            module.skip_space();

            if (module.offset == module.content.len) {
                break;
            }

            if (module.consume_character_if_match(right_brace)) {
                break;
            }

            const statement_line = module.get_line();
            const statement_column = module.get_column();

            const statement_start_character = module.content[module.offset];
            const statement = module.statements.add();
            const require_semicolon = true;
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
                        const local_value = module.parse_value(.{});
                        const local = module.locals.add();
                        local.* = .{
                            .variable = .{
                                .initial_value = local_value,
                                .type = local_type,
                                .name = local_name,
                                .line = statement_line,
                                .column = statement_column,
                                .scope = module.current_scope,
                            },
                            .is_argument = false,
                        };
                        assert(module.current_scope == &block.scope);
                        _ = block.locals.append(local);
                        break :blk .{
                            .local = local,
                        };
                    },
                    '#' => {
                        @trap();
                    },
                    'A'...'Z', 'a'...'z' => blk: {
                        const statement_start_identifier = module.parse_identifier();

                        if (lib.string.to_enum(StatementStartKeyword, statement_start_identifier)) |statement_start_keyword| {
                            switch (statement_start_keyword) {
                                ._ => @trap(),
                                .@"return" => break :blk .{
                                    .@"return" = module.parse_value(.{}),
                                },
                                .@"if" => {
                                    @trap();
                                },
                                .@"while" => {
                                    @trap();
                                },
                            }
                        }

                        @trap();
                    },
                    else => @trap(),
                },
                .line = statement_line,
                .column = statement_column,
            };
            _ = block.statements.append(statement);

            if (require_semicolon) {
                module.expect_character(';');
            }
        }

        return block;
    }

    fn rule_before_identifier(noalias module: *Module, value_builder: Value.Builder) *Value {
        const identifier = value_builder.token.identifier;
        assert(!lib.string.equal(identifier, ""));
        assert(!lib.string.equal(identifier, "_"));

        var scope_it: ?*Scope = module.current_scope;
        const variable = blk: while (scope_it) |scope| : (scope_it = scope.parent) {
            switch (scope.kind) {
                .global => {
                    @trap();
                },
                .function => {
                    @trap();
                },
                .local => {
                    const block: *LexicalBlock = @fieldParentPtr("scope", scope);
                    for (block.locals.get_slice()) |local| {
                        if (lib.string.equal(local.variable.name, identifier)) {
                            break :blk &local.variable;
                        }
                    }
                },
            }
        } else {
            module.report_error();
        };
        const value = module.values.add();
        value.* = .{
            .bb = .{
                .variable_reference = variable,
            },
        };
        return value;
    }

    fn rule_before_value_keyword(noalias module: *Module, value_builder: Value.Builder) *Value {
        _ = value_builder;
        _ = module;
        @trap();
    }

    fn rule_before_value_intrinsic(noalias module: *Module, value_builder: Value.Builder) *Value {
        _ = module;
        _ = value_builder;
        @trap();
    }

    fn rule_before_integer(noalias module: *Module, value_builder: Value.Builder) *Value {
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

    fn rule_after_binary(noalias module: *Module, value_builder: Value.Builder) *Value {
        const binary_operator_token = value_builder.token;
        const binary_operator_token_precedence = rules[@intFromEnum(binary_operator_token)].precedence;
        const left = value_builder.left orelse module.report_error();
        assert(binary_operator_token_precedence != .assignment); // TODO: this may be wrong. Assignment operator is not allowed in expressions
        const right_precedence = if (binary_operator_token_precedence == .assignment) .assignment else binary_operator_token_precedence.increment();
        const right = module.parse_precedence(value_builder.with_precedence(right_precedence).with_token(.none).with_left(null));

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

    fn rule_before_unary(noalias module: *Module, value_builder: Value.Builder) *Value {
        assert(value_builder.left == null);
        const unary_token = value_builder.token;
        const unary_id: Unary.Id = switch (unary_token) {
            .none => unreachable,
            .@"-" => .@"-",
            .@"+" => .@"+",
            else => @trap(),
        };

        const right = module.parse_precedence(value_builder.with_precedence(.prefix).with_token(.none).with_kind(if (unary_id == .@"&") .left else value_builder.kind));

        const value = switch (unary_id) {
            .@"+" => @trap(),
            .@"-" => blk: {
                const value = module.values.add();
                value.* = .{
                    .bb = .{
                        .unary = .{
                            .id = unary_id,
                            .value = right,
                        },
                    },
                };
                break :blk value;
            },
            else => @trap(),
        };
        return value;
    }

    fn rule_after_dereference(noalias module: *Module, value_builder: Value.Builder) *Value {
        _ = module;
        _ = value_builder;
        @trap();
    }

    fn rule_before_parenthesis(noalias module: *Module, value_builder: Value.Builder) *Value {
        _ = module;
        _ = value_builder;
        @trap();
    }

    fn rule_after_call(noalias module: *Module, value_builder: Value.Builder) *Value {
        _ = module;
        _ = value_builder;
        @trap();
    }

    pub fn get_anonymous_struct_pair(module: *Module, pair: [2]*Type) *Type {
        _ = module;
        _ = pair;
        @trap();
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
                            _ = &is_var_args;

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

                            while (module.offset < module.content.len and module.content[module.offset] != right_parenthesis) : (semantic_argument_count += 1) {
                                module.skip_space();

                                @trap();
                            }

                            module.expect_character(right_parenthesis);
                            module.skip_space();

                            const return_type = module.parse_type();
                            // TODO
                            assert(semantic_argument_count == 0);
                            const argument_types: []const *Type = &.{};

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
                                        .arguments = .initialize(),
                                        .attributes = .{},
                                        .scope = .{
                                            .kind = .function,
                                            .line = global_line,
                                            .column = global_column,
                                        },
                                    },
                                };

                                const global_scope = module.current_scope;
                                module.current_scope = &storage.bb.function.scope;
                                defer module.current_scope = global_scope;

                                storage.bb.function.main_block = module.parse_block();
                            } else {
                                // TODO: initialize value.bb
                                @trap();
                            }
                        },
                        else => @trap(),
                    }
                } else {
                    module.offset -= global_string.len;
                }
            }
        }
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
        };
    }

    pub fn emit_block(module: *Module, function: *Global, block: *llvm.BasicBlock) void {
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
            function.variable.storage.?.llvm.?.to_function().append_basic_block(block);
        }

        module.llvm.builder.position_at_end(block);
    }

    pub fn emit(module: *Module) void {
        module.initialize_llvm();

        const llvm_pointer_type = module.llvm.context.get_pointer_type(0).to_type();
        const void_type = module.llvm.context.get_void_type();
        for (module.types.get_slice()) |*ty| {
            const llvm_type = switch (ty.bb) {
                .void, .noreturn => void_type,
                .integer => |integer| module.llvm.context.get_integer_type(integer.bit_count).to_type(),
                // Consider function types later since we need to deal with ABI
                .function => null,
                .pointer => llvm_pointer_type,
                else => @trap(),
            };
            ty.llvm.handle = llvm_type;

            if (module.has_debug_info) {
                const debug_type = switch (ty.bb) {
                    .void => module.llvm.di_builder.create_basic_type(ty.name, 0, .void, .{}),
                    .noreturn => module.llvm.di_builder.create_basic_type(ty.name, 0, .void, .{ .no_return = true }),
                    .integer => |integer| module.llvm.di_builder.create_basic_type(ty.name, integer.bit_count, switch (integer.signed) {
                        true => .signed,
                        false => .unsigned,
                    }, .{}),
                    .function => |function| blk: {
                        var debug_argument_type_buffer: [64]*llvm.DI.Type = undefined;
                        const semantic_debug_argument_types = debug_argument_type_buffer[0 .. function.semantic_argument_types.len + 1 + @intFromBool(function.is_var_args)];
                        semantic_debug_argument_types[0] = function.semantic_return_type.llvm.debug.?;

                        for (function.semantic_argument_types, semantic_debug_argument_types[1..][0..function.semantic_argument_types.len]) |semantic_type, *debug_argument_type| {
                            debug_argument_type.* = semantic_type.llvm.debug.?;
                        }

                        if (function.is_var_args) {
                            semantic_debug_argument_types[function.semantic_argument_types.len + 1] = module.void_type.llvm.debug.?;
                        }

                        const subroutine_type = module.llvm.di_builder.create_subroutine_type(module.llvm.file, semantic_debug_argument_types, .{});
                        break :blk subroutine_type.to_type();
                    },
                    .pointer => |pointer| module.llvm.di_builder.create_pointer_type(pointer.type.llvm.debug.?, 64, 64, 0, ty.name).to_type(),
                    else => @trap(),
                };
                ty.llvm.debug = debug_type;
            }
        }

        for (module.globals.get_slice()) |*global| {
            switch (global.variable.storage.?.bb) {
                .function => {
                    const function_type = &global.variable.storage.?.type.?.bb.pointer.type.bb.function;
                    const argument_variables = global.variable.storage.?.bb.function.arguments.get_slice();
                    function_type.argument_abis = module.arena.allocate(Abi.Information, argument_variables.len);

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

                            if (function_type.return_abi.flags.kind == .indirect) {
                                assert(!function_type.return_abi.flags.sret_after_this);
                                function_type.available_registers.system_v.gpr -= 1;
                                const indirect_type = module.get_pointer_type(.{ .type = function_type.return_abi.semantic_type });
                                abi_argument_type_buffer[abi_argument_type_count] = indirect_type;
                                llvm_abi_argument_type_buffer[abi_argument_type_count] = indirect_type.llvm.handle.?;
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
                    const llvm_function_type = llvm.Type.Function.get(function_type.abi_return_type.llvm.handle.?, llvm_abi_argument_types, function_type.is_var_args);

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
                    global.variable.storage.?.type.?.bb.pointer.type.llvm.handle = llvm_function_type.to_type();
                    global.variable.storage.?.type.?.bb.pointer.type.llvm.debug = subroutine_type.to_type();

                    const llvm_function_value = module.llvm.module.create_function(.{
                        .name = global.variable.name,
                        // TODO: make it better
                        .linkage = switch (global.linkage) {
                            .external => .ExternalLinkage,
                            .internal => .InternalLinkage,
                        },
                        .type = global.variable.storage.?.type.?.bb.pointer.type.llvm.handle.?.to_function(),
                    });

                    global.variable.storage.?.llvm = llvm_function_value.to_value();

                    llvm_function_value.set_calling_convention(function_type.calling_convention.to_llvm());

                    const attribute_list = module.build_attribute_list(.{
                        .abi_return_type = function_type.abi_return_type,
                        .abi_argument_types = function_type.abi_argument_types,
                        .argument_type_abis = function_type.argument_abis,
                        .return_type_abi = function_type.return_abi,
                        .attributes = global.variable.storage.?.bb.function.attributes,
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
                            else => @trap(),
                        };
                        const name = global.variable.name;
                        const linkage_name = name;
                        const subprogram = module.llvm.di_builder.create_function(module.scope.llvm.?, name, linkage_name, module.llvm.file, global.variable.line, subroutine_type, local_to_unit, is_definition, scope_line, flags, module.build_mode.is_optimized());
                        llvm_function_value.set_subprogram(subprogram);

                        break :blk @ptrCast(subprogram);
                    } else undefined;
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

                    // const argument_variables = global.value.bb.function.arguments.add_many(semantic_argument_count);
                    for (
                        //semantic_arguments,
                        function_type.argument_abis, argument_variables, 0..) |
                    //semantic_argument,
                    argument_abi, *argument_variable, argument_index| {
                        const abi_arguments = llvm_abi_arguments[argument_abi.abi_start..][0..argument_abi.abi_count];
                        assert(argument_abi.flags.kind == .ignore or argument_abi.abi_count != 0);
                        const argument_abi_kind = argument_abi.flags.kind;
                        const semantic_argument_storage = switch (argument_abi_kind) {
                            .direct, .extend => blk: {
                                const first_argument = abi_arguments[0];
                                const coerce_to_type = argument_abi.get_coerce_to_type();
                                if (coerce_to_type.bb != .structure and coerce_to_type.is_abi_equal(argument_abi.semantic_type) and argument_abi.attributes.direct.offset == 0) {
                                    assert(argument_abi.abi_count == 1);
                                    const is_promoted = false;
                                    var v = first_argument.to_value();
                                    v = switch (coerce_to_type.llvm.handle == v.get_type()) {
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
                                                    true => module.llvm.builder.create_sign_extend(first_argument.to_value(), destination_type.llvm.handle.?),
                                                    false => module.llvm.builder.create_zero_extend(first_argument.to_value(), destination_type.llvm.handle.?),
                                                },
                                                false => @trap(),
                                            };
                                            _ = module.create_store(.{ .source_value = result, .destination_value = alloca, .source_type = destination_type, .destination_type = destination_type });
                                            break :blk alloca;
                                        },
                                        false => { // TODO: ExtVectorBoolType
                                            const alloca = module.create_alloca(.{ .type = argument_abi.semantic_type, .name = argument_variable.variable.name });
                                            _ = module.create_store(.{ .source_value = first_argument.to_value(), .destination_value = alloca, .source_type = argument_abi.semantic_type, .destination_type = argument_abi.semantic_type });
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
                                                for (coerce_to_type.bb.structure.fields, abi_arguments, 0..) |field, abi_argument, field_index| {
                                                    const gep = module.llvm.builder.create_struct_gep(coerce_to_type.llvm.handle.?.to_struct(), address, @intCast(field_index));
                                                    // TODO: check if alignment is right
                                                    _ = module.create_store(.{ .source_value = abi_argument.to_value(), .destination_value = gep, .source_type = field.type, .destination_type = field.type });
                                                }

                                                if (source_size > destination_size) {
                                                    _ = module.llvm.builder.create_memcpy(pointer, pointer_type.get_byte_alignment(), address, address_alignment, module.integer_type(64, false).llvm.handle.?.to_integer().get_constant(destination_size, @intFromBool(false)).to_value());
                                                }
                                            },
                                        }
                                    } else {
                                        assert(argument_abi.abi_count == 1);
                                        const abi_argument_type = function_type.abi_argument_types[argument_abi.abi_start];
                                        const destination_size = pointer_type.get_byte_size() - argument_abi.attributes.direct.offset;
                                        const is_volatile = false;
                                        _ = abi_argument_type;
                                        _ = destination_size;
                                        _ = is_volatile;
                                        @trap();
                                        // module.create_coerced_store(abi_arguments[0].to_value(), abi_argument_type, pointer, pointer_type, destination_size, is_volatile);
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

                        // TODO: delete this

                        // const argument_value = module.values.add();
                        // argument_value.* = .{
                        //     .llvm = semantic_argument_storage,
                        //     .type = argument_variable.variable.value.type,
                        //     .bb = .argument,
                        //     .lvalue = true,
                        //     .dereference_to_assign = false,
                        // };
                        // argument_variable.* = .{
                        //     .value = argument_value,
                        //     .name = argument_variable.name,
                        // };

                        // no pointer
                        const argument_type = argument_variable.variable.storage.?.type.?.bb.pointer.type;
                        if (module.has_debug_info) {
                            const always_preserve = true;
                            const flags = llvm.DI.Flags{};
                            const parameter_variable = module.llvm.di_builder.create_parameter_variable(function_scope, argument_variable.variable.name, @intCast(argument_index + 1), module.llvm.file, argument_variable.variable.line, argument_type.llvm.debug.?, always_preserve, flags);
                            const inlined_at: ?*llvm.DI.Metadata = null; // TODO
                            const debug_location = llvm.DI.create_debug_location(module.llvm.context, argument_variable.variable.line, argument_variable.variable.column, function_scope, inlined_at);
                            _ = module.llvm.di_builder.insert_declare_record_at_end(semantic_argument_storage, parameter_variable, module.llvm.di_builder.null_expression(), debug_location, entry_block);
                        }
                    }

                    module.analyze_block(global, global.variable.storage.?.bb.function.main_block);

                    // Handle jump to the return block
                    const return_block = global.variable.storage.?.bb.function.return_block orelse module.report_error();

                    if (module.llvm.builder.get_insert_block()) |current_basic_block| {
                        assert(current_basic_block.get_terminator() == null);

                        if (current_basic_block.is_empty() or current_basic_block.to_value().use_empty()) {
                            return_block.to_value().replace_all_uses_with(current_basic_block.to_value());
                            return_block.delete();
                        } else {
                            module.emit_block(global, return_block);
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
                            module.emit_block(global, return_block);
                        }
                    }

                    // End function debug info
                    if (llvm_function_value.get_subprogram()) |subprogram| {
                        module.llvm.di_builder.finalize_subprogram(subprogram);
                    }

                    if (function_type.return_abi.semantic_type == module.noreturn_type or global.variable.storage.?.bb.function.attributes.naked) {
                        @trap();
                    } else if (function_type.return_abi.semantic_type == module.void_type) {
                        module.llvm.builder.create_ret_void();
                    } else {
                        const abi_kind = function_type.return_abi.flags.kind;
                        const return_value: ?*llvm.Value = switch (abi_kind) {
                            .direct, .extend => blk: {
                                const coerce_to_type = function_type.return_abi.get_coerce_to_type();
                                const return_alloca = global.variable.storage.?.bb.function.return_alloca orelse unreachable;

                                if (function_type.return_abi.semantic_type.is_abi_equal(coerce_to_type) and function_type.return_abi.attributes.direct.offset == 0) {
                                    if (module.llvm.builder.find_return_value_dominating_store(return_alloca, function_type.return_abi.semantic_type.llvm.handle.?)) |store| {
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
                                    _ = source;
                                    _ = source_type;
                                    _ = destination_type;
                                    @trap();
                                    // const result = module.create_coerced_load(source, source_type, destination_type);
                                    // break :blk result;
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

    const ValueAnalysis = struct {
        type: ?*Type = null,
    };

    pub fn analyze(module: *Module, function: *Global, value: *Value, analysis: ValueAnalysis) void {
        module.analyze_value_type(function, value, analysis);
        module.emit_value(function, value);
    }

    pub fn emit_value(module: *Module, function: *Global, value: *Value) void {
        const value_type = value.type orelse unreachable;
        assert(value.llvm == null);

        const llvm_value: *llvm.Value = switch (value.bb) {
            .constant_integer => |constant_integer| value_type.llvm.handle.?.to_integer().get_constant(constant_integer.value, @intFromBool(constant_integer.signed)).to_value(),
            .unary => |unary| switch (unary.id) {
                .@"-" => blk: {
                    const unary_value = unary.value.llvm orelse b: {
                        module.emit_value(function, unary.value);
                        break :b unary.value.llvm orelse unreachable;
                    };
                    break :blk negate_llvm_value(unary_value, unary.value.is_constant());
                },
                else => @trap(),
            },
            .binary => |binary| blk: {
                const left = if (binary.left.llvm) |left_llvm| left_llvm else b: {
                    module.emit_value(function, binary.left);
                    break :b binary.left.llvm orelse unreachable;
                };
                const right = if (binary.right.llvm) |right_llvm| right_llvm else b: {
                    module.emit_value(function, binary.right);
                    break :b binary.right.llvm orelse unreachable;
                };
                const result = switch (value_type.bb) {
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
                        .@"&" => module.llvm.builder.create_and(left, right),
                        .@"|" => module.llvm.builder.create_or(left, right),
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
                        },
                    else => @trap(),
                };
                break :blk result;
            },
            .variable_reference => |variable| if (variable.type == value_type) switch (value_type.get_evaluation_kind()) {
                .scalar => module.create_load(.{
                    .type = value_type,
                    .value = variable.storage.?.llvm.?,
                    .alignment = variable.storage.?.type.?.bb.pointer.alignment,
                }),
                .aggregate => @trap(),
                .complex => @trap(),
            } else @trap(),
            else => @trap(),
        };

        value.llvm = llvm_value;
    }

    pub fn analyze_value_type(module: *Module, function: *Global, value: *Value, analysis: ValueAnalysis) void {
        assert(value.type == null);
        assert(value.llvm == null);

        if (analysis.type) |expected_type| switch (expected_type.bb) {
            .integer => |integer| switch (value.bb) {
                .constant_integer => |constant_integer| switch (constant_integer.signed) {
                    true => {
                        if (!integer.signed) {
                            module.report_error();
                        }

                        @trap();
                    },
                    false => {
                        const type_max = (@as(u64, 1) << @intCast(integer.bit_count)) - 1;
                        if (constant_integer.value > type_max) {
                            module.report_error();
                        }
                    },
                },
                .unary => |unary| {
                    switch (unary.id) {
                        .@"+" => @trap(),
                        .@"-" => {
                            module.analyze_value_type(function, unary.value, analysis);
                            if (!unary.value.type.?.is_signed()) {
                                module.report_error();
                            }

                            assert(expected_type == unary.value.type);
                        },
                        .@"&" => @trap(),
                    }
                },
                .binary => |binary| {
                    const is_boolean = binary.id.is_boolean();

                    const boolean_type = module.integer_type(1, false);

                    if (is_boolean and expected_type != boolean_type) {
                        module.report_error();
                    }

                    module.analyze_value_type(function, binary.left, .{
                        .type = if (is_boolean) null else expected_type,
                    });

                    module.analyze_value_type(function, binary.right, .{
                        .type = binary.left.type,
                    });
                },
                .variable_reference => |variable| {
                    if (variable.type != expected_type) {
                        module.report_error();
                    }
                },
                else => @trap(),
            },
            else => @trap(),
        };

        const value_type = if (analysis.type) |expected_type| expected_type else switch (value.bb) {
            .binary => |binary| blk: {
                if (binary.left.bb == .constant_integer and binary.right.bb == .constant_integer) {
                    module.report_error();
                }

                if (binary.left.bb == .constant_integer) {
                    module.analyze_value_type(function, binary.right, .{});
                    module.analyze_value_type(function, binary.left, .{
                        .type = binary.right.type,
                    });
                } else if (binary.right.bb == .constant_integer) {
                    module.analyze_value_type(function, binary.left, .{});
                    module.analyze_value_type(function, binary.right, .{
                        .type = binary.left.type,
                    });
                } else {
                    module.analyze_value_type(function, binary.left, .{});
                    module.analyze_value_type(function, binary.right, .{});
                }

                assert(binary.left.type != null);
                assert(binary.right.type != null);
                assert(binary.left.type == binary.right.type);
                break :blk binary.left.type.?;
            },
            .variable_reference => |variable| blk: {
                break :blk variable.type;
            },
            else => @trap(),
        };

        value.type = value_type;
    }

    pub fn analyze_block(module: *Module, function: *Global, block: *LexicalBlock) void {
        if (module.has_debug_info) {
            const lexical_block = module.llvm.di_builder.create_lexical_block(block.scope.parent.?.llvm.?, module.llvm.file, block.scope.line, block.scope.column);
            block.scope.llvm = lexical_block.to_scope();
        }

        var last_line: u32 = 0;
        var last_column: u32 = 0;
        var last_statement_debug_location: *llvm.DI.Location = undefined;

        for (block.statements.get_slice()) |statement| {
            if (module.has_debug_info) {
                if (statement.line != last_line or statement.column != last_column) {
                    const inlined_at: ?*llvm.DI.Metadata = null; // TODO
                    last_statement_debug_location = llvm.DI.create_debug_location(module.llvm.context, statement.line, statement.column, block.scope.llvm.?, inlined_at);
                    module.llvm.builder.set_current_debug_location(last_statement_debug_location);
                    last_line = statement.line;
                    last_column = statement.column;
                }
            }

            switch (statement.bb) {
                .@"return" => |rv| {
                    const function_type = &function.variable.storage.?.type.?.bb.pointer.type.bb.function;
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
                            module.analyze(function, return_value, .{
                                .type = return_abi.semantic_type,
                            });

                            if (module.has_debug_info) {
                                module.llvm.builder.set_current_debug_location(last_statement_debug_location);
                            }

                            // Clang equivalent: CodeGenFunction::EmitReturnStmt
                            const return_alloca = function.variable.storage.?.bb.function.return_alloca orelse module.report_error();

                            switch (return_abi.semantic_type.get_evaluation_kind()) {
                                .scalar => {
                                    switch (return_abi.flags.kind) {
                                        .indirect => {
                                            @trap();
                                        },
                                        else => {
                                            // assert(!return_value.?.lvalue);
                                            assert(return_value.type.?.is_abi_equal(return_abi.semantic_type));
                                            _ = module.create_store(.{
                                                .source_value = return_value.llvm.?,
                                                .destination_value = return_alloca,
                                                .source_type = return_abi.semantic_type,
                                                .destination_type = return_abi.semantic_type,
                                            });
                                        },
                                    }
                                },
                                .aggregate => {
                                    @trap();
                                    // TODO: handcoded code, might be wrong
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
                                    //         assert(!return_value.lvalue);
                                    //         assert(return_value.type.is_abi_equal(return_abi.semantic_type));
                                    //         _ = module.create_store(.{
                                    //             .source_value = return_value.llvm,
                                    //             .destination_value = unreachable, // return_alloca,
                                    //             .source_type = return_abi.semantic_type,
                                    //             .destination_type = return_abi.semantic_type,
                                    //         });
                                    //     },
                                    // }
                                },
                                .complex => @trap(),
                            }
                        },
                    }

                    const return_block = function.variable.storage.?.bb.function.return_block orelse module.report_error();

                    _ = module.llvm.builder.create_branch(return_block);
                    _ = module.llvm.builder.clear_insertion_position();
                },
                .local => |local| {
                    const expected_type = local.variable.type;
                    assert(local.variable.storage == null);
                    module.analyze_value_type(function, local.variable.initial_value, .{ .type = local.variable.type });
                    local.variable.resolve_type(local.variable.initial_value.type.?);
                    if (expected_type) |lvt| assert(lvt == local.variable.type);
                    module.emit_local_storage(local, last_statement_debug_location);

                    module.emit_assignment(function, local.variable.storage.?, local.variable.initial_value);
                },
            }
        }
    }

    fn emit_assignment(module: *Module, function: *Global, left: *Value, right: *Value) void {
        assert(left.llvm != null);
        assert(right.llvm == null);
        const pointer_type = left.type.?;
        const value_type = right.type.?;
        assert(pointer_type.bb == .pointer);
        assert(pointer_type.bb.pointer.type == value_type);

        switch (value_type.get_evaluation_kind()) {
            .scalar => {
                module.emit_value(function, right);
                _ = module.create_store(.{
                    .source_value = right.llvm.?,
                    .destination_value = left.llvm.?,
                    .source_type = value_type,
                    .destination_type = value_type,
                    .alignment = pointer_type.bb.pointer.alignment,
                });
            },
            .aggregate => @trap(),
            .complex => @trap(),
        }
    }

    pub fn emit_local_storage(module: *Module, local: *Local, statement_debug_location: *llvm.DI.Location) void {
        assert(local.variable.storage == null);
        const resolved_type = local.variable.type.?;
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
            module.llvm.builder.set_current_debug_location(statement_debug_location);
            const debug_type = resolved_type.llvm.debug.?;
            const always_preserve = true;
            // TODO:
            const alignment = 0;
            const flags = llvm.DI.Flags{};
            const local_variable = module.llvm.di_builder.create_auto_variable(local.variable.scope.llvm.?, local.variable.name, module.llvm.file, local.variable.line, debug_type, always_preserve, flags, alignment);
            const inlined_at: ?*llvm.DI.Metadata = null; // TODO
            const debug_location = llvm.DI.create_debug_location(module.llvm.context, local.variable.line, local.variable.column, local.variable.scope.llvm.?, inlined_at);
            _ = module.llvm.di_builder.insert_declare_record_at_end(storage.llvm.?, local_variable, module.llvm.di_builder.null_expression(), debug_location, module.llvm.builder.get_insert_block().?);
            module.llvm.builder.set_current_debug_location(statement_debug_location);
        }
        local.variable.storage = storage;
    }

    pub fn align_integer_type(module: *Module, ty: *Type) *Type {
        assert(ty.bb == .integer);
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
    };

    pub fn create_load(module: *Module, options: LoadOptions) *llvm.Value {
        switch (options.type.bb) {
            .void,
            .noreturn,
            => unreachable,
            .array => unreachable,
            .function => unreachable,
            .vector => @trap(),
            .bits, .float, .integer, .pointer, .enumerator, .structure => {
                const storage_type = switch (options.type.is_arbitrary_bit_integer()) {
                    true => module.align_integer_type(options.type),
                    false => options.type,
                };
                const alignment: c_uint = if (options.alignment) |a| a else @intCast(storage_type.get_byte_alignment());
                const v = module.llvm.builder.create_load(storage_type.llvm.handle.?, options.value);
                v.set_alignment(alignment);
                return switch (storage_type == options.type) {
                    true => v,
                    false => module.raw_int_cast(.{ .source_type = storage_type, .destination_type = options.type, .value = v }),
                };
            },
        }
    }

    const AllocaOptions = struct {
        type: *Type,
        name: []const u8 = "",
        alignment: ?c_uint = null,
    };

    pub fn create_alloca(module: *Module, options: AllocaOptions) *llvm.Value {
        const abi_type = switch (options.type.is_arbitrary_bit_integer()) {
            true => module.align_integer_type(options.type),
            false => options.type,
        };
        const alignment: c_uint = if (options.alignment) |a| a else @intCast(abi_type.get_byte_alignment());
        const v = module.llvm.builder.create_alloca(abi_type.llvm.handle.?, options.name);
        v.set_alignment(alignment);
        return v;
    }

    const StoreOptions = struct {
        source_value: *llvm.Value,
        destination_value: *llvm.Value,
        source_type: *Type,
        destination_type: *Type,
        alignment: ?c_uint = null,
    };

    pub fn create_store(module: *Module, options: StoreOptions) *llvm.Value {
        const raw_store_type = switch (options.source_type.is_arbitrary_bit_integer()) {
            true => module.align_integer_type(options.source_type),
            false => options.source_type,
        };
        const source_value = switch (raw_store_type == options.source_type) {
            true => options.source_value,
            false => module.raw_int_cast(.{ .source_type = options.source_type, .destination_type = raw_store_type, .value = options.source_value }),
        };
        const alignment = if (options.alignment) |a| a else options.destination_type.get_byte_alignment();
        const v = module.llvm.builder.create_store(source_value, options.destination_value);
        v.set_alignment(alignment);
        return v;
    }

    const IntCast = struct {
        source_type: *Type,
        destination_type: *Type,
        value: *llvm.Value,
    };

    pub fn raw_int_cast(module: *Module, options: IntCast) *llvm.Value {
        assert(options.source_type != options.destination_type);
        const source_size = options.source_type.get_bit_size();
        const destination_size = options.destination_type.get_bit_size();
        const result = switch (source_size < destination_size) {
            true => switch (options.source_type.is_signed()) {
                true => module.llvm.builder.create_sign_extend(options.value, options.destination_type.llvm.handle.?),
                false => module.llvm.builder.create_zero_extend(options.value, options.destination_type.llvm.handle.?),
            },
            false => module.llvm.builder.create_truncate(options.value, options.destination_type.llvm.handle.?),
        };
        return result;
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
    value_keyword: Value.Keyword,
    value_intrinsic: Value.Intrinsic,
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
    // Pointer dereference
    @".&",
    // Parenthesis
    @"(",
    @")",

    const Id = enum {
        none,
        end_of_statement,
        integer,
        identifier,
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
        // Pointer dereference
        @".&",
        // Parenthesis
        @"(",
        @")",
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

    const Flags = packed struct {
        kind: Kind,
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

        pub fn get_direct(direct: Direct) Information {
            var result = Information{
                .semantic_type = direct.semantic_type,
                .flags = .{
                    .kind = .direct,
                },
            };
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

        pub fn get_ignore(ignore: Ignore) Information {
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
                .void => result[current_index] = .none,
                // .noreturn => result[current_index] = .none,
                // .bits => result[current_index] = .integer,
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
                // .structure => |struct_type| {
                //     if (struct_type.byte_size <= 64) {
                //         const has_variable_array = false;
                //         if (!has_variable_array) {
                //             // const struct_type = ty.get_payload(.@"struct");
                //             result[current_index] = .none;
                //             const is_union = false;
                //             var member_offset: u32 = 0;
                //             for (struct_type.fields) |field| {
                //                 const offset = options.base_offset + member_offset;
                //                 const member_size = field.type.get_byte_size();
                //                 const member_alignment = field.type.get_byte_alignment();
                //                 member_offset = @intCast(lib.align_forward_u64(member_offset + member_size, ty.get_byte_alignment()));
                //                 const native_vector_size = 16;
                //                 if (ty.get_byte_size() > 16 and ((!is_union and ty.get_byte_size() != member_size) or ty.get_byte_size() > native_vector_size)) {
                //                     result[0] = .memory;
                //                     const r = classify_post_merge(ty.get_byte_size(), result);
                //                     return r;
                //                 }
                //
                //                 if (offset % member_alignment != 0) {
                //                     result[0] = .memory;
                //                     const r = classify_post_merge(ty.get_byte_size(), result);
                //                     return r;
                //                 }
                //
                //                 const member_classes = classify(field.type, .{
                //                     .base_offset = offset,
                //                     .is_named_argument = false,
                //                 });
                //                 for (&result, member_classes) |*r, m| {
                //                     const merge_result = r.merge(m);
                //                     r.* = merge_result;
                //                 }
                //
                //                 if (result[0] == .memory or result[1] == .memory) break;
                //             }
                //
                //             const final = classify_post_merge(ty.get_byte_size(), result);
                //             result = final;
                //         }
                //     }
                // },
                // .array => |*array_type| {
                //     if (ty.get_byte_size() <= 64) {
                //         if (options.base_offset % ty.get_byte_alignment() == 0) {
                //             result[current_index] = .none;
                //
                //             const vector_size = 16;
                //             if (ty.get_byte_size() > 16 and (ty.get_byte_size() != array_type.element_type.get_byte_size() or ty.get_byte_size() > vector_size)) {
                //                 unreachable;
                //             } else {
                //                 var offset = options.base_offset;
                //
                //                 for (0..array_type.element_count.?) |_| {
                //                     const element_classes = classify(array_type.element_type, .{
                //                         .base_offset = offset,
                //                         .is_named_argument = false,
                //                     });
                //                     offset += array_type.element_type.get_byte_size();
                //                     const merge_result = [2]Class{ result[0].merge(element_classes[0]), result[1].merge(element_classes[1]) };
                //                     result = merge_result;
                //                     if (result[0] == .memory or result[1] == .memory) {
                //                         break;
                //                     }
                //                 }
                //
                //                 const final_result = classify_post_merge(ty.get_byte_size(), result);
                //                 assert(final_result[1] != .sseup or final_result[0] != .sse);
                //                 result = final_result;
                //             }
                //         }
                //     }
                // },
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
                // .bits => |bits| {
                //     return get_int_type_at_offset(module, bits.backing_type, offset, if (source_type == ty) bits.backing_type else source_type, source_offset);
                // },
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
                        else => return module.integer_type(@intCast(@min(ty.get_byte_size() - source_offset, 8) * 8), integer_type.signed),
                    }
                },
                .pointer => return if (offset == 0) ty else @trap(),
                // .structure => {
                //     if (get_member_at_offset(ty, offset)) |field| {
                //         return get_int_type_at_offset(module, field.type, @intCast(offset - field.byte_offset), source_type, source_offset);
                //     }
                //     unreachable;
                // },
                // .array => |array_type| {
                //     const element_type = array_type.element_type;
                //     const element_size = element_type.get_byte_size();
                //     const element_offset = (offset / element_size) * element_size;
                //     return get_int_type_at_offset(module, element_type, @intCast(offset - element_offset), source_type, source_offset);
                // },
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

        fn get_member_at_offset(ty: *Type, offset: u32) ?*const Field {
            if (ty.get_byte_size() <= offset) {
                return null;
            }

            var offset_it: u32 = 0;
            var last_match: ?*const Field = null;

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

            _ = end;
            // TODO: uncomment the structure and array below because otherwise a bug is going to happen
            if (true) @trap();

            switch (ty.bb) {
                // .structure => |*struct_type| {
                //     var offset: u64 = 0;
                //
                //     for (struct_type.fields) |field| {
                //         if (offset >= end) break;
                //         const field_start = if (offset < start) start - offset else 0;
                //         if (!contains_no_user_data(field.type, field_start, end - offset)) return false;
                //         offset += field.type.get_byte_size();
                //     }
                //
                //     return true;
                // },
                // .array => |array_type| {
                //     for (0..array_type.element_count.?) |i| {
                //         const offset = i * array_type.element_type.get_byte_size();
                //         if (offset >= end) break;
                //         const element_start = if (offset < start) start - offset else 0;
                //         if (!contains_no_user_data(array_type.element_type, element_start, end - offset)) return false;
                //     }
                //
                //     return true;
                // },
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
                    return .{ get_indirect_result(argument_type, options.available_gpr), needed_registers };
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
                Abi.Information.get_direct(.{
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
                false => Abi.SystemV.get_indirect_result(semantic_argument_type, available_registers.system_v.gpr),
            };

            if (argument_type_abi.get_padding_type() != null) {
                @trap();
            }

            argument_type_abi.abi_start = options.abi_start;

            const count = switch (argument_type_abi.flags.kind) {
                .direct, .extend => blk: {
                    const coerce_to_type = argument_type_abi.get_coerce_to_type();
                    const flattened_struct = argument_type_abi.flags.kind == .direct and argument_type_abi.get_can_be_flattened() and coerce_to_type.bb == .structure;

                    const count: u16 = switch (flattened_struct) {
                        false => 1,
                        true => @trap(),
                        // true => @intCast(argument_type_abi.get_coerce_to_type().bb.structure.fields.len),
                    };

                    switch (flattened_struct) {
                        false => {
                            llvm_abi_argument_type_buffer[argument_type_abi.abi_start] = coerce_to_type.llvm.handle.?;
                            abi_argument_type_buffer[argument_type_abi.abi_start] = coerce_to_type;
                        },
                        true => {
                            @trap();
                            // for (coerce_to_type.bb.structure.fields, 0..) |field, field_index| {
                            //     const index = argument_type_abi.abi_start + field_index;
                            //     llvm_abi_argument_type_buffer[index] = field.type.llvm.handle.?;
                            //     abi_argument_type_buffer[index] = field.type;
                            // }
                        },
                    }

                    break :blk count;
                },
                .indirect => blk: {
                    const indirect_type = module.get_pointer_type(.{ .type = argument_type_abi.semantic_type });
                    abi_argument_type_buffer[argument_type_abi.abi_start] = indirect_type;
                    llvm_abi_argument_type_buffer[argument_type_abi.abi_start] = indirect_type.llvm.handle.?;
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
            _ = result;
            @trap();
            // assert(result.bb.structure.fields[1].byte_offset == 8);
            // return result;
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
                        return Abi.Information.get_ignore(.{
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
                        return Abi.Information.get_direct(.{
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

            return Abi.Information.get_direct(.{
                .semantic_type = return_type,
                .type = low orelse unreachable,
            });
        }

        pub fn get_byval_argument_pair(module: *Module, pair: [2]*Type) *Type {
            const low_size = pair[0].get_byte_size();
            const high_alignment = pair[1].get_byte_alignment();
            const high_offset = lib.align_forward_u64(low_size, high_alignment);
            assert(high_offset != 0 and high_offset <= 8);
            _ = module;
            @trap();
            // const low = if (high_offset != 8)
            //     if ((pair[0].bb == .float and pair[0].bb.float.kind == .half) or (pair[0].bb == .float and pair[0].bb.float.kind == .float)) {
            //         @trap();
            //     } else {
            //         assert(pair[0].is_integer_backing());
            //         @trap();
            //     }
            // else
            //     pair[0];
            // const high = pair[1];
            // const struct_type = module.get_anonymous_struct_pair(.{ low, high });
            // assert(struct_type.bb.structure.fields[1].byte_offset == 8);
            //
            // return struct_type;
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

        pub fn get_indirect_result(ty: *Type, free_gpr: u32) Abi.Information {
            if (!ty.is_aggregate_type_for_abi() and !is_illegal_vector_type(ty) and !ty.is_arbitrary_bit_integer()) {
                return switch (ty.is_promotable_integer_type_for_abi()) {
                    true => @trap(),
                    false => Abi.Information.get_direct(.{
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
            const overflow_arg_area_pointer = module.llvm.builder.create_struct_gep(va_list_struct.llvm.handle.to_struct(), va_list_pointer, 2);
            const overflow_arg_area_type = va_list_struct.bb.structure.fields[2].type;
            const overflow_arg_area = module.create_load(.{ .type = overflow_arg_area_type, .value = overflow_arg_area_pointer });
            if (arg_type.get_byte_alignment() > 8) {
                @trap();
            }
            const arg_type_size = arg_type.get_byte_size();
            const raw_offset = lib.align_forward_u64(arg_type_size, 8);
            const offset = module.integer_type(32, false).llvm.handle.to_integer().get_constant(raw_offset, @intFromBool(false));
            const new_overflow_arg_area = module.llvm.builder.create_gep(.{
                .type = module.integer_type(8, false).llvm.handle,
                .aggregate = overflow_arg_area,
                .indices = &.{offset.to_value()},
                .inbounds = false,
            });
            _ = module.create_store(.{ .destination_type = overflow_arg_area_type, .source_type = overflow_arg_area_type, .source_value = new_overflow_arg_area, .destination_value = overflow_arg_area_pointer });
            return overflow_arg_area;
        }
    };
};

const Field = struct {
    name: []const u8,
    type: *Type,
    bit_offset: u64,
    byte_offset: u64,
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
    const values = Value.Buffer.initialize();

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
        .pointer_types = .initialize(),
        .lexical_blocks = .initialize(),
        .statements = .initialize(),
        .void_type = void_type,
        .noreturn_type = noreturn_type,
        .current_scope = undefined,
        .scope = .{
            .kind = .global,
            .column = 0,
            .line = 0,
        },
        .name = options.name,
        .path = options.path,
        .executable = options.executable,
        .objects = options.objects,
        .target = options.target,
        .build_mode = options.build_mode,
        .silent = options.silent,
    };

    module.current_scope = &module.scope;

    module.parse();
    module.emit();
}
