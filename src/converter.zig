const lib = @import("lib.zig");
const assert = lib.assert;
const os = lib.os;
const Arena = lib.Arena;
const llvm = @import("LLVM.zig");

test {
    _ = @import("converter_test.zig");
}

const left_bracket = '[';
const right_bracket = ']';
const left_brace = '{';
const right_brace = '}';
const left_parenthesis = '(';
const right_parenthesis = ')';

const max_argument_count = 64;

fn array_type_name(arena: *Arena, array_type: ArrayType) [:0]const u8 {
    var buffer: [256]u8 = undefined;
    var i: usize = 0;
    buffer[i] = left_bracket;
    i += 1;
    i += lib.string_format.integer_decimal(buffer[i..], array_type.element_count.?);
    buffer[i] = right_bracket;
    i += 1;
    const element_name = array_type.element_type.name.?;
    @memcpy(buffer[i..][0..element_name.len], element_name);
    i += element_name.len;
    return arena.duplicate_string(buffer[0..i]);
}

fn array_type_llvm(noalias module: *Module, array: ArrayType) Type.LLVM {
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

pub const ResolvedCallingConvention = enum {
    system_v,
    win64,
};

const Module = struct {
    arena: *Arena,
    llvm: LLVM,
    target: Target,
    globals: Variable.Array = .{},
    types: Type.Array = .{},
    values: Value.Array = .{},
    current_function: ?*Variable = null,
    debug_tag: c_uint = 0,
    void_type: *Type = undefined,
    noreturn_type: *Type = undefined,
    va_list_type: ?*Type = null,
    void_value: *Value = undefined,
    anonymous_pair_type_buffer: [64]u32 = undefined,
    pointer_type_buffer: [128]u32 = undefined,
    pointer_type_count: u32 = 0,
    anonymous_pair_type_count: u32 = 0,
    arena_restore_position: u64,

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
            module.current_function.?.value.llvm.to_function().append_basic_block(block);
        }

        module.llvm.builder.position_at_end(block);
    }

    pub fn dump(module: *Module) void {
        lib.print_string(module.llvm.handle.to_string());
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

    pub fn create_coerced_load(module: *Module, source: *llvm.Value, source_ty: *Type, destination_type: *Type) *llvm.Value {
        var source_pointer = source;
        var source_type = source_ty;

        const result = switch (source_type.is_abi_equal(destination_type)) {
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
                        _ = module.llvm.builder.create_memcpy(destination_alloca, destination_alignment, source, source_alignment, module.integer_type(64, false).llvm.handle.to_integer().get_constant(source_size, @intFromBool(false)).to_value());
                        const load = module.create_load(.{ .type = destination_type, .value = destination_alloca, .alignment = destination_alignment });
                        return load;
                    }
                }
            },
        };
        return result;
    }

    pub fn create_coerced_store(module: *Module, source_value: *llvm.Value, source_type: *Type, destination: *llvm.Value, destination_ty: *Type, destination_size: u64, destination_volatile: bool) void {
        _ = destination_volatile;
        var destination_type = destination_ty;
        var destination_pointer = destination;
        const source_size = source_type.get_byte_size();
        if (!source_type.is_abi_equal(destination_type)) {
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
                    const gep = module.llvm.builder.create_struct_gep(source_type.llvm.handle.to_struct(), destination_pointer, @intCast(field_index));
                    const field_value = module.llvm.builder.create_extract_value(source_value, @intCast(field_index));
                    _ = module.create_store(.{
                        .source_value = field_value,
                        .source_type = field.type,
                        .destination_value = gep,
                        .destination_type = field.type,
                        .alignment = destination_alignment,
                    });
                }
            } else {
                _ = module.create_store(.{
                    .source_value = source_value,
                    .source_type = source_type,
                    .destination_value = destination_pointer,
                    .destination_type = destination_type,
                    .alignment = destination_alignment,
                });
            }
            // TODO: is this valid for pointers too?
        } else if (source_type.is_integer_backing()) {
            @trap();
        } else {
            // Coercion through memory
            const original_destination_alignment = destination_type.get_byte_alignment();
            const source_alloca_alignment = @max(original_destination_alignment, source_type.get_byte_alignment());
            const source_alloca = module.create_alloca(.{ .type = source_type, .alignment = source_alloca_alignment, .name = "coerce" });
            _ = module.create_store(.{
                .source_value = source_value,
                .destination_value = source_alloca,
                .source_type = source_type,
                .destination_type = source_type,
                .alignment = source_alloca_alignment,
            });
            _ = module.llvm.builder.create_memcpy(destination_pointer, original_destination_alignment, source_alloca, source_alloca_alignment, module.integer_type(64, false).llvm.handle.to_integer().get_constant(destination_size, @intFromBool(false)).to_value());
        }
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
            .semantic_type = options.return_type_abi.semantic_type.llvm.handle,
            .abi_type = options.abi_return_type.llvm.handle,
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
                .semantic_type = options.return_type_abi.semantic_type.llvm.handle,
                .abi_type = options.abi_argument_types[abi_index].llvm.handle,
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
                    .semantic_type = argument_type_abi.semantic_type.llvm.handle,
                    .abi_type = options.abi_argument_types[abi_index].llvm.handle,
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
            const llvm_parameter_types = [_]*llvm.Type{
                unsigned_int.llvm.handle,
                unsigned_int.llvm.handle,
                void_pointer.llvm.handle,
                void_pointer.llvm.handle,
            };
            const line = 1;
            const bit_alignment = 0; // TODO
            const flags = llvm.DI.Flags{};
            const llvm_member_types = [_]*llvm.DI.Type.Derived{
                if (module.llvm.di_builder) |di_builder| di_builder.create_member_type(module.llvm.global_scope, "gp_offset", module.llvm.file, line, 32, bit_alignment, 0, .{}, unsigned_int.llvm.debug) else undefined,
                if (module.llvm.di_builder) |di_builder| di_builder.create_member_type(module.llvm.global_scope, "fp_offset", module.llvm.file, line, 32, bit_alignment, 32, .{}, unsigned_int.llvm.debug) else undefined,
                if (module.llvm.di_builder) |di_builder| di_builder.create_member_type(module.llvm.global_scope, "overflow_arg_area", module.llvm.file, line, 64, bit_alignment, 64, .{}, void_pointer.llvm.debug) else undefined,
                if (module.llvm.di_builder) |di_builder| di_builder.create_member_type(module.llvm.global_scope, "reg_save_area", module.llvm.file, line, 64, bit_alignment, 128, .{}, void_pointer.llvm.debug) else undefined,
            };
            const llvm_handle = module.llvm.context.get_struct_type(&llvm_parameter_types);
            const bit_size = 24 * 8;
            const va_list_name = "va_list";
            const llvm_debug = if (module.llvm.di_builder) |di_builder| di_builder.create_struct_type(module.llvm.global_scope, va_list_name, module.llvm.file, line, bit_size, bit_alignment, flags, &llvm_member_types) else undefined;

            const field_buffer = [_]Field{
                .{ .name = "gp_offset", .type = unsigned_int, .bit_offset = 0, .byte_offset = 0 },
                .{ .name = "fp_offset", .type = unsigned_int, .bit_offset = 32, .byte_offset = 4 },
                .{ .name = "overflow_arg_area", .type = void_pointer, .bit_offset = 64, .byte_offset = 8 },
                .{ .name = "reg_save_area", .type = void_pointer, .bit_offset = 128, .byte_offset = 16 },
            };
            const fields = module.arena.allocate(Field, 4);
            @memcpy(fields, &field_buffer);

            const result = module.types.add(.{
                .llvm = .{
                    .handle = llvm_handle.to_type(),
                    .debug = llvm_debug.to_type(),
                },
                .name = va_list_name,
                .bb = .{
                    .structure = .{
                        .bit_alignment = 64,
                        .byte_alignment = 16,
                        .byte_size = 24,
                        .bit_size = 24 * 8,
                        .fields = fields,
                    },
                },
            });

            const array = ArrayType{
                .element_count = 1,
                .element_type = result,
            };
            const ty = module.types.add(.{
                .name = array_type_name(module.arena, array),
                .llvm = array_type_llvm(module, array),
                .bb = .{
                    .array = array,
                },
            });
            module.va_list_type = ty;
            return ty;
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
        const v = module.llvm.builder.create_alloca(abi_type.llvm.handle, options.name);
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
                true => module.llvm.builder.create_sign_extend(options.value, options.destination_type.llvm.handle),
                false => module.llvm.builder.create_zero_extend(options.value, options.destination_type.llvm.handle),
            },
            false => module.llvm.builder.create_truncate(options.value, options.destination_type.llvm.handle),
        };
        return result;
    }

    const LoadOptions = struct {
        type: *Type,
        value: *llvm.Value,
        alignment: ?c_uint = null,
    };

    pub fn create_load(module: *Module, options: LoadOptions) *llvm.Value {
        switch (options.type.bb) {
            .void, .noreturn, .forward_declaration => unreachable,
            .array => unreachable,
            .function => unreachable,
            .vector => @trap(),
            .bits, .float, .integer, .pointer, .enumerator, .structure => {
                const storage_type = switch (options.type.is_arbitrary_bit_integer()) {
                    true => module.align_integer_type(options.type),
                    false => options.type,
                };
                const alignment: c_uint = if (options.alignment) |a| a else @intCast(storage_type.get_byte_alignment());
                const v = module.llvm.builder.create_load(storage_type.llvm.handle, options.value);
                v.set_alignment(alignment);
                return switch (storage_type == options.type) {
                    true => v,
                    false => module.raw_int_cast(.{ .source_type = storage_type, .destination_type = options.type, .value = v }),
                };
            },
        }
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

    pub fn current_basic_block(module: *Module) *llvm.BasicBlock {
        return module.llvm.builder.get_insert_block() orelse unreachable;
    }

    const LLVM = struct {
        context: *llvm.Context,
        handle: *llvm.Module,
        builder: *llvm.Builder,
        di_builder: ?*llvm.DI.Builder,
        global_scope: *llvm.DI.Scope,
        file: *llvm.DI.File,
        pointer_type: *llvm.Type,
        intrinsic_table: IntrinsicTable,

        const IntrinsicTable = struct {
            trap: llvm.Intrinsic.Id,
            va_start: llvm.Intrinsic.Id,
            va_end: llvm.Intrinsic.Id,
            va_copy: llvm.Intrinsic.Id,
        };
    };

    pub fn get_anonymous_struct_pair(module: *Module, pair: [2]*Type) *Type {
        for (module.anonymous_pair_type_buffer[0..module.anonymous_pair_type_count]) |anonymous_type_index| {
            const anonymous_type = &module.types.get()[anonymous_type_index];
            const fields = anonymous_type.bb.structure.fields;
            if (fields.len == 2 and pair[0] == fields[0].type and pair[1] == fields[1].type) {
                return anonymous_type;
            }
        } else {
            const llvm_pair_members = &.{ pair[0].llvm.handle, pair[1].llvm.handle };
            const llvm_pair = module.llvm.context.get_struct_type(llvm_pair_members);
            const byte_alignment = @max(pair[0].get_byte_alignment(), pair[1].get_byte_alignment());
            const byte_size = lib.align_forward_u64(pair[0].get_byte_size() + pair[1].get_byte_size(), byte_alignment);
            const fields = module.arena.allocate(Field, 2);
            fields[0] = .{
                .bit_offset = 0,
                .byte_offset = 0,
                .type = pair[0],
                .name = "",
            };
            fields[1] = .{
                .bit_offset = pair[0].get_bit_size(), // TODO
                .byte_offset = pair[0].get_byte_size(), // TODO
                .type = pair[1],
                .name = "",
            };
            const pair_type = module.types.add(.{
                .name = "",
                .bb = .{
                    .structure = .{
                        .bit_alignment = byte_alignment * 8,
                        .byte_alignment = byte_alignment,
                        .byte_size = byte_size,
                        .bit_size = byte_size * 8,
                        .fields = fields,
                    },
                },
                .llvm = .{
                    .handle = llvm_pair.to_type(),
                    .debug = undefined,
                },
            });

            module.anonymous_pair_type_buffer[module.anonymous_pair_type_count] = @intCast(pair_type - module.types.get().ptr);
            module.anonymous_pair_type_count += 1;

            return pair_type;
        }
    }

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

    pub fn load_arbitrary_integer_type(module: *Module, destination_type: *Type, value: *Value) *Value {
        _ = module;
        assert(value.type.bb == .pointer);
        const appointee_type = value.type.bb.pointer.type;
        assert(appointee_type != destination_type);
        assert(destination_type.bb == .integer);
        assert(appointee_type.bb == .integer);
        assert(!appointee_type.is_arbitrary_bit_integer());
        assert(destination_type.is_arbitrary_bit_integer());
        // const bit_count = appointee_type.get_bit_size();
        // const abi_bit_count: u32 = @intCast(@max(8, lib.next_power_of_two(bit_count)));
        // const is_signed = appointee_type.is_signed();
        _ = integer_type;
        @trap();
    }

    pub fn store_arbitrary_integer_type(module: *Module) void {
        _ = module;
        @trap();
    }

    pub fn initialize(arena: *Arena, options: ConvertOptions) *Module {
        const arena_restore_position = arena.position;
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
        const default_address_space = 0;
        module.* = .{
            .arena = arena,
            .target = options.target,
            .llvm = .{
                .global_scope = global_scope,
                .file = file,
                .handle = handle,
                .context = context,
                .builder = context.create_builder(),
                .di_builder = maybe_di_builder,
                .pointer_type = context.get_pointer_type(default_address_space).to_type(),
                .intrinsic_table = .{
                    .trap = llvm.lookup_intrinsic_id("llvm.trap"),
                    .va_start = llvm.lookup_intrinsic_id("llvm.va_start"),
                    .va_end = llvm.lookup_intrinsic_id("llvm.va_end"),
                    .va_copy = llvm.lookup_intrinsic_id("llvm.va_copy"),
                },
            },
            .arena_restore_position = arena_restore_position,
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
                const name_buffer = [3]u8{ if (sign) 's' else 'u', @intCast(if (bit_count < 10) bit_count % 10 + '0' else bit_count / 10 + '0'), if (bit_count > 9) @intCast(bit_count % 10 + '0') else 0 };
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

        module.void_value = module.values.add();
        module.void_value.* = .{
            .llvm = undefined,
            .bb = .infer_or_ignore,
            .type = module.void_type,
            .lvalue = false,
            .dereference_to_assign = false,
        };

        return module;
    }

    pub fn deinitialize(module: *Module) void {
        const arena = module.arena;
        const position = module.arena_restore_position;
        defer arena.restore(position);
    }

    const Pointer = struct {
        type: *Type,
        alignment: ?u32 = null,
    };

    pub fn get_pointer_type(module: *Module, pointer: Pointer) *Type {
        const p = PointerType{
            .type = pointer.type,
            .alignment = if (pointer.alignment) |a| a else pointer.type.get_byte_alignment(),
        };
        const all_types = module.types.get();
        const pointer_type = for (module.pointer_type_buffer[0..module.pointer_type_count]) |pointer_type_index| {
            const ty = &all_types[pointer_type_index];
            const pointer_type = &all_types[pointer_type_index].bb.pointer;
            if (pointer_type.type == p.type and pointer_type.alignment == p.alignment) {
                break ty;
            }
        } else blk: {
            const pointer_name = if (p.type.name) |name| module.arena.join_string(&.{ "&", name }) else "unknownptr";
            const pointer_type = module.types.add(.{
                .name = pointer_name,
                .llvm = .{
                    .handle = module.llvm.pointer_type,
                    .debug = if (module.llvm.di_builder) |di_builder| di_builder.create_pointer_type(p.type.llvm.debug, 64, 64, 0, pointer_name).to_type() else undefined,
                },
                .bb = .{
                    .pointer = p,
                },
            });

            const index = pointer_type - module.types.get().ptr;
            module.pointer_type_buffer[module.pointer_type_count] = @intCast(index);
            module.pointer_type_count += 1;
            break :blk pointer_type;
        };

        return pointer_type;
    }
};

const AttributeContainerType = enum {
    call,
    function,
};

fn llvm_add_function_attribute(value: *llvm.Value, attribute: *llvm.Attribute, container_type: AttributeContainerType) void {
    switch (container_type) {
        .call => {
            const call = value.is_call_instruction() orelse unreachable;
            call.add_attribute(.function, attribute);
        },
        .function => {
            const function = value.to_function();
            function.add_attribute(.function, attribute);
        },
    }
}

fn llvm_add_argument_attribute(value: *llvm.Value, attribute: *llvm.Attribute, index: c_uint, container_type: AttributeContainerType) void {
    switch (container_type) {
        .call => {
            const call = value.is_call_instruction() orelse unreachable;
            call.add_attribute(@enumFromInt(index), attribute);
        },
        .function => {
            const function = value.to_function();
            function.add_attribute(@enumFromInt(index), attribute);
        },
    }
}

pub const Function = struct {
    return_alloca: *llvm.Value,
    exit_block: ?*llvm.BasicBlock,
    return_block: *llvm.BasicBlock,
    current_scope: *llvm.DI.Scope,
    return_pointer: *Value,
    attributes: Attributes,
    locals: Variable.Array = .{},
    arguments: Variable.Array = .{},

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
        struct_initialization: struct {
            is_constant: bool,
        },
        bits_initialization,
        infer_or_ignore,
        constant_integer: ConstantInteger,
        constant_array,
        external_function,
    },
    type: *Type,
    llvm: *llvm.Value,
    lvalue: bool,
    dereference_to_assign: bool,

    const Array = struct {
        buffer: [1024]Value = undefined,
        count: usize = 0,

        pub fn add(values: *Array) *Value {
            const result = &values.buffer[values.count];
            values.count += 1;
            return result;
        }
    };

    pub fn is_constant(value: *Value) bool {
        return switch (value.bb) {
            .constant_integer, .constant_array => true,
            .struct_initialization => |si| si.is_constant,
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
    argument_type_abis: []const Abi.Information,
    abi_return_type: *Type,
    abi_argument_types: []const *Type,
    calling_convention: CallingConvention,
    available_registers: Abi.RegisterCount,
    is_var_args: bool,

    fn get_abi_argument_types(function_type: *const FunctionType) []const *Type {
        return function_type.abi_argument_types[0..function_type.abi_argument_count];
    }
};

const StructType = struct {
    fields: []const Field,
    bit_size: u64,
    byte_size: u64,
    bit_alignment: u32,
    byte_alignment: u32,
};

const Bits = struct {
    fields: []const Field,
    backing_type: *Type,
};

pub const ArrayType = struct {
    element_count: ?usize,
    element_type: *Type,
};

pub const IntegerType = struct {
    bit_count: u32,
    signed: bool,
};

pub const FloatType = struct {
    const Kind = enum {
        half,
        bfloat,
        float,
        double,
        fp128,
    };
    kind: Kind,
};

pub const Enumerator = struct {};

pub const PointerType = struct {
    type: *Type,
    alignment: u32,
};

pub const Type = struct {
    bb: BB,
    llvm: LLVM,
    name: ?[]const u8,

    pub const EvaluationKind = enum {
        scalar,
        complex,
        aggregate,
    };

    pub const BB = union(enum) {
        void,
        noreturn,
        forward_declaration,
        integer: IntegerType,
        float: FloatType,
        structure: StructType,
        bits: Bits,
        function: FunctionType,
        array: ArrayType,
        pointer: PointerType,
        enumerator: Enumerator,
        vector,
    };

    pub fn is_aggregate_type_for_abi(ty: *Type) bool {
        const ev_kind = ty.get_evaluation_kind();
        const is_member_function_pointer_type = false; // TODO
        return ev_kind != .scalar or is_member_function_pointer_type;
    }

    pub fn is_integer_backing(ty: *Type) bool {
        return switch (ty.bb) {
            .enumerator, .integer, .bits, .pointer => true,
            else => false,
        };
    }

    pub fn is_abi_equal(ty: *const Type, other: *const Type) bool {
        return ty == other or ty.llvm.handle == other.llvm.handle;
    }

    pub fn is_signed(ty: *const Type) bool {
        return switch (ty.bb) {
            .integer => |integer| integer.signed,
            .bits => |bits| bits.backing_type.is_signed(),
            else => @trap(),
        };
    }

    pub fn is_integral_or_enumeration_type(ty: *Type) bool {
        return switch (ty.bb) {
            .integer => true,
            .bits => true,
            .structure => false,
            // .integer => |integer| switch (integer.bit_count) {
            //     1, 8, 16, 32, 64, 128 => true,
            //     else => false,
            // },
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
            else => false,
        };
    }

    pub fn is_promotable_integer_type_for_abi(ty: *Type) bool {
        return switch (ty.bb) {
            .integer => |integer| integer.bit_count < 32,
            .bits => |bits| bits.backing_type.is_promotable_integer_type_for_abi(),
            else => @trap(),
        };
    }

    pub fn get_evaluation_kind(ty: *const Type) EvaluationKind {
        return switch (ty.bb) {
            .structure, .array => .aggregate,
            .integer, .bits, .pointer => .scalar,
            else => @trap(),
        };
    }

    pub fn get_byte_allocation_size(ty: *const Type) u64 {
        return lib.align_forward_u64(ty.get_byte_size(), ty.get_byte_alignment());
    }

    pub fn get_bit_size(ty: *const Type) u64 {
        return switch (ty.bb) {
            .integer => |integer| integer.bit_count,
            .structure => |struct_type| struct_type.bit_size,
            .bits => |bits| bits.backing_type.get_bit_size(),
            .void, .forward_declaration, .function, .noreturn => unreachable,
            .array => |*array| array.element_type.get_bit_size() * array.element_count.?,
            .pointer => 64,
            .enumerator => @trap(),
            .float => @trap(),
            .vector => @trap(),
        };
    }

    pub fn get_byte_size(ty: *const Type) u64 {
        return switch (ty.bb) {
            .integer => |integer| @divExact(@max(8, lib.next_power_of_two(integer.bit_count)), 8),
            .structure => |struct_type| struct_type.byte_size,
            .bits => |bits| bits.backing_type.get_byte_size(),
            .void, .forward_declaration, .function, .noreturn => unreachable,
            .array => |*array| array.element_type.get_byte_size() * array.element_count.?,
            .pointer => 8,
            .enumerator => @trap(),
            .float => @trap(),
            .vector => @trap(),
        };
    }

    pub fn get_bit_alignment(ty: *const Type) u32 {
        return switch (ty.bb) {
            .integer => |integer| integer.bit_count,
            .structure => |struct_type| struct_type.bit_alignment,
            .bits => |bits| bits.backing_type.get_bit_alignment(),
            .void, .forward_declaration, .function, .noreturn => unreachable,
            .array => |*array| array.element_type.get_bit_alignment(),
            .pointer => 64,
            .enumerator => @trap(),
            .float => @trap(),
            .vector => @trap(),
        };
    }

    pub fn get_byte_alignment(ty: *const Type) u32 {
        return switch (ty.bb) {
            .integer => |integer| @as(u32, @intCast(@divExact(@max(8, lib.next_power_of_two(integer.bit_count)), 8))),
            .structure => |struct_type| struct_type.byte_alignment,
            .bits => |bits| bits.backing_type.get_byte_alignment(),
            .function => 1,
            .void, .forward_declaration, .noreturn => unreachable,
            .array => |*array| array.element_type.get_byte_alignment(),
            .pointer => 8,
            .enumerator => @trap(),
            .float => @trap(),
            .vector => @trap(),
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
        buffer: [1024]Variable = undefined,
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
        while (true) {
            const offset = converter.offset;
            while (converter.offset < converter.content.len and is_space(converter.content[converter.offset])) {
                converter.line_offset += @intFromBool(converter.content[converter.offset] == '\n');
                converter.line_character_offset = if (converter.content[converter.offset] == '\n') converter.offset else converter.line_character_offset;
                converter.offset += 1;
            }

            if (converter.offset + 1 < converter.content.len) {
                const i = converter.offset;
                const is_comment = converter.content[i] == '/' and converter.content[i + 1] == '/';
                if (is_comment) {
                    while (converter.offset < converter.content.len and converter.content[converter.offset] != '\n') {
                        converter.offset += 1;
                    }

                    if (converter.offset < converter.content.len) {
                        converter.line_offset += 1;
                        converter.line_character_offset = converter.offset;
                        converter.offset += 1;
                    }
                }
            }

            if (converter.offset - offset == 0) {
                break;
            }
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

                const length_expression = converter.parse_value(module, module.integer_type(64, false), .value);
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
                    const element_count = length_expression.bb.constant_integer.value;
                    const array = ArrayType{
                        .element_count = element_count,
                        .element_type = element_type,
                    };
                    const ty = module.types.add(.{
                        .name = array_type_name(module.arena, array),
                        .llvm = array_type_llvm(module, array),
                        .bb = .{
                            .array = array,
                        },
                    });
                    return ty;
                }
            },
            '&' => {
                converter.offset += 1;

                converter.skip_space();

                const element_type = converter.parse_type(module);

                return module.get_pointer_type(.{
                    .type = element_type,
                });
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

    fn parse_hexadecimal(noalias converter: *Converter) u64 {
        var value: u64 = 0;
        while (true) {
            const ch = converter.content[converter.offset];
            if (!lib.is_hex_digit(ch)) {
                break;
            }

            converter.offset += 1;
            value = lib.parse.accumulate_hexadecimal(value, ch);
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
                        'x' => b: {
                            converter.offset += 1;
                            break :b converter.parse_hexadecimal();
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
            .lvalue = false,
            .dereference_to_assign = false,
        };
        return integer_value;
    }

    fn expect_character(noalias converter: *Converter, expected_ch: u8) void {
        if (!converter.consume_character_if_match(expected_ch)) {
            converter.report_error();
        }
    }

    fn parse_call(noalias converter: *Converter, noalias module: *Module, may_be_callable: *Value) *Value {
        const child_type = may_be_callable.type.bb.pointer.type;
        const pointer_type = switch (child_type.bb) {
            .function => may_be_callable.type,
            .pointer => |p| switch (p.type.bb) {
                .function => child_type,
                else => @trap(),
            },
            else => @trap(),
        };
        const raw_function_type = pointer_type.bb.pointer.type;
        const llvm_callable = switch (child_type == raw_function_type) {
            true => may_be_callable.llvm,
            else => module.create_load(.{ .type = pointer_type, .value = may_be_callable.llvm }),
        };

        const function_type = &raw_function_type.bb.function;
        const calling_convention = function_type.calling_convention;
        const llvm_calling_convention = calling_convention.to_llvm();
        var llvm_abi_argument_value_buffer: [max_argument_count]*llvm.Value = undefined;
        var llvm_abi_argument_type_buffer: [max_argument_count]*llvm.Type = undefined;
        var abi_argument_type_buffer: [max_argument_count]*Type = undefined;
        var argument_type_abi_buffer: [max_argument_count]Abi.Information = undefined;

        var abi_argument_count: u16 = 0;
        var semantic_argument_count: u32 = 0;
        const function_semantic_argument_count = function_type.argument_type_abis.len;

        // TODO
        const uses_in_alloca = false;
        if (uses_in_alloca) {
            @trap();
        }

        const llvm_indirect_return_value: *llvm.Value = switch (function_type.return_type_abi.flags.kind) {
            .indirect, .in_alloca, .coerce_and_expand => blk: {
                // TODO: handle edge cases:
                // - virtual function pointer thunk
                // - return alloca already exists

                const temporal_alloca = module.create_alloca(.{ .type = function_type.return_type_abi.semantic_type, .name = "tmp" });
                const has_sret = function_type.return_type_abi.flags.kind == .indirect;
                if (has_sret) {
                    llvm_abi_argument_value_buffer[abi_argument_count] = temporal_alloca;
                    abi_argument_type_buffer[abi_argument_count] = module.void_type;
                    llvm_abi_argument_type_buffer[abi_argument_count] = module.void_type.llvm.handle;
                    abi_argument_count += 1;
                    break :blk temporal_alloca;
                } else if (function_type.return_type_abi.flags.kind == .in_alloca) {
                    @trap();
                } else {
                    @trap();
                }
            },
            else => undefined,
        };

        var available_registers = function_type.available_registers;

        while (true) : (semantic_argument_count += 1) {
            converter.skip_space();

            if (converter.consume_character_if_match(right_parenthesis)) {
                break;
            }

            const semantic_argument_index = semantic_argument_count;
            const is_named_argument = semantic_argument_index < function_semantic_argument_count;
            if (is_named_argument or function_type.is_var_args) {
                const expected_semantic_argument_type: ?*Type = if (is_named_argument) function_type.argument_type_abis[semantic_argument_index].semantic_type else null;
                const semantic_argument_value = converter.parse_value(module, expected_semantic_argument_type, .value);

                _ = converter.consume_character_if_match(',');

                const semantic_argument_type = switch (is_named_argument) {
                    true => function_type.argument_type_abis[semantic_argument_index].semantic_type,
                    false => if (semantic_argument_value.lvalue and semantic_argument_value.dereference_to_assign) blk: {
                        const t = semantic_argument_value.type;
                        assert(t.bb == .pointer);
                        assert(t.bb.pointer.type.bb == .structure);
                        break :blk t.bb.pointer.type;
                    } else semantic_argument_value.type,
                };
                const argument_abi = if (is_named_argument) function_type.argument_type_abis[semantic_argument_index] else Abi.SystemV.classify_argument(module, &available_registers, &llvm_abi_argument_type_buffer, &abi_argument_type_buffer, .{
                    .type = semantic_argument_type,
                    .abi_start = abi_argument_count,
                    .is_named_argument = true,
                });
                if (is_named_argument) {
                    for (llvm_abi_argument_type_buffer[argument_abi.abi_start..][0..argument_abi.abi_count], abi_argument_type_buffer[argument_abi.abi_start..][0..argument_abi.abi_count], function_type.abi_argument_types[argument_abi.abi_start..][0..argument_abi.abi_count]) |*llvm_t, *t, abi_argument_type| {
                        llvm_t.* = abi_argument_type.llvm.handle;
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
                        if (coerce_to_type.bb != .structure and semantic_argument_type.is_abi_equal(coerce_to_type) and argument_abi.attributes.direct.offset == 0) {
                            var v = switch (argument_abi.semantic_type.get_evaluation_kind()) {
                                .aggregate => @trap(),
                                else => semantic_argument_value,
                            };
                            _ = &v;

                            if (coerce_to_type != v.type) {
                                switch (v.type) {
                                    else => @trap(),
                                }
                            }

                            // TODO: bitcast
                            // if (argument_abi.abi_start < function_type.argument_type_abis.len and v.type.llvm.handle != abi_arguments

                            // TODO: fill types
                            llvm_abi_argument_value_buffer[abi_argument_count] = v.llvm;
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
                                    const destination_size = coerce_to_type.get_byte_size();
                                    const source_size = argument_abi.semantic_type.get_byte_size();

                                    const alignment = argument_abi.semantic_type.get_byte_alignment();
                                    const source = switch (source_size < destination_size) {
                                        true => blk: {
                                            const temporal_alloca = module.create_alloca(.{ .type = coerce_to_type, .name = "coerce", .alignment = alignment });
                                            const destination = temporal_alloca;
                                            const source = semantic_argument_value.llvm;
                                            _ = module.llvm.builder.create_memcpy(destination, alignment, source, alignment, module.integer_type(64, false).llvm.handle.to_integer().get_constant(semantic_argument_type.get_byte_size(), @intFromBool(false)).to_value());
                                            break :blk temporal_alloca;
                                        },
                                        false => src.llvm,
                                    };

                                    // TODO:
                                    assert(argument_abi.attributes.direct.offset == 0);

                                    for (coerce_to_type.bb.structure.fields, 0..) |field, field_index| {
                                        const gep = module.llvm.builder.create_struct_gep(coerce_to_type.llvm.handle.to_struct(), source, @intCast(field_index));
                                        const maybe_undef = false;
                                        if (maybe_undef) {
                                            @trap();
                                        }
                                        const load = module.create_load(.{ .value = gep, .type = field.type, .alignment = alignment });

                                        llvm_abi_argument_value_buffer[abi_argument_count] = load;
                                        abi_argument_count += 1;
                                    }
                                }
                            } else {
                                assert(argument_abi.abi_count == 1);
                                assert(src.type.bb == .pointer);
                                const source_type = src.type.bb.pointer.type;
                                assert(source_type == argument_abi.semantic_type);
                                const destination_type = argument_abi.get_coerce_to_type();
                                const load = module.create_coerced_load(src.llvm, source_type, destination_type);

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
                            const indirect_alignment = argument_abi.attributes.indirect.alignment;
                            const address_alignment = semantic_argument_type.get_byte_alignment();
                            const get_or_enforce_known_alignment = indirect_alignment;
                            // llvm::getOrEnforceKnownAlignment(Addr.emitRawPointer(*this),
                            //      Align.getAsAlign(),
                            //      *TD) < Align.getAsAlign()) {
                            // TODO
                            const need_copy = switch (address_alignment < indirect_alignment and get_or_enforce_known_alignment < indirect_alignment) {
                                true => @trap(),
                                false => b: {
                                    const is_lvalue = !(semantic_argument_value.type.bb == .pointer and semantic_argument_type == semantic_argument_value.type.bb.pointer.type);
                                    if (is_lvalue) {
                                        var need_copy = false;
                                        const is_by_val_or_by_ref = argument_abi.flags.kind == .indirect_aliased or argument_abi.flags.indirect_by_value;

                                        const lv_alignment = semantic_argument_value.type.get_byte_alignment();
                                        const arg_type_alignment = argument_abi.semantic_type.get_byte_alignment();
                                        if (!is_by_val_or_by_ref or lv_alignment < arg_type_alignment) {
                                            need_copy = true;
                                        }

                                        break :b need_copy;
                                    } else {
                                        break :b false;
                                    }
                                },
                            };

                            if (!need_copy) {
                                llvm_abi_argument_value_buffer[abi_argument_count] = semantic_argument_value.llvm;
                                abi_argument_count += 1;
                                break :indirect;
                            }
                        }

                        @trap();
                    },
                    .ignore => unreachable,
                    else => @trap(),
                }

                assert(abi_argument_count == argument_abi.abi_start + argument_abi.abi_count);
            } else {
                converter.report_error();
            }
        }

        if (function_type.is_var_args) {
            assert(abi_argument_count >= function_type.abi_argument_types.len);
        } else {
            // TODO
            assert(abi_argument_count == function_type.abi_argument_types.len);
        }

        const llvm_abi_argument_values = llvm_abi_argument_value_buffer[0..abi_argument_count];
        const llvm_call = module.llvm.builder.create_call(raw_function_type.llvm.handle.to_function(), llvm_callable, llvm_abi_argument_values);

        const attribute_list = module.build_attribute_list(.{
            .return_type_abi = function_type.return_type_abi,
            .abi_return_type = function_type.abi_return_type,
            .abi_argument_types = abi_argument_type_buffer[0..abi_argument_count],
            .argument_type_abis = argument_type_abi_buffer[0..semantic_argument_count],
            .attributes = .{},
            .call_site = true,
        });

        const call_base = llvm_call.to_instruction().to_call_base();
        call_base.set_calling_convention(llvm_calling_convention);
        call_base.set_attributes(attribute_list);

        const return_type_abi = &function_type.return_type_abi;
        const return_abi_kind = return_type_abi.flags.kind;

        switch (return_abi_kind) {
            .ignore => {
                assert(return_type_abi.semantic_type == module.noreturn_type or return_type_abi.semantic_type == module.void_type);
                return module.void_value;
            },
            .direct, .extend => {
                const coerce_to_type = return_type_abi.get_coerce_to_type();

                if (return_type_abi.semantic_type.is_abi_equal(coerce_to_type) and return_type_abi.attributes.direct.offset == 0) {
                    const coerce_to_type_kind = coerce_to_type.get_evaluation_kind();
                    switch (coerce_to_type_kind) {
                        .aggregate => {},
                        .complex => @trap(),
                        .scalar => {
                            const value = module.values.add();
                            value.* = .{
                                .llvm = llvm_call,
                                .bb = .instruction,
                                .type = return_type_abi.semantic_type,
                                .lvalue = false,
                                .dereference_to_assign = false,
                            };
                            return value;
                        },
                    }
                }

                // TODO: if
                const fixed_vector_type = false;
                if (fixed_vector_type) {
                    @trap();
                }

                const coerce_alloca = module.create_alloca(.{ .type = return_type_abi.semantic_type, .name = "coerce" });
                var destination_pointer = switch (return_type_abi.attributes.direct.offset == 0) {
                    true => coerce_alloca,
                    false => @trap(),
                };
                _ = &destination_pointer;

                if (return_type_abi.semantic_type.bb.structure.fields.len > 0) {
                    // CreateCoercedStore(
                    // CI, StorePtr,
                    // llvm::TypeSize::getFixed(DestSize - RetAI.getDirectOffset()),
                    // DestIsVolatile);
                    const source_value = llvm_call;
                    const source_type = function_type.abi_return_type;
                    // const source_size = source_type.get_byte_size();
                    var destination_type = return_type_abi.semantic_type;
                    const destination_size = destination_type.get_byte_size();
                    // const destination_alignment = destination_type.get_byte_alignment();
                    const left_destination_size = destination_size - return_type_abi.attributes.direct.offset;

                    const is_destination_volatile = false; // TODO
                    module.create_coerced_store(source_value, source_type, destination_pointer, destination_type, left_destination_size, is_destination_volatile);
                } else {
                    @trap();
                }

                const value = module.values.add();
                value.* = .{
                    .llvm = destination_pointer,
                    .bb = .instruction,
                    .type = module.get_pointer_type(.{ .type = return_type_abi.semantic_type }),
                    .lvalue = true,
                    .dereference_to_assign = true,
                };
                return value;
            },
            .indirect => {
                const value = module.values.add();
                value.* = .{
                    .llvm = llvm_indirect_return_value,
                    .bb = .instruction,
                    .type = module.get_pointer_type(.{ .type = return_type_abi.semantic_type }),
                    .lvalue = true,
                    .dereference_to_assign = true,
                };
                return value;
            },
            else => @trap(),
        }
    }

    fn parse_block(noalias converter: *Converter, noalias module: *Module) void {
        converter.skip_space();

        const current_function_global = module.current_function orelse unreachable;
        const current_function = &current_function_global.value.bb.function;
        const current_function_type = &current_function_global.value.type.bb.pointer.type.bb.function;
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

                const has_type = converter.consume_character_if_match(':');

                converter.skip_space();

                const local_type_stated: ?*Type = switch (has_type) {
                    true => converter.parse_type(module),
                    false => null,
                };

                converter.skip_space();

                converter.expect_character('=');

                const value = converter.parse_value(module, local_type_stated, .value);
                const local_storage = module.values.add();
                const is_inferred = local_type_stated == null;
                const is_inferred_pointer = is_inferred and value.dereference_to_assign;
                const local_type = switch (is_inferred_pointer) {
                    true => value.type.bb.pointer.type,
                    false => if (local_type_stated) |t| t else value.type,
                };
                const local_pointer_type = switch (value.dereference_to_assign) {
                    true => b: {
                        assert(value.type != local_type);
                        assert(value.type.bb == .pointer);
                        break :b value.type;
                    },
                    false => b: {
                        assert(value.type == local_type);
                        const pointer_type = module.get_pointer_type(.{
                            .type = local_type,
                        });
                        break :b pointer_type;
                    },
                };
                const local_alignment = local_pointer_type.bb.pointer.alignment;
                const llvm_alloca = module.create_alloca(.{ .type = local_type, .name = local_name, .alignment = local_alignment });
                local_storage.* = .{
                    .llvm = llvm_alloca,
                    .type = local_pointer_type,
                    .bb = .local,
                    .lvalue = true,
                    .dereference_to_assign = false,
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
                    _ = di_builder.insert_declare_record_at_end(local_storage.llvm, local_variable, di_builder.null_expression(), debug_location, module.current_basic_block());
                    module.llvm.builder.set_current_debug_location(statement_debug_location);
                }

                const alignment: u32 = @intCast(local_type.get_byte_alignment());
                const destination = local_storage.llvm;
                const source = value.llvm;
                switch (local_type.get_evaluation_kind()) {
                    .aggregate => {
                        _ = module.llvm.builder.create_memcpy(destination, alignment, source, alignment, module.integer_type(64, false).llvm.handle.to_integer().get_constant(local_type.get_byte_size(), @intFromBool(false)).to_value());
                    },
                    else => {
                        _ = module.create_store(.{ .source_value = source, .destination_value = destination, .source_type = local_type, .destination_type = local_type });
                    },
                }

                const local = current_function.locals.add();
                local.* = .{
                    .name = local_name,
                    .value = local_storage,
                };
            } else if (statement_start_ch == '#') {
                const intrinsic = converter.parse_intrinsic(module, null);
                switch (intrinsic.type.bb) {
                    .void, .noreturn => {},
                    else => @trap(),
                }
            } else if (is_identifier_start_ch(statement_start_ch)) {
                const statement_start_identifier = converter.parse_identifier();

                if (string_to_enum(StatementStartKeyword, statement_start_identifier)) |statement_start_keyword| {
                    switch (statement_start_keyword) {
                        .@"return" => {
                            converter.skip_space();

                            const abi_return_type = current_function_type.abi_return_type;
                            _ = abi_return_type;
                            const return_type_abi = &current_function_type.return_type_abi;
                            const returns_nothing = converter.consume_character_if_match(';');
                            if (returns_nothing) {
                                @trap();
                            } else {
                                // TODO: take ABI into account
                                const return_value = converter.parse_value(module, return_type_abi.semantic_type, .value);

                                if (module.llvm.di_builder) |_| {
                                    module.llvm.builder.set_current_debug_location(statement_debug_location);
                                }

                                // Clang equivalent: CodeGenFunction::EmitReturnStmt
                                switch (return_type_abi.semantic_type.get_evaluation_kind()) {
                                    .scalar => {
                                        switch (return_type_abi.flags.kind) {
                                            .indirect => {
                                                @trap();
                                            },
                                            else => {
                                                const return_alloca = current_function.return_alloca;
                                                _ = module.create_store(.{
                                                    .source_value = return_value.llvm,
                                                    .destination_value = return_alloca,
                                                    .source_type = return_type_abi.semantic_type,
                                                    .destination_type = current_function_type.abi_return_type,
                                                });
                                            },
                                        }
                                    },
                                    .aggregate => {
                                        // TODO: handcoded code, might be wrong
                                        const return_alloca = current_function.return_alloca;
                                        const abi_alignment = current_function_type.return_type_abi.semantic_type.get_byte_alignment();
                                        const abi_size = current_function_type.return_type_abi.semantic_type.get_byte_size();
                                        switch (return_type_abi.flags.kind) {
                                            .indirect => {
                                                _ = module.llvm.builder.create_memcpy(return_alloca, abi_alignment, return_value.llvm, abi_alignment, module.integer_type(64, false).llvm.handle.to_integer().get_constant(abi_size, @intFromBool(false)).to_value());
                                            },
                                            else => {
                                                switch (current_function_type.abi_return_type.get_evaluation_kind()) {
                                                    .aggregate => {
                                                        assert(abi_alignment == return_type_abi.semantic_type.get_byte_alignment());
                                                        assert(abi_size == return_type_abi.semantic_type.get_byte_size());
                                                        _ = module.llvm.builder.create_memcpy(return_alloca, abi_alignment, return_value.llvm, abi_alignment, module.integer_type(64, false).llvm.handle.to_integer().get_constant(abi_size, @intFromBool(false)).to_value());
                                                    },
                                                    .scalar => {
                                                        const destination_type = current_function_type.return_type_abi.semantic_type;
                                                        const source_type = current_function_type.return_type_abi.semantic_type;
                                                        assert(return_value.type == source_type);
                                                        const rv = switch (return_value.type.bb) {
                                                            .pointer => return_value.llvm,
                                                            // TODO: this feels hacky
                                                            else => switch (return_value.lvalue) {
                                                                true => module.create_load(.{ .type = return_value.type, .value = return_value.llvm }),
                                                                false => return_value.llvm,
                                                            },
                                                        };
                                                        _ = module.create_store(.{ .source_value = rv, .source_type = source_type, .destination_value = return_alloca, .destination_type = destination_type });
                                                    },
                                                    .complex => @trap(),
                                                }
                                            },
                                        }
                                    },
                                    .complex => @trap(),
                                }
                            }

                            _ = module.llvm.builder.create_branch(current_function.return_block);
                            _ = module.llvm.builder.clear_insertion_position();
                        },
                        .@"if" => {
                            const taken_block = module.llvm.context.create_basic_block("if.true", current_function_global.value.llvm.to_function());
                            const not_taken_block = module.llvm.context.create_basic_block("if.false", current_function_global.value.llvm.to_function());
                            const exit_block = module.llvm.context.create_basic_block("if.end", null);

                            converter.skip_space();

                            converter.expect_character(left_parenthesis);
                            converter.skip_space();

                            const condition = converter.parse_value(module, null, .value);

                            converter.skip_space();
                            converter.expect_character(right_parenthesis);

                            _ = module.llvm.builder.create_conditional_branch(condition.llvm, taken_block, not_taken_block);
                            module.llvm.builder.position_at_end(taken_block);

                            const previous_exit_block = current_function.exit_block;
                            defer current_function.exit_block = previous_exit_block;

                            current_function.exit_block = exit_block;

                            converter.parse_block(module);

                            const if_final_block = module.llvm.builder.get_insert_block();

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
                            module.llvm.builder.position_at_end(not_taken_block);
                            if (is_else) {
                                current_function.exit_block = exit_block;
                                converter.parse_block(module);
                                is_second_block_terminated = module.llvm.builder.get_insert_block() == null;
                            } else {
                                if (if_final_block) |final_block| {
                                    const current_insert_block = module.llvm.builder.get_insert_block();
                                    defer if (current_insert_block) |block| {
                                        module.llvm.builder.position_at_end(block);
                                    };
                                    module.llvm.builder.position_at_end(final_block);
                                    _ = module.llvm.builder.create_branch(not_taken_block);
                                    module.llvm.builder.clear_insertion_position();
                                }

                                assert(exit_block.to_value().use_empty());
                                not_taken_block.to_value().set_name("if.end");
                                assert(exit_block.get_parent() == null);
                                exit_block.delete();
                            }

                            if (!(if_final_block == null and is_second_block_terminated)) {
                                if (if_final_block != null) {
                                    // @trap();
                                }

                                if (!is_second_block_terminated) {
                                    // if (is_else) {
                                    //     @trap();
                                    // } else {}
                                }
                            } else {
                                assert(exit_block.get_parent() == null);
                                // TODO:
                                // if call `exit_block.erase_from_paren()`, it crashes, investigate
                                exit_block.delete();
                            }

                            require_semicolon = false;
                        },
                    }
                } else {
                    converter.offset -= statement_start_identifier.len;

                    const v = converter.parse_value(module, null, .maybe_pointer);

                    converter.skip_space();

                    switch (converter.content[converter.offset]) {
                        '=' => {
                            // const left = v;
                            converter.expect_character('=');

                            converter.skip_space();

                            const left = v;
                            if (left.type.bb != .pointer) {
                                converter.report_error();
                            }
                            const store_alignment = left.type.bb.pointer.alignment;
                            const store_type = left.type.bb.pointer.type;
                            const right = converter.parse_value(module, store_type, .value);

                            switch (store_type.get_evaluation_kind()) {
                                .aggregate => {
                                    @trap();
                                },
                                else => _ = module.create_store(.{ .source_value = right.llvm, .destination_value = left.llvm, .source_type = store_type, .destination_type = store_type, .alignment = store_alignment }),
                            }
                        },
                        ';' => {
                            const is_noreturn = v.type.bb == .noreturn;
                            const is_valid = v.type.bb == .void or is_noreturn;
                            if (!is_valid) {
                                converter.report_error();
                            }

                            if (is_noreturn) {
                                _ = module.llvm.builder.create_unreachable();
                            }
                        },
                        else => @trap(),
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
        icmp_eq,
        icmp_ne,

        pub fn to_int_predicate(expression_state: ExpressionState) llvm.IntPredicate {
            return switch (expression_state) {
                .icmp_ne => .ne,
                .icmp_eq => .eq,
                else => @trap(),
            };
        }
    };

    const ValueKind = enum {
        pointer,
        value,
        maybe_pointer,
    };

    fn parse_value(noalias converter: *Converter, noalias module: *Module, maybe_expected_type: ?*Type, value_kind: ValueKind) *Value {
        converter.skip_space();

        var value_state = ExpressionState.none;
        var previous_value: ?*Value = null;
        var iterations: usize = 0;
        var iterative_expected_type = maybe_expected_type;

        const value: *Value = while (true) : (iterations += 1) {
            if (iterations == 1) {
                iterative_expected_type = previous_value.?.type;
            }

            const current_value = switch (converter.consume_character_if_match(left_parenthesis)) {
                true => blk: {
                    const r = converter.parse_value(module, iterative_expected_type, value_kind);
                    converter.skip_space();
                    converter.expect_character(right_parenthesis);
                    break :blk r;
                },
                false => converter.parse_single_value(module, iterative_expected_type, value_kind),
            };

            converter.skip_space();

            const left = switch (value_state) {
                .none => undefined,
                else => previous_value.?.llvm,
            };
            const right = current_value.llvm;
            const next_ty = if (previous_value) |pv| pv.type else current_value.type;

            const llvm_value = switch (value_state) {
                .none => current_value.llvm,
                .sub => module.llvm.builder.create_sub(left, right),
                .add => module.llvm.builder.create_add(left, right),
                .mul => module.llvm.builder.create_mul(left, right),
                .sdiv => module.llvm.builder.create_sdiv(left, right),
                .udiv => module.llvm.builder.create_udiv(left, right),
                .srem => module.llvm.builder.create_srem(left, right),
                .urem => module.llvm.builder.create_urem(left, right),
                .shl => module.llvm.builder.create_shl(left, right),
                .ashr => module.llvm.builder.create_ashr(left, right),
                .lshr => module.llvm.builder.create_lshr(left, right),
                .@"and" => module.llvm.builder.create_and(left, right),
                .@"or" => module.llvm.builder.create_or(left, right),
                .xor => module.llvm.builder.create_xor(left, right),
                .icmp_ne, .icmp_eq => |icmp| module.llvm.builder.create_compare(icmp.to_int_predicate(), left, right),
            };

            switch (value_state) {
                .none => previous_value = current_value,
                else => {
                    previous_value = module.values.add();
                    previous_value.?.* = .{
                        .llvm = llvm_value,
                        .type = switch (value_state) {
                            .none => unreachable,
                            .icmp_eq, .icmp_ne => module.integer_type(1, false),
                            .sub,
                            .add,
                            .mul,
                            .sdiv,
                            .udiv,
                            .srem,
                            .urem,
                            .shl,
                            .ashr,
                            .lshr,
                            .@"and",
                            .@"or",
                            .xor,
                            => next_ty,
                        },
                        .bb = .instruction,
                        .lvalue = false,
                        .dereference_to_assign = false,
                    };
                },
            }

            const ch = converter.content[converter.offset];
            value_state = switch (ch) {
                ',', ';', right_parenthesis, right_bracket, right_brace => break previous_value.?,
                '=' => switch (converter.content[converter.offset + 1]) {
                    '=' => blk: {
                        converter.offset += 2;
                        break :blk .icmp_eq;
                    },
                    else => break previous_value.?,
                },
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
        not_zero,
    };

    const Intrinsic = enum {
        byte_size,
        cast,
        cast_to,
        extend,
        trap,
        truncate,
        va_start,
        va_end,
        va_copy,
        va_arg,
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
            .byte_size => {
                const ty = converter.parse_type(module);
                converter.skip_space();
                converter.expect_character(')');
                const byte_size = ty.get_byte_size();
                const destination_type = expected_type orelse converter.report_error();
                if (destination_type.bb != .integer) {
                    converter.report_error();
                }
                const value = module.values.add();
                value.* = .{
                    .llvm = destination_type.llvm.handle.to_integer().get_constant(byte_size, @intFromBool(false)).to_value(),
                    .bb = .{
                        .constant_integer = .{
                            .value = byte_size,
                            .signed = false,
                        },
                    },
                    .type = destination_type,
                    .lvalue = false,
                    .dereference_to_assign = false,
                };
                return value;
            },
            .cast => {
                @trap();
            },
            .cast_to => {
                const destination_type = converter.parse_type(module);
                converter.skip_space();
                converter.expect_character(',');
                const source_value = converter.parse_value(module, null, .value);
                converter.skip_space();
                converter.expect_character(')');

                if (source_value.type.bb == .pointer and destination_type.bb == .integer) {
                    const value = module.values.add();
                    value.* = .{
                        .llvm = module.llvm.builder.create_ptr_to_int(source_value.llvm, destination_type.llvm.handle),
                        .type = destination_type,
                        .bb = .instruction,
                        .lvalue = false,
                        .dereference_to_assign = false,
                    };
                    return value;
                } else {
                    @trap();
                }
            },
            .extend => {
                const source_value = converter.parse_value(module, null, .value);
                converter.skip_space();
                converter.expect_character(right_parenthesis);
                const source_type = source_value.type;
                const destination_type = expected_type orelse converter.report_error();
                if (source_type.get_bit_size() > destination_type.get_bit_size()) {
                    converter.report_error();
                } else if (source_type.get_bit_size() == destination_type.get_bit_size() and source_type.is_signed() == destination_type.is_signed()) {
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
                    .lvalue = false,
                    .dereference_to_assign = false,
                };

                return value;
            },
            .trap => {
                converter.expect_character(right_parenthesis);

                // TODO: lookup in advance
                const intrinsic_id = module.llvm.intrinsic_table.trap;
                const argument_types: []const *llvm.Type = &.{};
                const argument_values: []const *llvm.Value = &.{};
                const intrinsic_function = module.llvm.handle.get_intrinsic_declaration(intrinsic_id, argument_types);
                const intrinsic_function_type = module.llvm.context.get_intrinsic_type(intrinsic_id, argument_types);
                const llvm_call = module.llvm.builder.create_call(intrinsic_function_type, intrinsic_function, argument_values);
                _ = module.llvm.builder.create_unreachable();
                module.llvm.builder.clear_insertion_position();

                const value = module.values.add();
                value.* = .{
                    .llvm = llvm_call,
                    .type = module.noreturn_type,
                    .bb = .instruction,
                    .lvalue = false,
                    .dereference_to_assign = false,
                };

                return value;
            },
            .truncate => {
                const source_value = converter.parse_value(module, null, .value);
                converter.skip_space();
                converter.expect_character(right_parenthesis);
                const destination_type = expected_type orelse converter.report_error();
                const truncate = module.llvm.builder.create_truncate(source_value.llvm, destination_type.llvm.handle);

                const value = module.values.add();
                value.* = .{
                    .llvm = truncate,
                    .type = destination_type,
                    .bb = .instruction,
                    .lvalue = false,
                    .dereference_to_assign = false,
                };

                return value;
            },
            .va_start => {
                converter.expect_character(right_parenthesis);

                const va_list_type = module.get_va_list_type();
                const alloca = module.create_alloca(.{ .type = va_list_type });
                const intrinsic_id = module.llvm.intrinsic_table.va_start;
                const argument_types: []const *llvm.Type = &.{module.llvm.pointer_type};
                const intrinsic_function = module.llvm.handle.get_intrinsic_declaration(intrinsic_id, argument_types);
                const intrinsic_function_type = module.llvm.context.get_intrinsic_type(intrinsic_id, argument_types);
                const argument_values: []const *llvm.Value = &.{alloca};
                _ = module.llvm.builder.create_call(intrinsic_function_type, intrinsic_function, argument_values);

                const value = module.values.add();
                value.* = .{
                    .llvm = alloca,
                    .type = module.get_pointer_type(.{ .type = va_list_type }),
                    .bb = .instruction,
                    .lvalue = true,
                    .dereference_to_assign = true,
                };

                return value;
            },
            .va_end => {
                const va_list = converter.parse_value(module, module.get_pointer_type(.{ .type = module.get_va_list_type() }), .pointer);
                converter.skip_space();
                converter.expect_character(right_parenthesis);
                const intrinsic_id = module.llvm.intrinsic_table.va_end;
                const argument_types: []const *llvm.Type = &.{module.llvm.pointer_type};
                const intrinsic_function = module.llvm.handle.get_intrinsic_declaration(intrinsic_id, argument_types);
                const intrinsic_function_type = module.llvm.context.get_intrinsic_type(intrinsic_id, argument_types);
                const argument_values: []const *llvm.Value = &.{va_list.llvm};
                const llvm_value = module.llvm.builder.create_call(intrinsic_function_type, intrinsic_function, argument_values);
                const value = module.values.add();
                value.* = .{
                    .llvm = llvm_value,
                    .type = module.void_type,
                    .bb = .instruction,
                    .lvalue = false,
                    .dereference_to_assign = false,
                };

                return value;
            },
            .va_copy => @trap(),
            .va_arg => {
                const va_list_type = module.get_va_list_type();
                const raw_va_list = converter.parse_value(module, module.get_pointer_type(.{ .type = va_list_type }), .pointer);
                const va_list = module.llvm.builder.create_gep(.{
                    .type = va_list_type.llvm.handle,
                    .aggregate = raw_va_list.llvm,
                    .indices = &([1]*llvm.Value{module.integer_type(64, false).llvm.handle.to_integer().get_constant(0, @intFromBool(false)).to_value()} ** 2),
                });

                converter.skip_space();

                converter.expect_character(',');

                converter.skip_space();

                const arg_type = converter.parse_type(module);
                converter.skip_space();

                converter.expect_character(right_parenthesis);
                const r = Abi.SystemV.classify_argument_type(module, arg_type, .{
                    .available_gpr = 0,
                    .is_named_argument = false,
                    .is_reg_call = false,
                });
                const abi = r[0];
                const needed_register_count = r[1];

                const abi_kind = abi.flags.kind;
                assert(abi_kind != .ignore);

                const va_list_struct = va_list_type.bb.array.element_type;
                const llvm_address = switch (needed_register_count.gpr == 0 and needed_register_count.sse == 0) {
                    true => Abi.SystemV.emit_va_arg_from_memory(module, va_list, va_list_struct, arg_type),
                    false => blk: {
                        const va_list_struct_llvm = va_list_struct.llvm.handle.to_struct();
                        const gpr_offset_pointer = if (needed_register_count.gpr != 0) module.llvm.builder.create_struct_gep(va_list_struct_llvm, va_list, 0) else undefined;
                        const gpr_offset = if (needed_register_count.gpr != 0) module.create_load(.{ .type = va_list_struct.bb.structure.fields[0].type, .value = gpr_offset_pointer, .alignment = 16 }) else undefined;
                        const raw_in_regs = 48 - needed_register_count.gpr * 8;
                        const int32 = module.integer_type(32, false);
                        const int32_llvm = int32.llvm.handle.to_integer();
                        var in_regs = if (needed_register_count.gpr != 0) int32_llvm.get_constant(raw_in_regs, @intFromBool(false)).to_value() else @trap();
                        in_regs = if (needed_register_count.gpr != 0) module.llvm.builder.create_compare(.ule, gpr_offset, in_regs) else in_regs;

                        const fp_offset_pointer = if (needed_register_count.sse != 0) module.llvm.builder.create_struct_gep(va_list_struct_llvm, va_list, 1) else undefined;
                        const fp_offset = if (needed_register_count.sse != 0) module.create_load(.{ .type = va_list_struct.bb.structure.fields[1].type, .value = fp_offset_pointer }) else undefined;
                        const raw_fits_in_fp = 176 - needed_register_count.sse * 16;
                        var fits_in_fp = if (needed_register_count.sse != 0) int32_llvm.get_constant(raw_fits_in_fp, @intFromBool(false)).to_value() else undefined;
                        fits_in_fp = if (needed_register_count.sse != 0) module.llvm.builder.create_compare(.ule, fp_offset, fits_in_fp) else undefined;
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
                            const register_address = module.llvm.builder.create_gep(.{
                                .type = va_list_struct.bb.structure.fields[3].type.bb.pointer.type.llvm.handle,
                                .aggregate = reg_save_area,
                                .indices = &.{gpr_offset},
                                .inbounds = false,
                            });
                            if (arg_type.get_byte_alignment() > 8) {
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
                            _ = module.create_store(.{ .destination_value = gpr_offset_pointer, .source_value = new_offset, .source_type = int32, .destination_type = int32, .alignment = 16 });
                        }

                        if (needed_register_count.sse != 0) {
                            @trap();
                        }

                        _ = module.llvm.builder.create_branch(end_block);

                        module.emit_block(in_mem_block);

                        const memory_address = Abi.SystemV.emit_va_arg_from_memory(module, va_list, va_list_struct, arg_type);
                        module.emit_block(end_block);

                        const values = &.{ register_address, memory_address };
                        const blocks = &.{ in_reg_block, in_mem_block };
                        const phi = module.llvm.builder.create_phi(module.llvm.pointer_type);
                        phi.add_incoming(values, blocks);
                        break :blk phi.to_value();
                    },
                };

                switch (arg_type.get_evaluation_kind()) {
                    .aggregate => {
                        const result_type = module.get_pointer_type(.{ .type = arg_type });
                        const value = module.values.add();
                        value.* = .{
                            .type = result_type,
                            .bb = .instruction,
                            .llvm = llvm_address,
                            .lvalue = true,
                            .dereference_to_assign = true,
                        };
                        return value;
                    },
                    .scalar => {
                        const value = module.values.add();
                        const load = module.create_load(.{ .type = arg_type, .value = llvm_address });
                        value.* = .{
                            .type = arg_type,
                            .bb = .instruction,
                            .llvm = load,
                            .lvalue = false,
                            .dereference_to_assign = false,
                        };
                        return value;
                    },
                    .complex => @trap(),
                }
            },
        }
    }

    fn parse_single_value(noalias converter: *Converter, noalias module: *Module, expected_type: ?*Type, value_kind: ValueKind) *Value {
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
                    .structure => |*struct_type| {
                        var field_count: u32 = 0;

                        var field_value_buffer: [64]*Value = undefined;
                        var field_index_buffer: [64]u32 = undefined;

                        var is_ordered = true;
                        var is_constant = true;

                        while (converter.consume_character_if_match('.')) : (field_count += 1) {
                            converter.skip_space();

                            const field_name = converter.parse_identifier();
                            const field_index: u32 = for (struct_type.fields, 0..) |*field, field_index| {
                                if (lib.string.equal(field.name, field_name)) {
                                    break @intCast(field_index);
                                }
                            } else converter.report_error();

                            is_ordered = is_ordered and field_index == field_count;
                            const field = struct_type.fields[field_index];

                            converter.skip_space();

                            converter.expect_character('=');

                            converter.skip_space();

                            const field_value = converter.parse_value(module, field.type, .value);
                            if (field.type != field_value.type) {
                                @trap();
                            }
                            if (field.type.llvm.handle != field_value.type.llvm.handle) {
                                @trap();
                            }
                            is_constant = is_constant and field_value.is_constant();
                            field_value_buffer[field_count] = field_value;
                            field_index_buffer[field_count] = field_index;

                            converter.skip_space();

                            _ = converter.consume_character_if_match(',');

                            converter.skip_space();
                        }

                        converter.expect_character(right_brace);

                        if (must_be_constant and !is_constant) {
                            @trap();
                        }

                        if (field_count != struct_type.fields.len) {
                            // expect: 'zero' keyword
                            @trap();
                        }

                        const llvm_value = switch (is_constant and is_ordered) {
                            true => blk: {
                                var llvm_value_buffer: [64]*llvm.Constant = undefined;
                                var llvm_gc_value_buffer = [1]?*llvm.GlobalVariable{null} ** 64;
                                const llvm_values = llvm_value_buffer[0..field_count];
                                const llvm_gc_values = llvm_gc_value_buffer[0..field_count];
                                for (field_value_buffer[0..field_count], llvm_gc_values, llvm_values, struct_type.fields) |field_value, *llvm_gc_value, *llvm_field_value, *field| {
                                    llvm_field_value.* = switch (field.type.llvm.handle == field_value.llvm.get_type()) {
                                        true => field_value.llvm.to_constant(),
                                        false => switch (field.type.bb) {
                                            .array => b: {
                                                const global_variable = field_value.llvm.to_global_variable();
                                                const initializer = global_variable.get_initializer();
                                                const use_empty = field_value.llvm.use_empty();
                                                if (use_empty) {
                                                    llvm_gc_value.* = global_variable;
                                                }
                                                break :b initializer;
                                            },
                                            .structure => b: {
                                                assert(field_value.lvalue);
                                                assert(field.type == field_value.type);
                                                const global_variable = field_value.llvm.to_global_variable();
                                                const initializer = global_variable.get_initializer();
                                                const use_empty = field_value.llvm.use_empty();
                                                if (use_empty) {
                                                    llvm_gc_value.* = global_variable;
                                                }
                                                break :b initializer;
                                            },
                                            else => @trap(),
                                        },
                                    };
                                }

                                const constant_struct = ty.llvm.handle.to_struct().get_constant(llvm_values);
                                const result = switch (module.current_function == null) {
                                    true => constant_struct.to_value(),
                                    false => b: {
                                        const global_variable = module.llvm.handle.create_global_variable(.{
                                            .linkage = .InternalLinkage,
                                            .name = module.arena.join_string(&.{ "__const.", module.current_function.?.name, if (ty.name) |n| n else "" }),
                                            .initial_value = constant_struct,
                                            .type = ty.llvm.handle,
                                        });
                                        break :b global_variable.to_value();
                                    },
                                };

                                for (llvm_gc_values) |maybe_gc_value| {
                                    if (maybe_gc_value) |gc_value| {
                                        gc_value.erase_from_parent();
                                        // gc_value.delete();
                                    }
                                }

                                break :blk result;
                            },
                            false => @trap(),
                        };

                        const value = module.values.add();
                        value.* = .{
                            .llvm = llvm_value,
                            .type = ty,
                            .bb = .{
                                .struct_initialization = .{
                                    .is_constant = is_constant,
                                },
                            },
                            .lvalue = true,
                            .dereference_to_assign = false,
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

                            const field_value = converter.parse_value(module, field.type, .value);

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
                            .lvalue = false,
                            .dereference_to_assign = false,
                        };

                        return value;
                    },
                    else => converter.report_error(),
                }
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

                            const element_value = converter.parse_value(module, array.element_type, .value);
                            elements_are_constant = elements_are_constant and element_value.is_constant();
                            element_buffer[element_count] = element_value.llvm;

                            converter.skip_space();

                            _ = converter.consume_character_if_match(',');
                        }

                        if (array.element_count == null) {
                            array.element_count = element_count;
                            ty.llvm = array_type_llvm(module, array.*);
                            ty.name = array_type_name(module.arena, array.*);
                        }

                        const array_elements = element_buffer[0..element_count];
                        if (elements_are_constant) {
                            const constant_array = array.element_type.llvm.handle.get_constant_array(@ptrCast(array_elements));
                            const global = switch (module.current_function == null) {
                                true => constant_array.to_value(),
                                false => b: {
                                    const global_variable = module.llvm.handle.create_global_variable(.{
                                        .linkage = .InternalLinkage,
                                        .name = module.arena.join_string(&.{ "__const.", module.current_function.?.name, if (ty.name) |n| n else "" }),
                                        .initial_value = constant_array,
                                        .type = ty.llvm.handle,
                                    });
                                    break :b global_variable.to_value();
                                },
                            };
                            const value = module.values.add();
                            value.* = .{
                                .llvm = global,
                                .type = ty,
                                .bb = .constant_array,
                                .lvalue = true,
                                .dereference_to_assign = false,
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
            '&' => {
                converter.offset += 1;
                return converter.parse_value(module, expected_type, .pointer);
            },
            '!' => blk: {
                converter.offset += 1;

                // TODO: should we skip space here?
                converter.skip_space();
                break :blk .not_zero;
            },
            else => os.abort(),
        };

        const value_offset = converter.offset;
        const value_start_ch = converter.content[value_offset];
        var value = switch (value_start_ch) {
            'a'...'z', 'A'...'Z', '_' => b: {
                if (module.current_function) |current_function| {
                    const identifier = converter.parse_identifier();
                    if (lib.string.equal(identifier, "_")) {
                        return module.get_infer_or_ignore_value();
                    } else if (lib.string.equal(identifier, "undefined")) {
                        const expected_ty = expected_type orelse converter.report_error();
                        // TODO: cache poison
                        const value = module.values.add();
                        value.* = .{
                            .llvm = expected_ty.llvm.handle.get_poison(),
                            .type = expected_ty,
                            .bb = .instruction, // TODO
                            .lvalue = false,
                            .dereference_to_assign = false,
                        };
                        return value;
                    } else {
                        const variable = if (current_function.value.bb.function.locals.find(identifier)) |local| local else if (current_function.value.bb.function.arguments.find(identifier)) |argument| argument else if (module.globals.find(identifier)) |global| global else converter.report_error();

                        converter.skip_space();

                        assert(variable.value.type.bb == .pointer);
                        const appointee_type = variable.value.type.bb.pointer.type;

                        if (converter.consume_character_if_match(left_parenthesis)) {
                            if (value_kind == .pointer) {
                                converter.report_error();
                            }
                            const call = converter.parse_call(module, variable.value);
                            break :b call;
                        } else if (converter.consume_character_if_match('.')) {
                            converter.skip_space();

                            switch (appointee_type.bb) {
                                .structure => |*struct_type| {
                                    const field_name = converter.parse_identifier();
                                    const field_index: u32 = for (struct_type.fields, 0..) |field, field_index| {
                                        if (lib.string.equal(field.name, field_name)) {
                                            break @intCast(field_index);
                                        }
                                    } else converter.report_error();
                                    const field = struct_type.fields[field_index];
                                    const gep = module.llvm.builder.create_struct_gep(appointee_type.llvm.handle.to_struct(), variable.value.llvm, field_index);

                                    switch (value_kind) {
                                        .pointer, .maybe_pointer => {
                                            @trap();
                                        },
                                        .value => {
                                            const load = module.values.add();
                                            load.* = .{
                                                .llvm = module.create_load(.{ .type = field.type, .value = gep }),
                                                .type = field.type,
                                                .bb = .instruction,
                                                .lvalue = false,
                                                .dereference_to_assign = false,
                                            };
                                            break :b load;
                                        },
                                    }
                                },
                                .bits => |*bits| {
                                    const field_name = converter.parse_identifier();
                                    const field_index: u32 = for (bits.fields, 0..) |field, field_index| {
                                        if (lib.string.equal(field.name, field_name)) {
                                            break @intCast(field_index);
                                        }
                                    } else converter.report_error();
                                    const field = bits.fields[field_index];

                                    const bitfield_load = module.create_load(.{ .type = bits.backing_type, .value = variable.value.llvm });
                                    const bitfield_shifted = module.llvm.builder.create_lshr(bitfield_load, bits.backing_type.llvm.handle.to_integer().get_constant(field.bit_offset, @intFromBool(false)).to_value());
                                    const bitfield_masked = module.llvm.builder.create_and(bitfield_shifted, bits.backing_type.llvm.handle.to_integer().get_constant((@as(u64, 1) << @intCast(field.type.get_bit_size())) - 1, @intFromBool(false)).to_value());

                                    if (value_kind == .pointer) {
                                        converter.report_error();
                                    }

                                    const value = module.values.add();
                                    value.* = .{
                                        .type = bits.backing_type,
                                        .llvm = bitfield_masked,
                                        .bb = .instruction,
                                        .lvalue = false,
                                        .dereference_to_assign = false,
                                    };

                                    break :b value;
                                },
                                .pointer => |pointer_type| {
                                    const element_type = pointer_type.type;
                                    if (converter.consume_character_if_match('&')) {
                                        const load = module.values.add();
                                        load.* = .{
                                            .llvm = module.create_load(.{ .type = appointee_type, .value = variable.value.llvm }),
                                            .type = appointee_type,
                                            .bb = .instruction,
                                            .lvalue = false,
                                            .dereference_to_assign = false,
                                        };
                                        break :b load;
                                    } else {
                                        switch (element_type.bb) {
                                            .structure => |*struct_type| {
                                                const field_name = converter.parse_identifier();
                                                const field_index: u32 = for (struct_type.fields, 0..) |field, field_index| {
                                                    if (lib.string.equal(field.name, field_name)) {
                                                        break @intCast(field_index);
                                                    }
                                                } else converter.report_error();
                                                const field = struct_type.fields[field_index];
                                                const gep = module.llvm.builder.create_struct_gep(element_type.llvm.handle.to_struct(), variable.value.llvm, field_index);
                                                switch (value_kind) {
                                                    .pointer, .maybe_pointer => {
                                                        @trap();
                                                    },
                                                    .value => {
                                                        const load = module.values.add();
                                                        load.* = .{
                                                            .llvm = module.create_load(.{ .type = field.type, .value = gep }),
                                                            .type = field.type,
                                                            .bb = .instruction,
                                                            .lvalue = false,
                                                            .dereference_to_assign = false,
                                                        };
                                                        break :b load;
                                                    },
                                                }
                                            },
                                            else => @trap(),
                                        }
                                    }
                                },
                                else => @trap(),
                            }
                        } else if (converter.consume_character_if_match(left_bracket)) {
                            converter.skip_space();

                            const index_type = module.integer_type(64, false);
                            const llvm_index_type = module.integer_type(64, false).llvm.handle.to_integer();
                            const zero_index = llvm_index_type.get_constant(0, @intFromBool(false)).to_value();
                            const index = converter.parse_value(module, index_type, .value);

                            converter.skip_space();
                            converter.expect_character(right_bracket);

                            const gep = module.llvm.builder.create_gep(.{
                                .type = appointee_type.llvm.handle,
                                .aggregate = variable.value.llvm,
                                .indices = &.{ zero_index, index.llvm },
                            });

                            switch (value_kind) {
                                .pointer, .maybe_pointer => {
                                    @trap();
                                },
                                .value => {
                                    const load = module.values.add();
                                    const load_type = appointee_type.bb.array.element_type;
                                    load.* = .{
                                        .llvm = module.create_load(.{ .type = load_type, .value = gep }),
                                        .type = load_type,
                                        .bb = .instruction,
                                        .lvalue = false,
                                        .dereference_to_assign = false,
                                    };
                                    break :b load;
                                },
                            }
                        } else {
                            switch (value_kind) {
                                .pointer, .maybe_pointer => break :b variable.value,
                                .value => switch (appointee_type.get_evaluation_kind()) {
                                    .aggregate => {
                                        const value_address = module.values.add();
                                        value_address.* = .{
                                            .llvm = variable.value.llvm,
                                            .type = variable.value.type,
                                            .bb = .instruction,
                                            .lvalue = true,
                                            .dereference_to_assign = true,
                                        };
                                        break :b value_address;
                                    },
                                    else => {
                                        const load = module.values.add();
                                        load.* = .{
                                            .llvm = module.create_load(.{ .type = appointee_type, .value = variable.value.llvm }),
                                            .type = appointee_type,
                                            .bb = .instruction,
                                            .lvalue = false,
                                            .dereference_to_assign = false,
                                        };
                                        break :b load;
                                    },
                                },
                            }
                        }
                    }
                } else {
                    converter.report_error();
                }
            },
            '0'...'9' => converter.parse_integer(module, expected_type.?, prefix == .negative),
            else => os.abort(),
        };

        switch (prefix) {
            .none,
            .negative, // Already done in 'parse_integer' // TODO:
            => {},
            .not_zero => {
                const llvm_value = module.llvm.builder.create_compare(.eq, value.llvm, value.type.llvm.handle.to_integer().get_constant(0, 0).to_value());
                value.* = .{
                    .llvm = llvm_value,
                    .bb = .instruction,
                    .type = module.integer_type(1, false),
                    .lvalue = false,
                    .dereference_to_assign = false,
                };
            },
        }

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
                .void, .noreturn => result[current_index] = .none,
                .bits => result[current_index] = .integer,
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

                                for (0..array_type.element_count.?) |_| {
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
                        else => return module.integer_type(@intCast(@min(ty.get_byte_size() - source_offset, 8) * 8), integer_type.signed),
                    }
                },
                .pointer => return if (offset == 0) ty else @trap(),
                .structure => {
                    if (get_member_at_offset(ty, offset)) |field| {
                        return get_int_type_at_offset(module, field.type, @intCast(offset - field.byte_offset), source_type, source_offset);
                    }
                    unreachable;
                },
                .array => |array_type| {
                    const element_type = array_type.element_type;
                    const element_size = element_type.get_byte_size();
                    const element_offset = (offset / element_size) * element_size;
                    return get_int_type_at_offset(module, element_type, @intCast(offset - element_offset), source_type, source_offset);
                },
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
                        if (argument_type.bb == .enumerator) {
                            @trap();
                        }

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
                        true => @intCast(argument_type_abi.get_coerce_to_type().bb.structure.fields.len),
                    };

                    switch (flattened_struct) {
                        false => {
                            llvm_abi_argument_type_buffer[argument_type_abi.abi_start] = coerce_to_type.llvm.handle;
                            abi_argument_type_buffer[argument_type_abi.abi_start] = coerce_to_type;
                        },
                        true => {
                            for (coerce_to_type.bb.structure.fields, 0..) |field, field_index| {
                                const index = argument_type_abi.abi_start + field_index;
                                llvm_abi_argument_type_buffer[index] = field.type.llvm.handle;
                                abi_argument_type_buffer[index] = field.type;
                            }
                        },
                    }

                    break :blk count;
                },
                .indirect => blk: {
                    const indirect_type = module.get_pointer_type(.{ .type = argument_type_abi.semantic_type });
                    abi_argument_type_buffer[argument_type_abi.abi_start] = indirect_type;
                    llvm_abi_argument_type_buffer[argument_type_abi.abi_start] = indirect_type.llvm.handle;
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
            _ = &high;

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

pub noinline fn convert(arena: *Arena, options: ConvertOptions) void {
    const build_dir = "bb-cache";
    os.make_directory(build_dir);

    var converter = Converter{
        .content = options.content,
        .offset = 0,
        .line_offset = 0,
        .line_character_offset = 0,
    };

    llvm.default_initialize();

    const module = Module.initialize(arena, options);
    defer module.deinitialize();

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
                        var calling_convention = CallingConvention.c;
                        const function_attributes = Function.Attributes{};
                        var is_var_args = false;

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

                        var argument_buffer: [max_argument_count]struct {
                            name: []const u8,
                            type: *Type,
                            line: u32,
                            column: u32,
                        } = undefined;
                        var semantic_argument_count: u32 = 0;

                        while (converter.offset < converter.content.len and converter.content[converter.offset] != right_parenthesis) : (semantic_argument_count += 1) {
                            converter.skip_space();

                            const argument_line = converter.get_line();
                            const argument_column = converter.get_column();

                            if (converter.consume_character_if_match('.')) {
                                if (converter.consume_character_if_match('.')) {
                                    converter.expect_character('.');
                                    converter.skip_space();

                                    if (converter.content[converter.offset] == ')') {
                                        if (calling_convention != .c) {
                                            converter.report_error();
                                        }
                                        is_var_args = true;
                                        break;
                                    } else {
                                        @trap();
                                    }
                                } else {
                                    @trap();
                                }
                            }

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

                        const semantic_arguments = argument_buffer[0..semantic_argument_count];
                        const argument_type_abis = module.arena.allocate(Abi.Information, semantic_arguments.len);

                        var return_type_abi: Abi.Information = undefined;

                        const resolved_calling_convention = calling_convention.resolve(module.target);
                        const is_reg_call = resolved_calling_convention == .system_v and false; // TODO: regcall calling_convention

                        const function_type = switch (resolved_calling_convention) {
                            .system_v => ft: {
                                var available_registers: Abi.RegisterCount = switch (resolved_calling_convention) {
                                    .system_v => .{
                                        .system_v = .{
                                            .gpr = if (is_reg_call) 11 else 6,
                                            .sse = if (is_reg_call) 16 else 8,
                                        },
                                    },
                                    .win64 => @trap(),
                                };
                                var abi_return_type: *Type = undefined;
                                var abi_argument_type_count: u16 = 0;
                                var llvm_abi_argument_type_buffer: [max_argument_count]*llvm.Type = undefined;
                                var abi_argument_type_buffer: [max_argument_count]*Type = undefined;

                                return_type_abi = Abi.SystemV.classify_return_type(module, semantic_return_type);
                                const return_abi_kind = return_type_abi.flags.kind;
                                abi_return_type = switch (return_abi_kind) {
                                    .direct, .extend => return_type_abi.coerce_to_type.?,
                                    .ignore, .indirect => module.void_type,
                                    else => |t| @panic(@tagName(t)),
                                };

                                if (return_type_abi.flags.kind == .indirect) {
                                    assert(!return_type_abi.flags.sret_after_this);
                                    available_registers.system_v.gpr -= 1;
                                    const indirect_type = module.get_pointer_type(.{ .type = return_type_abi.semantic_type });
                                    abi_argument_type_buffer[abi_argument_type_count] = indirect_type;
                                    llvm_abi_argument_type_buffer[abi_argument_type_count] = indirect_type.llvm.handle;
                                    abi_argument_type_count += 1;
                                }

                                const required_arguments = semantic_argument_count;

                                for (argument_type_abis, semantic_arguments, 0..) |*argument_type_abi, semantic_argument, semantic_argument_index| {
                                    const semantic_argument_type = semantic_argument.type;
                                    const is_named_argument = semantic_argument_index < required_arguments;
                                    assert(is_named_argument);

                                    argument_type_abi.* = Abi.SystemV.classify_argument(module, &available_registers, &llvm_abi_argument_type_buffer, &abi_argument_type_buffer, .{
                                        .type = semantic_argument_type,
                                        .abi_start = abi_argument_type_count,
                                        .is_named_argument = is_named_argument,
                                    });

                                    abi_argument_type_count += argument_type_abi.abi_count;
                                }

                                const abi_argument_types = module.arena.allocate(*Type, abi_argument_type_count);
                                @memcpy(abi_argument_types, abi_argument_type_buffer[0..abi_argument_types.len]);

                                const llvm_abi_argument_types = llvm_abi_argument_type_buffer[0..abi_argument_type_count];
                                const llvm_function_type = llvm.Type.Function.get(abi_return_type.llvm.handle, llvm_abi_argument_types, is_var_args);

                                const subroutine_type_flags = llvm.DI.Flags{};
                                const subroutine_type = if (module.llvm.di_builder) |di_builder| blk: {
                                    var debug_argument_type_buffer: [max_argument_count + 1]*llvm.DI.Type = undefined;
                                    const semantic_debug_argument_types = debug_argument_type_buffer[0 .. argument_type_abis.len + 1 + @intFromBool(is_var_args)];
                                    semantic_debug_argument_types[0] = return_type_abi.semantic_type.llvm.debug;

                                    for (argument_type_abis, semantic_debug_argument_types[1..][0..argument_type_abis.len]) |argument_abi, *debug_argument_type| {
                                        debug_argument_type.* = argument_abi.semantic_type.llvm.debug;
                                    }

                                    if (is_var_args) {
                                        semantic_debug_argument_types[argument_type_abis.len + 1] = module.void_type.llvm.debug;
                                    }

                                    const subroutine_type = di_builder.create_subroutine_type(module.llvm.file, semantic_debug_argument_types, subroutine_type_flags);
                                    break :blk subroutine_type;
                                } else undefined;

                                const result = module.types.add(.{
                                    .bb = .{
                                        .function = .{
                                            .return_type_abi = return_type_abi,
                                            .calling_convention = calling_convention,
                                            .is_var_args = is_var_args,
                                            .argument_type_abis = argument_type_abis,
                                            .abi_return_type = abi_return_type,
                                            .abi_argument_types = abi_argument_types,
                                            .available_registers = available_registers,
                                        },
                                    },
                                    .llvm = .{
                                        .handle = llvm_function_type.to_type(),
                                        .debug = subroutine_type.to_type(),
                                    },
                                    .name = null,
                                });
                                break :ft result;
                            },
                            .win64 => {
                                @trap();
                            },
                        };

                        const llvm_handle = module.llvm.handle.create_function(.{
                            .name = global_name,
                            .linkage = switch (is_export or is_extern) {
                                true => .ExternalLinkage,
                                false => .InternalLinkage,
                            },
                            .type = function_type.llvm.handle.to_function(),
                        });

                        llvm_handle.set_calling_convention(calling_convention.to_llvm());
                        const has_semicolon = converter.consume_character_if_match(';');

                        const function_scope: *llvm.DI.Scope = if (module.llvm.di_builder) |di_builder| blk: {
                            const scope_line: u32 = @intCast(converter.line_offset + 1);
                            const local_to_unit = !is_export and !is_extern;
                            const flags = llvm.DI.Flags{};
                            const is_definition = !is_extern;
                            const subprogram = di_builder.create_function(module.llvm.global_scope, global_name, linkage_name, module.llvm.file, global_line, function_type.llvm.debug.to_subroutine(), local_to_unit, is_definition, scope_line, flags, options.build_mode.is_optimized());
                            llvm_handle.set_subprogram(subprogram);

                            break :blk @ptrCast(subprogram);
                        } else undefined;

                        const value = module.values.add();
                        value.* = .{
                            .llvm = llvm_handle.to_value(),
                            .type = module.get_pointer_type(.{ .type = function_type }),
                            .bb = switch (has_semicolon) {
                                true => .external_function,
                                false => .{
                                    .function = .{
                                        .current_scope = function_scope,
                                        .attributes = function_attributes,
                                        .return_pointer = undefined,
                                        .return_alloca = undefined,
                                        .exit_block = null,
                                        .return_block = undefined,
                                    },
                                },
                            },
                            .lvalue = true,
                            .dereference_to_assign = false,
                        };

                        const global = module.globals.add();
                        global.* = .{
                            .value = value,
                            .name = global_name,
                        };

                        const attribute_list = module.build_attribute_list(.{
                            .abi_return_type = function_type.bb.function.abi_return_type,
                            .abi_argument_types = function_type.bb.function.abi_argument_types,
                            .argument_type_abis = function_type.bb.function.argument_type_abis,
                            .return_type_abi = function_type.bb.function.return_type_abi,
                            .attributes = function_attributes,
                            .call_site = false,
                        });

                        llvm_handle.set_attributes(attribute_list);

                        if (!has_semicolon) {
                            const entry_block = module.llvm.context.create_basic_block("entry", llvm_handle);
                            value.bb.function.return_block = module.llvm.context.create_basic_block("ret_block", null);

                            module.llvm.builder.position_at_end(entry_block);
                            module.llvm.builder.set_current_debug_location(null);

                            // function prologue

                            var llvm_abi_argument_buffer: [argument_buffer.len]*llvm.Argument = undefined;
                            llvm_handle.get_arguments(&llvm_abi_argument_buffer);
                            const llvm_abi_arguments = llvm_abi_argument_buffer[0..function_type.bb.function.abi_argument_types.len];

                            module.current_function = global;
                            defer module.current_function = null;

                            switch (return_type_abi.flags.kind) {
                                .ignore => {},
                                .indirect => {
                                    const indirect_argument_index = @intFromBool(return_type_abi.flags.sret_after_this);
                                    if (return_type_abi.flags.sret_after_this) {
                                        @trap();
                                    }
                                    value.bb.function.return_alloca = llvm_abi_arguments[indirect_argument_index].to_value();
                                    if (!return_type_abi.flags.indirect_by_value) {
                                        @trap();
                                    }
                                },
                                .in_alloca => {
                                    @trap();
                                },
                                else => {
                                    const alloca = module.create_alloca(.{ .type = return_type_abi.semantic_type, .name = "retval" });
                                    value.bb.function.return_alloca = alloca;
                                },
                            }

                            const argument_variables = global.value.bb.function.arguments.add_many(semantic_argument_count);
                            for (semantic_arguments, argument_type_abis, argument_variables, 0..) |semantic_argument, argument_abi, *argument_variable, argument_index| {
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
                                                    const alloca = module.create_alloca(.{ .type = destination_type, .name = semantic_argument.name });
                                                    const result = switch (bit_count < abi_bit_count) {
                                                        true => switch (is_signed) {
                                                            true => module.llvm.builder.create_sign_extend(first_argument.to_value(), destination_type.llvm.handle),
                                                            false => module.llvm.builder.create_zero_extend(first_argument.to_value(), destination_type.llvm.handle),
                                                        },
                                                        false => @trap(),
                                                    };
                                                    _ = module.create_store(.{ .source_value = result, .destination_value = alloca, .source_type = destination_type, .destination_type = destination_type });
                                                    break :blk alloca;
                                                },
                                                false => { // TODO: ExtVectorBoolType
                                                    const alloca = module.create_alloca(.{ .type = argument_abi.semantic_type, .name = semantic_argument.name });
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
                                                            const gep = module.llvm.builder.create_struct_gep(coerce_to_type.llvm.handle.to_struct(), address, @intCast(field_index));
                                                            // TODO: check if alignment is right
                                                            _ = module.create_store(.{ .source_value = abi_argument.to_value(), .destination_value = gep, .source_type = field.type, .destination_type = field.type });
                                                        }

                                                        if (source_size > destination_size) {
                                                            _ = module.llvm.builder.create_memcpy(pointer, pointer_type.get_byte_alignment(), address, address_alignment, module.integer_type(64, false).llvm.handle.to_integer().get_constant(destination_size, @intFromBool(false)).to_value());
                                                        }
                                                    },
                                                }
                                            } else {
                                                assert(argument_abi.abi_count == 1);
                                                const abi_argument_type = function_type.bb.function.abi_argument_types[argument_abi.abi_start];
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

                                const argument_value = module.values.add();
                                argument_value.* = .{
                                    .llvm = semantic_argument_storage,
                                    .type = module.get_pointer_type(.{ .type = semantic_argument.type }),
                                    .bb = .argument,
                                    .lvalue = true,
                                    .dereference_to_assign = false,
                                };
                                argument_variable.* = .{
                                    .value = argument_value,
                                    .name = semantic_argument.name,
                                };

                                if (module.llvm.di_builder) |di_builder| {
                                    const always_preserve = true;
                                    const flags = llvm.DI.Flags{};
                                    const parameter_variable = di_builder.create_parameter_variable(function_scope, semantic_argument.name, @intCast(argument_index + 1), module.llvm.file, semantic_argument.line, semantic_argument.type.llvm.debug, always_preserve, flags);
                                    const inlined_at: ?*llvm.DI.Metadata = null; // TODO
                                    const debug_location = llvm.DI.create_debug_location(module.llvm.context, semantic_argument.line, semantic_argument.column, function_scope, inlined_at);
                                    _ = di_builder.insert_declare_record_at_end(semantic_argument_storage, parameter_variable, di_builder.null_expression(), debug_location, module.current_basic_block());
                                }
                            }

                            converter.parse_block(module);

                            // Handle jump to the return block
                            const return_block = value.bb.function.return_block;

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
                            if (module.llvm.di_builder) |di_builder| {
                                if (llvm_handle.get_subprogram()) |subprogram| {
                                    di_builder.finalize_subprogram(subprogram);
                                }
                            }

                            if (return_type_abi.semantic_type == module.noreturn_type or value.bb.function.attributes.naked) {
                                @trap();
                            } else if (return_type_abi.semantic_type == module.void_type) {
                                module.llvm.builder.create_ret_void();
                            } else {
                                const abi_kind = return_type_abi.flags.kind;
                                const return_value: ?*llvm.Value = switch (abi_kind) {
                                    .direct, .extend => blk: {
                                        const coerce_to_type = return_type_abi.get_coerce_to_type();
                                        const return_alloca = value.bb.function.return_alloca;

                                        if (return_type_abi.semantic_type.is_abi_equal(coerce_to_type) and return_type_abi.attributes.direct.offset == 0) {
                                            if (module.llvm.builder.find_return_value_dominating_store(return_alloca, return_type_abi.semantic_type.llvm.handle)) |store| {
                                                const store_instruction = store.to_instruction();
                                                const return_value = store_instruction.to_value().get_operand(0);
                                                const alloca = store_instruction.to_value().get_operand(1);
                                                assert(alloca == return_alloca);
                                                store_instruction.erase_from_parent();
                                                assert(alloca.use_empty());
                                                alloca.to_instruction().erase_from_parent();
                                                break :blk return_value;
                                            } else {
                                                const load_value = module.create_load(.{ .type = return_type_abi.semantic_type, .value = return_alloca });
                                                break :blk load_value;
                                            }
                                        } else {
                                            const source = switch (return_type_abi.attributes.direct.offset == 0) {
                                                true => return_alloca,
                                                false => @trap(),
                                            };

                                            const source_type = return_type_abi.semantic_type;
                                            const destination_type = coerce_to_type;
                                            const result = module.create_coerced_load(source, source_type, destination_type);
                                            break :blk result;
                                        }
                                    },
                                    .indirect => switch (return_type_abi.semantic_type.get_evaluation_kind()) {
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

                        if (!has_semicolon and lib.optimization_mode == .Debug) {
                            const verify_result = llvm_handle.verify();
                            if (!verify_result.success) {
                                lib.print_string(module.llvm.handle.to_string());
                                lib.print_string("============================\n");
                                lib.print_string(llvm_handle.to_string());
                                lib.print_string("============================\n");
                                lib.print_string(verify_result.error_message orelse unreachable);
                                lib.print_string("\n============================\n");
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

                        const struct_type = module.types.add(.{
                            .name = global_name,
                            .bb = .forward_declaration,
                            .llvm = .{
                                .handle = undefined,
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
                        var byte_alignment: u32 = 1;
                        var bit_alignment: u32 = 1;

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

                            const field_byte_alignment = field_type.get_byte_alignment();
                            const field_bit_alignment = field_type.get_bit_alignment();
                            const field_bit_size = field_type.get_bit_size();
                            const field_byte_size = field_type.get_byte_size();

                            const field_byte_offset = lib.align_forward_u64(byte_offset, field_byte_alignment);
                            const field_bit_offset = field_byte_offset * 8;

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
                            byte_offset = field_byte_offset + field_byte_size;

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

                        const fields = module.arena.allocate(Field, field_count);
                        @memcpy(fields, field_buffer[0..field_count]);

                        const element_types = llvm_field_type_buffer[0..field_count];
                        struct_type.llvm.handle = module.llvm.context.get_struct_type(element_types).to_type();

                        if (module.llvm.di_builder) |di_builder| {
                            const member_types = llvm_debug_member_type_buffer[0..field_count];
                            const debug_struct_type = di_builder.create_struct_type(module.llvm.global_scope, global_name, module.llvm.file, global_line, bit_size, @intCast(bit_alignment), .{}, member_types);
                            const forward_declared: *llvm.DI.Type.Composite = @ptrCast(struct_type.llvm.debug);
                            forward_declared.replace_all_uses_with(debug_struct_type);
                            struct_type.llvm.debug = debug_struct_type.to_type();
                        }

                        struct_type.bb = .{
                            .structure = .{
                                .bit_size = byte_size * 8,
                                .byte_size = byte_size,
                                .bit_alignment = bit_alignment,
                                .byte_alignment = byte_alignment,
                                .fields = fields,
                            },
                        };
                    },
                    .bits => {
                        const allow_implicit_type = converter.content[converter.offset] == left_brace;
                        const maybe_backing_type: ?*Type = switch (allow_implicit_type) {
                            true => null,
                            false => converter.parse_type(module),
                        };

                        converter.skip_space();

                        converter.expect_character(left_brace);

                        var field_buffer: [128]Field = undefined;
                        var field_line_buffer: [128]u32 = undefined;
                        var field_count: usize = 0;

                        var field_bit_offset: u64 = 0;

                        while (true) : (field_count += 1) {
                            converter.skip_space();

                            if (converter.consume_character_if_match(right_brace)) {
                                break;
                            }

                            const field_line = converter.get_line();
                            field_line_buffer[field_count] = field_line;

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

                            // if (module.llvm.di_builder) |di_builder| {
                            //     llvm_debug_field_buffer[field_count] = member_type;
                            // }

                            field_bit_offset += field_bit_size;

                            converter.skip_space();

                            _ = converter.consume_character_if_match(',');
                        }

                        _ = converter.consume_character_if_match(';');

                        const fields = module.arena.allocate(Field, field_count);
                        @memcpy(fields, field_buffer[0..field_count]);

                        const field_lines = field_line_buffer[0..field_count];

                        const backing_type = if (maybe_backing_type) |bt| bt else module.integer_type(@intCast(@max(8, lib.next_power_of_two(field_bit_offset))), false);
                        if (backing_type.bb != .integer) {
                            converter.report_error();
                        }

                        if (backing_type.get_bit_size() > 64) {
                            converter.report_error();
                        }

                        const bit_size = backing_type.get_bit_size();
                        const bit_alignment = backing_type.get_bit_alignment();

                        var llvm_debug_field_buffer: [128]*llvm.DI.Type.Derived = undefined;
                        const debug_member_types = llvm_debug_field_buffer[0..field_count];

                        if (module.llvm.di_builder) |di_builder| {
                            for (fields, debug_member_types, field_lines) |field, *debug_member_type, field_line| {
                                debug_member_type.* = di_builder.create_bit_field_member_type(module.llvm.global_scope, field.name, module.llvm.file, field_line, field.type.get_bit_size(), field_bit_offset, 0, .{}, backing_type.llvm.debug);
                            }
                        }

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
                const value = converter.parse_value(module, expected_type, .value);

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
                global_variable.to_value().set_alignment(@intCast(expected_type.get_byte_alignment()));

                if (module.llvm.di_builder) |di_builder| {
                    const linkage_name = global_name;
                    const local_to_unit = !(is_export or is_extern);
                    const alignment = 0; // TODO
                    const global_variable_expression = di_builder.create_global_variable(module.llvm.global_scope, global_name, linkage_name, module.llvm.file, global_line, expected_type.llvm.debug, local_to_unit, di_builder.null_expression(), alignment);
                    global_variable.add_debug_info(global_variable_expression);
                }

                const global_value = module.values.add();
                global_value.* = .{
                    .llvm = global_variable.to_value(),
                    .type = module.get_pointer_type(.{ .type = expected_type }),
                    .bb = .global,
                    .lvalue = true,
                    .dereference_to_assign = false,
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
        .optimize_when_possible = @intFromEnum(options.build_mode) > @intFromEnum(BuildMode.soft_optimize),
        .debug_info = options.has_debug_info,
        .optimization_level = if (options.build_mode != .debug_none) options.build_mode.to_llvm_ir() else null,
        .path = options.objects[0],
    });

    switch (object_generate_result) {
        .success => {
            const result = llvm.link(module.arena, .{
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
