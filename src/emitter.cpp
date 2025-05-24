#include <compiler.hpp>
#include <llvm.hpp>

enum class EvaluationKind
{
    scalar,
    aggregate,
    complex,
};

enum class TypeKind
{
    abi,
    memory,
};
fn void analyze_block(Module* module, Block* block);
fn void emit_local_storage(Module* module, Variable* variable);
fn void emit_assignment(Module* module, LLVMValueRef left_llvm, Type* left_type, Value* right);
fn void emit_macro_instantiation(Module* module, Value* value);

fn void emit_block(Module* module, LLVMBasicBlockRef basic_block)
{
    auto current_basic_block = LLVMGetInsertBlock(module->llvm.builder);
    if (current_basic_block)
    {
        if (!LLVMGetBasicBlockTerminator(current_basic_block))
        {
            LLVMBuildBr(module->llvm.builder, basic_block);
        }
    }

    if (current_basic_block && LLVMGetBasicBlockParent(current_basic_block))
    {
        LLVMInsertExistingBasicBlockAfterInsertBlock(module->llvm.builder, basic_block);
    }
    else
    {
        LLVMAppendExistingBasicBlock(module->current_function->variable.storage->llvm, basic_block);
        
    }

    LLVMPositionBuilderAtEnd(module->llvm.builder, basic_block);
}

fn LLVMValueRef emit_intrinsic_call(Module* module, IntrinsicIndex index, Slice<LLVMTypeRef> argument_types, Slice<LLVMValueRef> argument_values)
{
    auto intrinsic_id = module->llvm.intrinsic_table[(backing_type(IntrinsicIndex))index];
    auto intrinsic_function = LLVMGetIntrinsicDeclaration(module->llvm.module, intrinsic_id.n, argument_types.pointer, argument_types.length);
    auto intrinsic_function_type = LLVMIntrinsicGetType(module->llvm.context, intrinsic_id.n, argument_types.pointer, argument_types.length);
    auto call = LLVMBuildCall2(module->llvm.builder, intrinsic_function_type, intrinsic_function, argument_values.pointer, argument_values.length, "");
    return call;
}

fn EvaluationKind get_evaluation_kind(Type* type)
{
    switch (type->id)
    {
        case TypeId::void_type:
        case TypeId::noreturn:
        case TypeId::forward_declaration:
        case TypeId::unresolved:
        case TypeId::function:
        case TypeId::alias:
            unreachable();
        case TypeId::integer:
        case TypeId::pointer:
        case TypeId::bits:
        case TypeId::enumerator:
            return EvaluationKind::scalar;
        case TypeId::array:
        case TypeId::structure:
        case TypeId::union_type:
            return EvaluationKind::aggregate;
        default:
            unreachable();
    }
}

fn bool type_is_aggregate_type_for_abi(Type* type)
{
    auto evaluation_kind = get_evaluation_kind(type);
    auto is_member_function_pointer_type = false; // TODO
    return evaluation_kind != EvaluationKind::scalar || is_member_function_pointer_type;
}

fn u64 get_byte_allocation_size(Type* type)
{
    auto size = get_byte_size(type);
    auto alignment = get_byte_alignment(type);
    auto result = align_forward(size, alignment);
    return result;
}

struct LLVMGlobal
{
    String host_triple;
    String host_cpu_model;
    String host_cpu_features;
};

global_variable LLVMGlobal llvm_global;

fn bool type_is_signed(Type* type)
{
    switch (type->id)
    {
        case TypeId::integer:
            return type->integer.is_signed;
        case TypeId::enumerator:
            return type_is_signed(type->enumerator.backing_type);
        case TypeId::bits:
            return type_is_signed(type->bits.backing_type);
        case TypeId::pointer: // TODO: pointers should be signed?
            return false;
        case TypeId::alias:
            return type_is_signed(type->alias.type);
        default: unreachable();
    }
}

fn bool type_is_slice(Type* type)
{
    return type->id == TypeId::structure && type->structure.is_slice;
}

fn bool is_integral_or_enumeration_type(Type* type)
{
    switch (type->id)
    {
        case TypeId::alias: return is_integral_or_enumeration_type(type->alias.type);
        case TypeId::integer:
        case TypeId::bits:
            return true;
        case TypeId::structure:
            return false;
        default: unreachable();
    }
}

fn Type* align_integer_type(Module* module, Type* type)
{
    auto bit_count = (u32)get_bit_size(type);
    auto abi_bit_count = align_bit_count(bit_count);
    bool is_signed = type_is_signed(type);
    auto result = integer_type(module, { .bit_count = abi_bit_count, .is_signed = is_signed });
    return result;
}

fn bool is_promotable_integer_type_for_abi(Type* type)
{
    switch (type->id)
    {
        case TypeId::integer: return type->integer.bit_count < 32;
        case TypeId::bits: return is_promotable_integer_type_for_abi(type->bits.backing_type);
        case TypeId::alias: return is_promotable_integer_type_for_abi(type->alias.type);
        default: unreachable();
    }
}

fn void llvm_initialize_all_raw()
{
    assert(!llvm_initialized);

    LLVMInitializeX86TargetInfo();
    LLVMInitializeX86Target();
    LLVMInitializeX86TargetMC();
    LLVMInitializeX86AsmPrinter();
    LLVMInitializeX86AsmParser();
    LLVMInitializeX86Disassembler();

    llvm_global = {
        .host_triple = llvm_default_target_triple(),
        .host_cpu_model = llvm_host_cpu_name(),
        .host_cpu_features = llvm_host_cpu_features(),
    };
}

fn void llvm_initialize_all()
{
    if (!llvm_initialized)
    {
        llvm_initialize_all_raw();
    }
}

fn bool is_arbitrary_bit_integer(Type* type)
{
    switch (type->id)
    {
        case TypeId::integer: switch (type->integer.bit_count)
                              {
                                  case 8:
                                  case 16:
                                  case 32:
                                  case 64:
                                  case 128:
                                      return false;
                                  default: return true;
                              } break;
        case TypeId::unresolved: unreachable();
        case TypeId::bits: return is_arbitrary_bit_integer(type->bits.backing_type);
        case TypeId::enumerator: return is_arbitrary_bit_integer(type->enumerator.backing_type);
        default: return false;
    }

}

fn u64 integer_max_value(u32 bit_count, bool is_signed)
{
    auto max_value = bit_count == 64 ? ~(u64)0 : ((u64)1 << (bit_count - is_signed)) - 1;
    return max_value;
}

fn void dump_module(Module* module)
{
    print(llvm_module_to_string(module->llvm.module));
}

fn void emit_value(Module* module, Value* value, TypeKind type_kind);

fn LLVMCallConv llvm_calling_convention(CallingConvention calling_convention)
{
    LLVMCallConv cc;
    switch (calling_convention)
    {
        case CallingConvention::c: cc = LLVMCCallConv; break;
        case CallingConvention::count: unreachable();
    }

    return cc;
}

fn Type* resolve_alias(Module* module, Type* type)
{
    Type* result_type = 0;
    switch (type->id)
    {
        case TypeId::pointer:
            {
                auto* element_type = type->pointer.element_type;
                auto* resolved_element_type = resolve_alias(module, element_type);
                result_type = get_pointer_type(module, resolved_element_type);
            } break;
        case TypeId::array:
            {
                auto* element_type = type->array.element_type;
                auto element_count = type->array.element_count;
                assert(element_count);
                auto* resolved_element_type = resolve_alias(module, element_type);
                result_type = get_array_type(module, resolved_element_type, element_count);
            } break;
        case TypeId::void_type:
        case TypeId::noreturn:
        case TypeId::integer:
        case TypeId::enumerator:
        case TypeId::function:
        case TypeId::bits:
        case TypeId::union_type:
            {
                result_type = type;
            } break;
        case TypeId::structure:
            {
                if (type->structure.is_slice)
                {
                    auto element_type = resolve_alias(module, type->structure.fields[0].type->pointer.element_type);
                    result_type = get_slice_type(module, element_type);
                }
                else
                {
                    result_type = type;
                }
            } break;
        case TypeId::alias:
            {
                result_type = resolve_alias(module, type->alias.type);
            } break;
        default: unreachable();
    }

    assert(result_type);
    return result_type;
}

fn void llvm_initialize(Module* module)
{
    llvm_initialize_all();

    auto context = LLVMContextCreate();
    auto m = llvm_context_create_module(context, module->name);
    auto builder = LLVMCreateBuilderInContext(context);
    LLVMDIBuilderRef di_builder = 0;
    LLVMMetadataRef di_compile_unit = 0;
    LLVMMetadataRef di_file = 0;

    if (module->has_debug_info)
    {
        di_builder = LLVMCreateDIBuilder(m);
        auto last_slash = string_last_character(module->path, '/');
        if (last_slash == string_no_match)
        {
            report_error();
        }
        auto directory = module->path(0, last_slash);
        auto file_name = module->path(last_slash + 1);
        di_file = LLVMDIBuilderCreateFile(di_builder, (char*)file_name.pointer, file_name.length, (char*)directory.pointer, directory.length);
        auto producer_name = string_literal("bloat buster");
        auto is_optimized = build_mode_is_optimized(module->build_mode);
        auto flags = string_literal("");
        u32 runtime_version = 0;
        auto split_name = string_literal("");
        auto sysroot = string_literal("");
        auto sdk = string_literal("");
        di_compile_unit = LLVMDIBuilderCreateCompileUnit(di_builder, LLVMDWARFSourceLanguageC17, di_file, (char*)producer_name.pointer, producer_name.length, is_optimized, (char*)flags.pointer, flags.length, runtime_version, (char*)split_name.pointer, split_name.length, LLVMDWARFEmissionFull, 0, 0, is_optimized, (char*)sysroot.pointer, sysroot.length, (char*)sdk.pointer, sdk.length);
        module->scope.llvm = di_compile_unit;
    }

    module->llvm = {
        .context = context,
        .module = m,
        .builder = builder,
        .di_builder = di_builder,
        .file = di_file,
        .compile_unit = di_compile_unit,
        .pointer_type = LLVMPointerTypeInContext(context, 0),
        .void_type = LLVMVoidTypeInContext(context),
    };

    for (u64 i = 0; i < (u64)IntrinsicIndex::count; i += 1)
    {
        String name = intrinsic_names[i];
        module->llvm.intrinsic_table[i].n = LLVMLookupIntrinsicID((char*)name.pointer, name.length);
    }
}

enum class AbiSystemVClass
{
    none,
    integer,
    sse,
    sse_up,
    x87,
    x87_up,
    complex_x87,
    memory,
};

struct AbiSystemVClassifyResult
{
    AbiSystemVClass r[2];
};


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
fn AbiSystemVClass abi_system_v_merge_class(AbiSystemVClass accumulator, AbiSystemVClass field)
{
    assert(accumulator != AbiSystemVClass::memory && accumulator != AbiSystemVClass::complex_x87);

    if (accumulator == field || field == AbiSystemVClass::none)
    {
        return accumulator;
    }

    if (field == AbiSystemVClass::memory)
    {
        return AbiSystemVClass::memory;
    }

    if (accumulator == AbiSystemVClass::integer || field == AbiSystemVClass::integer)
    {
        return AbiSystemVClass::integer;
    }

    if (field == AbiSystemVClass::x87 || field == AbiSystemVClass::x87_up || field == AbiSystemVClass::complex_x87 || accumulator == AbiSystemVClass::x87 || accumulator == AbiSystemVClass::x87_up)
    {
        return AbiSystemVClass::memory;
    }

    return AbiSystemVClass::sse;
}

fn AbiSystemVClassifyResult abi_system_v_classify_post_merge(u64 aggregate_size, AbiSystemVClassifyResult classes)
{
    AbiSystemVClassifyResult result = classes;

    if (result.r[1] == AbiSystemVClass::memory)
    {
        result.r[0] = AbiSystemVClass::memory;
    }

    if (result.r[1] == AbiSystemVClass::x87_up)
    {
        trap();
    }

    if (aggregate_size > 16 && (result.r[0] != AbiSystemVClass::sse || result.r[1] != AbiSystemVClass::sse_up))
    {
        result.r[0] = AbiSystemVClass::memory;
    }

    if (result.r[1] == AbiSystemVClass::sse_up && result.r[0] != AbiSystemVClass::sse)
    {
        result.r[0] = AbiSystemVClass::sse;
    }

    return result;
}

fn bool contains_no_user_data(Type* type, u64 start, u64 end)
{
    if (get_byte_size(type) <= start)
    {
        return true;
    }
    else
    {
        switch (type->id)
        {
            case TypeId::structure:
                {
                    u64 offset = 0;

                    for (auto& field: type->structure.fields)
                    {
                        if (offset >= end)
                        {
                            break;
                        }

                        auto field_start = offset < start ? start - offset : 0;
                        if (!contains_no_user_data(field.type, field_start, end - offset))
                        {
                            return false;
                        }
                        offset += get_byte_size(field.type);
                    }

                    return true;
                } break;
            case TypeId::array:
                {
                    auto element_type = type->array.element_type;
                    auto element_count = type->array.element_count;
                    auto element_size = get_byte_size(element_type);

                    for (u64 i = 0; i < element_count; i += 1)
                    {
                        auto offset = i * element_size;
                        if (offset >= end)
                        {
                            break;
                        }

                        auto element_start = offset < start ? start - offset : 0;
                        if (!contains_no_user_data(element_type, element_start, end - offset))
                        {
                            return false;
                        }
                    }
                    trap();
                } break;
            default: return false;
        }
    }
}

fn Field* get_member_at_offset(Type* struct_type, u32 offset)
{
    assert(struct_type->id == TypeId::structure);

    Field* result = 0;

    if (struct_type->structure.byte_size > offset)
    {
        u32 offset_it = 0;
        auto fields = struct_type->structure.fields;

        for (u64 i = 0; i < fields.length; i += 1)
        {
            auto* field = &fields[i];

            if (offset_it > offset)
            {
                break;
            }

            result = field;
            offset_it = (u32)align_forward(offset_it + get_byte_size(field->type), get_byte_alignment(field->type));
        }

        assert(result);
    }

    return result;
}

fn Type* abi_system_v_get_integer_type_at_offset(Module* module, Type* type, u32 offset, Type* source_type, u32 source_offset)
{
    switch (type->id)
    {
        case TypeId::integer:
            {
                auto bit_count = type->integer.bit_count;
                switch (bit_count)
                {
                    case 64: return type;
                    case 32: case 16: case 8:
                        {
                            assert(offset == 0);
                            auto start = source_offset + get_byte_size(type);
                            auto end = source_offset + 8;

                            if (contains_no_user_data(source_type, start, end))
                            {
                                return type;
                            }
                        } break;
                    default:
                        {
                            auto original_byte_count = get_byte_size(type);
                            assert(original_byte_count != source_offset);
                            auto byte_count = MIN(original_byte_count - source_offset, 8);
                            auto bit_count = byte_count * 8;

                            auto result_type = integer_type(module, { .bit_count = (u32)bit_count, .is_signed = false });
                            return result_type;
                        } break;
                }
            } break;
        case TypeId::pointer:
            {
                if (offset == 0)
                {
                    return type;
                }
                else
                {
                    trap();
                }
            } break;
        case TypeId::structure:
            {
                auto* field = get_member_at_offset(type, offset);
                if (field)
                {
                    auto field_type = field->type;
                    switch (field_type->id)
                    {
                        case TypeId::integer:
                        case TypeId::enumerator:
                            {
                                field_type = align_integer_type(module, field_type);
                            } break;
                        default: break;
                    }

                    return abi_system_v_get_integer_type_at_offset(module, field_type, offset - field->offset, source_type, source_offset);
                }
                else
                {
                    unreachable();
                }
            } break;
        case TypeId::bits:
            {
                auto backing_type = type->bits.backing_type;
                return abi_system_v_get_integer_type_at_offset(module, backing_type, offset, source_type == type ? backing_type : source_type, source_offset);
            } break;
        default: unreachable();
    }

    auto source_size = get_byte_size(source_type);
    auto byte_count = source_size - source_offset;
    u32 bit_count = byte_count > 8 ? 64 : byte_count * 8;
    auto result = integer_type(module, { .bit_count = bit_count, .is_signed = false });
    return result;
}

struct AbiSystemVClassify
{
    u64 base_offset;
    bool is_variable_argument;
    bool is_register_call;
};

fn AbiSystemVClassifyResult abi_system_v_classify_type(Type* type, AbiSystemVClassify options)
{
    AbiSystemVClassifyResult result = {};
    auto is_memory = options.base_offset >= 8;
    auto current_index = is_memory;
    auto not_current_index = !is_memory;
    assert(current_index != not_current_index);
    result.r[current_index] = AbiSystemVClass::memory;

    switch (type->id)
    {
        case TypeId::void_type:
        case TypeId::noreturn:
            result.r[current_index] = AbiSystemVClass::none;
            break;
        case TypeId::bits:
            return abi_system_v_classify_type(type->bits.backing_type, options);
        case TypeId::enumerator:
            return abi_system_v_classify_type(type->enumerator.backing_type, options);
        case TypeId::pointer:
            result.r[current_index] = AbiSystemVClass::integer;
            break;
        case TypeId::integer:
            {
                if (type->integer.bit_count <= 64)
                {
                    result.r[current_index] = AbiSystemVClass::integer;
                }
                else if (type->integer.bit_count == 128)
                {
                    trap();
                }
                else
                {
                    report_error();
                }
            } break;
        case TypeId::array:
            {
                auto byte_size = get_byte_size(type);
                if (byte_size <= 64)
                {
                    if (options.base_offset % get_byte_alignment(type) == 0)
                    {
                        auto element_type = type->array.element_type;
                        auto element_size = get_byte_size(element_type);

                        result.r[current_index] = AbiSystemVClass::none;

                        u64 vector_size = 16;

                        if (byte_size > 16 && (byte_size != get_byte_size(element_type) || byte_size > vector_size))
                        {
                            unreachable();
                        }
                        else
                        {
                            auto offset = options.base_offset;
                            auto element_count = type->array.element_count;

                            for (u64 i = 0; i < element_count; i += 1)
                            {
                                auto element_classes = abi_system_v_classify_type(element_type, AbiSystemVClassify{
                                    .base_offset = offset,
                                    .is_variable_argument = options.is_variable_argument,
                                });
                                offset += element_size;

                                result.r[0] = abi_system_v_merge_class(result.r[0], element_classes.r[0]);
                                result.r[1] = abi_system_v_merge_class(result.r[1], element_classes.r[1]);

                                if (result.r[0] == AbiSystemVClass::memory || result.r[1] == AbiSystemVClass::memory)
                                {
                                    break;
                                }
                            }

                            auto final_result = abi_system_v_classify_post_merge(byte_size, result);
                            assert(final_result.r[1] != AbiSystemVClass::sse || final_result.r[0] != AbiSystemVClass::sse);
                            result = final_result;
                        }
                    }
                }
            } break;
        case TypeId::structure:
        case TypeId::union_type:
            {
                auto byte_size = type->structure.byte_size;

                if (byte_size <= 64)
                {
                    auto has_variable_array = false;
                    if (!has_variable_array)
                    {
                        result.r[current_index] = AbiSystemVClass::none;
                        auto is_union = type->id == TypeId::union_type;

                        switch (type->id)
                        {
                            case TypeId::structure:
                                {
                                    for (auto& field : type->structure.fields)
                                    {
                                        auto offset = options.base_offset + field.offset;
                                        auto member_type = field.type;
                                        auto member_size = get_byte_size(member_type);
                                        auto member_alignment = get_byte_alignment(member_type);

                                        u64 native_vector_size = 16;

                                        auto gt_16 = byte_size > 16 && ((!is_union && byte_size != member_size) || byte_size > native_vector_size);
                                        auto padding = offset % member_alignment != 0;

                                        if (gt_16 || padding)
                                        {
                                            result.r[0] = AbiSystemVClass::memory;
                                            result = abi_system_v_classify_post_merge(byte_size, result);
                                            return result;
                                        }

                                        auto member_classes = abi_system_v_classify_type(member_type, {
                                            .base_offset = offset,
                                            .is_variable_argument = options.is_variable_argument,
                                            .is_register_call = options.is_register_call,
                                        });

                                        for (u64 i = 0; i < array_length(member_classes.r); i += 1)
                                        {
                                            result.r[i] = abi_system_v_merge_class(result.r[i], member_classes.r[i]);
                                        }

                                        if (result.r[0] == AbiSystemVClass::memory || result.r[1] == AbiSystemVClass::memory)
                                        {
                                            break;
                                        }
                                    }

                                    result = abi_system_v_classify_post_merge(byte_size, result);
                                } break;
                            case TypeId::union_type:
                                {
                                    trap();
                                } break;
                            default: unreachable();
                        }
                    }
                }
            } break;
        case TypeId::alias:
                return abi_system_v_classify_type(type->alias.type, options);
        default: unreachable();
    }

    return result;
}

fn void resolve_type_in_place_memory(Module* module, Type* type);
fn void resolve_type_in_place_abi(Module* module, Type* type)
{
    if (!type->llvm.abi)
    {
        LLVMTypeRef result = 0;

        switch (type->id)
        {
            case TypeId::void_type:
            case TypeId::noreturn:
                result = module->llvm.void_type;
                break;
            case TypeId::integer:
                result = LLVMIntTypeInContext(module->llvm.context, type->integer.bit_count);
                break;
            case TypeId::pointer:
                result = module->llvm.pointer_type;
                break;
            case TypeId::array:
                {
                    auto* element_type = type->array.element_type;
                    auto element_count = type->array.element_count;
                    assert(element_count);
                    resolve_type_in_place_memory(module, element_type);
                    auto array_type = LLVMArrayType2(element_type->llvm.memory, element_count);
                    result = array_type;
                } break;
            case TypeId::enumerator:
                {
                    auto backing_type = type->enumerator.backing_type;
                    resolve_type_in_place_abi(module, backing_type);
                    result = backing_type->llvm.abi;
                } break;
            case TypeId::structure:
                {
                    LLVMTypeRef llvm_type_buffer[64];
                    auto fields = type->structure.fields;
                    for (u64 i = 0; i < fields.length; i += 1)
                    {
                        auto& field = fields[i];
                        resolve_type_in_place_memory(module, field.type);
                        llvm_type_buffer[i] = field.type->llvm.memory;
                    }

                    result = LLVMStructTypeInContext(module->llvm.context, llvm_type_buffer, fields.length, 0);
                } break;
            case TypeId::bits:
                {
                    auto backing_type = type->bits.backing_type;
                    resolve_type_in_place_abi(module, backing_type);
                    result = backing_type->llvm.abi;
                } break;
            case TypeId::union_type:
                {
                    auto biggest_type = type->union_type.fields[type->union_type.biggest_field].type;
                    resolve_type_in_place_memory(module, biggest_type);
                    result = LLVMStructTypeInContext(module->llvm.context, &biggest_type->llvm.memory, 1, 0);
                } break;
            case TypeId::alias:
                {
                    auto aliased = type->alias.type;
                    resolve_type_in_place_abi(module, aliased);
                    result = aliased->llvm.abi;
                } break;
            default: unreachable();
        }

        assert(result);
        type->llvm.abi = result;
    }
}

fn void resolve_type_in_place_memory(Module* module, Type* type)
{
    if (!type->llvm.memory)
    {
        resolve_type_in_place_abi(module, type);
        
        LLVMTypeRef result = 0;

        switch (type->id)
        {
            case TypeId::void_type:
            case TypeId::noreturn:
            case TypeId::pointer:
            case TypeId::array:
            case TypeId::structure:
                result = type->llvm.abi;
                break;
            case TypeId::integer:
                {
                    auto byte_size = get_byte_size(type);
                    auto bit_count = byte_size * 8;
                    result = LLVMIntTypeInContext(module->llvm.context, bit_count);
                } break;
            case TypeId::enumerator:
                {
                    auto backing_type = type->enumerator.backing_type;
                    resolve_type_in_place_memory(module, backing_type);
                    result = backing_type->llvm.memory;
                } break;
            case TypeId::bits:
                {
                    auto backing_type = type->bits.backing_type;
                    resolve_type_in_place_memory(module, backing_type);
                    result = backing_type->llvm.memory;
                } break;
            case TypeId::union_type:
                {
                    auto biggest_type = type->union_type.fields[type->union_type.biggest_field].type;
                    resolve_type_in_place_memory(module, biggest_type);
                    result = LLVMStructTypeInContext(module->llvm.context, &biggest_type->llvm.memory, 1, 0);
                } break;
            case TypeId::alias:
                {
                    auto aliased = type->alias.type;
                    resolve_type_in_place_memory(module, aliased);
                    result = aliased->llvm.memory;
                } break;
            default: unreachable();
        }

        assert(result);
        type->llvm.memory = result;

        if (type->id == TypeId::bits)
        {
            assert(type->llvm.memory == type->llvm.abi);
        }
    }
}

fn void resolve_type_in_place_debug(Module* module, Type* type)
{
    if (module->has_debug_info)
    {
        if (!type->llvm.debug)
        {
            LLVMMetadataRef result = 0;

            switch (type->id)
            {
                case TypeId::void_type:
                case TypeId::noreturn:
                    {
                        result = LLVMDIBuilderCreateBasicType(module->llvm.di_builder, (char*)type->name.pointer, type->name.length, 0, (u32)DwarfType::void_type, type->id == TypeId::noreturn ? LLVMDIFlagNoReturn : LLVMDIFlagZero);
                    } break;
                case TypeId::integer:
                    {
                        DwarfType dwarf_type = type->integer.bit_count == 1 ? DwarfType::boolean : (type->integer.is_signed ? DwarfType::signed_type : DwarfType::unsigned_type);
                        LLVMDIFlags flags = {};
                        result = LLVMDIBuilderCreateBasicType(module->llvm.di_builder, (char*)type->name.pointer, type->name.length, type->integer.bit_count, (u32)dwarf_type, flags);
                    } break;
                case TypeId::pointer:
                    {
                        resolve_type_in_place_debug(module, type->pointer.element_type);
                        if (type->llvm.debug)
                        {
                            trap();
                        }
                        else
                        {
                            result = LLVMDIBuilderCreatePointerType(module->llvm.di_builder, type->pointer.element_type->llvm.debug, 64, 64, 0, (char*)type->name.pointer, type->name.length);
                        }
                    } break;
                case TypeId::array:
                    {
                        auto array_element_type = type->array.element_type;
                        auto array_element_count = type->array.element_count;
                        assert(array_element_count);
                        resolve_type_in_place_debug(module, array_element_type);
                        auto bit_alignment = get_byte_alignment(type) * 8;
                        auto array_type = LLVMDIBuilderCreateArrayType(module->llvm.di_builder, array_element_count, bit_alignment, array_element_type->llvm.debug, 0, 0);
                        result = array_type;
                    } break;
                case TypeId::enumerator:
                    {
                        auto backing_type = type->enumerator.backing_type;
                        resolve_type_in_place_debug(module, backing_type);

                        LLVMMetadataRef field_buffer[64];
                        for (u64 i = 0; i < type->enumerator.fields.length; i += 1)
                        {
                            auto& field = type->enumerator.fields[i];
                            auto enum_field = LLVMDIBuilderCreateEnumerator(module->llvm.di_builder, (char*)field.name.pointer, field.name.length, field.value, type_is_signed(backing_type));
                            field_buffer[i] = enum_field;
                        }

                        result = LLVMDIBuilderCreateEnumerationType(module->llvm.di_builder, module->scope.llvm, (char*)type->name.pointer, type->name.length, module->llvm.file, type->enumerator.line, get_bit_size(type), get_byte_alignment(type) * 8, field_buffer, type->enumerator.fields.length, backing_type->llvm.debug);
                    } break;
                case TypeId::structure:
                    {
                        LLVMDIFlags flags = {};
                        auto forward_declaration = LLVMDIBuilderCreateReplaceableCompositeType(module->llvm.di_builder, module->llvm.debug_tag, (char*)type->name.pointer, type->name.length, module->scope.llvm, module->llvm.file, type->structure.line, 0, type->structure.byte_size * 8, type->structure.byte_alignment * 8, flags, (char*)type->name.pointer, type->name.length);
                        type->llvm.debug = forward_declaration;
                        module->llvm.debug_tag += 1;

                        LLVMMetadataRef llvm_type_buffer[64];

                        auto fields = type->structure.fields;
                        for (u64 i = 0; i < fields.length; i += 1)
                        {
                            auto& field = fields[i];
                            auto field_type = field.type;
                            resolve_type_in_place_debug(module, field_type);
                            auto member_type = LLVMDIBuilderCreateMemberType(module->llvm.di_builder, module->scope.llvm, (char*)field.name.pointer, field.name.length, module->llvm.file, field.line, get_byte_size(field_type) * 8, get_byte_alignment(field_type) * 8, field.offset * 8, flags, field_type->llvm.debug);
                            llvm_type_buffer[i] = member_type;
                        }

                        auto struct_type = LLVMDIBuilderCreateStructType(module->llvm.di_builder, module->scope.llvm, (char*)type->name.pointer, type->name.length, module->llvm.file, type->structure.line, type->structure.byte_size * 8, type->structure.byte_alignment * 8, flags, 0, llvm_type_buffer, fields.length, 0, 0, (char*)type->name.pointer, type->name.length);
                        LLVMMetadataReplaceAllUsesWith(forward_declaration, struct_type);
                        result = struct_type;
                    } break;
                case TypeId::bits:
                    {
                        LLVMMetadataRef llvm_type_buffer[64];

                        auto fields = type->bits.fields;
                        auto backing_type = type->bits.backing_type->llvm.debug;
                        LLVMDIFlags flags = {};
                        for (u64 i = 0; i < fields.length; i += 1)
                        {
                            auto& field = fields[i];
                            auto field_type = field.type;
                            resolve_type_in_place_debug(module, field_type);
                            u64 bit_offset = 0;
                            auto member_type = LLVMDIBuilderCreateBitFieldMemberType(module->llvm.di_builder, module->scope.llvm, (char*)field.name.pointer, field.name.length, module->llvm.file, field.line, get_bit_size(field_type), bit_offset, field.offset, flags, backing_type);
                            llvm_type_buffer[i] = member_type;
                        }

                        auto size = get_byte_size(type) * 8;
                        auto alignment = get_byte_alignment(type) * 8;
                        auto struct_type = LLVMDIBuilderCreateStructType(module->llvm.di_builder, module->scope.llvm, (char*)type->name.pointer, type->name.length, module->llvm.file, type->bits.line, size, alignment, flags, 0, llvm_type_buffer, fields.length, 0, 0, (char*)type->name.pointer, type->name.length);
                        result = struct_type;
                    } break;
                case TypeId::union_type:
                    {
                        LLVMDIFlags flags = {};
                        auto forward_declaration = LLVMDIBuilderCreateReplaceableCompositeType(module->llvm.di_builder, module->llvm.debug_tag, (char*)type->name.pointer, type->name.length, module->scope.llvm, module->llvm.file, type->union_type.line, 0, type->union_type.byte_size * 8, type->union_type.byte_alignment * 8, flags, (char*)type->name.pointer, type->name.length);
                        module->llvm.debug_tag += 1;

                        LLVMMetadataRef llvm_type_buffer[64];

                        auto fields = type->union_type.fields;
                        for (u64 i = 0; i < fields.length; i += 1)
                        {
                            auto& field = fields[i];
                            auto field_type = field.type;
                            resolve_type_in_place_debug(module, field_type);
                            auto member_type = LLVMDIBuilderCreateMemberType(module->llvm.di_builder, module->scope.llvm, (char*)field.name.pointer, field.name.length, module->llvm.file, field.line, get_byte_size(field_type) * 8, get_byte_alignment(field_type) * 8, 0, flags, field_type->llvm.debug);
                            llvm_type_buffer[i] = member_type;
                        }

                        auto union_type = LLVMDIBuilderCreateUnionType(module->llvm.di_builder, module->scope.llvm, (char*)type->name.pointer, type->name.length, module->llvm.file, type->union_type.line, type->union_type.byte_size * 8, type->union_type.byte_alignment * 8, flags, llvm_type_buffer, fields.length, 0, (char*)type->name.pointer, type->name.length);
                        LLVMMetadataReplaceAllUsesWith(forward_declaration, union_type);
                        result = union_type;
                    } break;
                case TypeId::alias:
                    {
                        auto aliased = type->alias.type;
                        resolve_type_in_place_debug(module, aliased);
                        auto alignment = get_byte_alignment(aliased);
                        result = LLVMDIBuilderCreateTypedef(module->llvm.di_builder, aliased->llvm.debug, (char*) type->name.pointer, type->name.length, module->llvm.file, type->alias.line, type->alias.scope->llvm, alignment * 8);
                    } break;
                default: unreachable();
            }

            assert(result);
            type->llvm.debug = result;
        }
    }
}

fn void resolve_type_in_place(Module* module, Type* type)
{
    resolve_type_in_place_abi(module, type);
    resolve_type_in_place_memory(module, type);
    resolve_type_in_place_debug(module, type);
}

fn Type* resolve_type(Module* module, Type* type)
{
    Type* result = 0;

    switch (type->id)
    {
        case TypeId::unresolved:
            {
                assert(!module->current_macro_declaration);
                auto instantiation = module->current_macro_instantiation;
                if (!instantiation)
                {
                    report_error();
                }

                auto declaration = instantiation->declaration;
                auto declaration_arguments = declaration->constant_arguments;
                auto instantiation_arguments = instantiation->constant_arguments;
                assert(declaration_arguments.length == instantiation_arguments.length);

                for (u64 i = 0; i < declaration_arguments.length; i += 1)
                {
                    auto& declaration_argument = declaration_arguments[i];
                    auto& instantiation_argument = instantiation_arguments[i];
                    if (declaration_argument.id == ConstantArgumentId::type && type == declaration_argument.type)
                    {
                        assert(declaration_argument.name.equal(instantiation_argument.name));
                        result = instantiation_argument.type;
                        break;
                    }
                }

                if (!result)
                {
                    report_error();
                }
            } break;
        case TypeId::void_type:
        case TypeId::integer:
            {
                result = type;
            } break;
        case TypeId::pointer:
            {
                auto element_type = resolve_type(module, type->pointer.element_type);
                result = get_pointer_type(module, element_type);
            } break;
        case TypeId::structure:
            {
                if (type->structure.is_slice)
                {
                    auto pointer_type = type->structure.fields[0].type;
                    assert(pointer_type->id == TypeId::pointer);
                    auto element_type = resolve_type(module, pointer_type->pointer.element_type);
                    auto slice_type = get_slice_type(module, element_type);
                    result = slice_type;
                }
                else
                {
                    result = type;
                }
            } break;
        default: trap();
    }

    assert(result);
    assert(result->id != TypeId::unresolved);
    return result;
}

fn bool type_is_abi_equal(Module* module, Type* a, Type* b)
{
    resolve_type_in_place(module, a);
    resolve_type_in_place(module, b);

    bool result = a == b;
    if (!result)
    {
        result = a->llvm.abi == b->llvm.abi;
    }
    return result;
}

fn AbiInformation abi_system_v_get_ignore(Module* module, Type* semantic_type)
{
    resolve_type_in_place(module, semantic_type);

    return {
        .semantic_type = semantic_type,
        .flags = {
            .kind = AbiKind::ignore,
        },
    };
}

struct DirectOptions
{
    Type* semantic_type;
    Type* type;
    Type* padding;
    u32 offset;
    u32 alignment;
    bool can_be_flattened = true;
};

fn AbiInformation abi_system_v_get_direct(Module* module, DirectOptions direct)
{
    AbiInformation result = {
        .semantic_type = direct.semantic_type,
        .flags = {
            .kind = AbiKind::direct,
        },
    };
    resolve_type_in_place(module, direct.semantic_type);
    resolve_type_in_place(module, direct.type);
    if (unlikely(direct.padding))
    {
        resolve_type_in_place(module, direct.padding);
    }

    result.set_coerce_to_type(direct.type);
    result.set_padding_type(direct.padding);
    result.set_direct_offset(direct.offset);
    result.set_direct_alignment(direct.alignment);
    result.set_can_be_flattened(direct.can_be_flattened);

    return result;
}

struct ExtendOptions
{
    Type* semantic_type;
    Type* type;
    bool sign;
};

fn AbiInformation abi_system_v_get_extend(ExtendOptions options)
{
    assert(is_integral_or_enumeration_type(options.semantic_type));
    AbiInformation result = {
        .semantic_type = options.semantic_type,
        .flags = {
            .kind = AbiKind::extend,
        },
    };

    result.set_coerce_to_type(options.type ? options.type : options.semantic_type);
    result.set_padding_type(0);
    result.set_direct_offset(0);
    result.set_direct_alignment(0);
    result.flags.sign_extension = options.sign;

    return result;
}

fn Type* get_anonymous_struct_pair(Module* module, Type* low, Type* high)
{
    Type* pair;
    for (pair = module->first_pair_struct_type; pair; pair = pair->structure.next)
    {
        assert(pair->id == TypeId::structure);
        assert(pair->structure.fields.length == 2);

        if (pair->structure.fields[0].type == low &&
                pair->structure.fields[1].type == high)
        {
            return pair;
        }

        if (!pair->structure.next)
        {
            break;
        }
    }

    auto high_alignment = get_byte_alignment(high);
    auto alignment = MAX(get_byte_alignment(low), high_alignment);
    u64 high_offset = align_forward(get_byte_size(low), high_alignment);

    auto fields = arena_allocate<Field>(module->arena, 2);
    fields[0] = {
        .name = string_literal("low"),
        .type = low,
        .offset = 0,
        .line = 0,
    };
    fields[1] = {
        .name = string_literal("high"),
        .type = high,
        .offset = high_offset,
        .line = 0,
    };
    
    auto struct_type = type_allocate_init(module, {
        .structure = {
            .fields = fields,
            .byte_size = high_offset + get_byte_size(high),
            .byte_alignment = alignment,
        },
        .id = TypeId::structure,
        .name = string_literal(""),
    });

    if (pair)
    {
        assert(module->first_pair_struct_type);
        pair->structure.next = struct_type;
    }
    else
    {
        assert(!module->first_pair_struct_type);
        module->first_pair_struct_type = struct_type;
    }

    return struct_type;
}

fn Type* get_by_value_argument_pair(Module* module, Type* low, Type* high)
{
    auto low_size = get_byte_allocation_size(low);
    auto high_alignment = get_byte_alignment(high);
    auto high_start = align_forward(low_size, high_alignment);
    assert(high_start != 0 && high_start <= 8);
    if (high_start != 8)
    {
        trap();
    }

    auto result = get_anonymous_struct_pair(module, low, high);
    return result;
}


struct IndirectOptions
{
    Type* semantic_type;
    Type* padding_type = 0;
    u32 alignment;
    bool by_value = true;
    bool realign = false;
};

fn AbiInformation abi_system_v_get_indirect(IndirectOptions indirect)
{
    auto result = AbiInformation{
        .semantic_type = indirect.semantic_type,
        .attributes = {
            .indirect = {
                .alignment = 0,
                .address_space = 0,
            },
        },
        .flags = {
            .kind = AbiKind::indirect,
        },
    };

    result.set_indirect_align(indirect.alignment);
    result.set_indirect_by_value(indirect.by_value);
    result.set_indirect_realign(indirect.realign);
    result.set_sret_after_this(false);
    result.set_padding_type(indirect.padding_type);

    return result;
}

struct NaturalAlignIndirect
{
    Type* semantic_type;
    Type* padding_type = 0;
    bool by_value = true;
    bool realign = false;
};

fn AbiInformation abi_system_v_get_natural_align_indirect(NaturalAlignIndirect natural)
{
    auto alignment = get_byte_alignment(natural.semantic_type);
    return abi_system_v_get_indirect({
        .semantic_type = natural.semantic_type,
        .padding_type = natural.padding_type,
        .alignment = alignment,
        .by_value = natural.by_value,
        .realign = natural.realign,
    });
}

fn bool is_illegal_vector_type(Type* type)
{
    switch (type->id)
    {
        case TypeId::vector: trap();
        default:
            return false;
    }
}

fn AbiInformation abi_system_v_get_indirect_result(Module* module, Type* type, u32 free_gpr)
{
    if (!type_is_aggregate_type_for_abi(type) && !is_illegal_vector_type(type) && !is_arbitrary_bit_integer(type))
    {
        if (is_promotable_integer_type_for_abi(type))
        {
            trap();
        }
        else
        {
            return abi_system_v_get_direct(module, {
                .semantic_type = type,
                .type = type,
            });
        }
    }
    else
    {
        auto alignment = MAX(get_byte_alignment(type), 8);
        auto size = get_byte_size(type);

        if (free_gpr == 0 && alignment == 8 && size <= 8)
        {
            trap();
        }
        else
        {
            return abi_system_v_get_indirect({
                .semantic_type = type,
                .alignment = alignment,
            });
        }
    }
}


struct AbiSystemVClassifyArgumentTypeOptions
{
    u32 available_gpr;
    bool is_named_argument;
    bool is_reg_call;
};

struct AbiSystemVClassifyArgumentTypeResult
{
    AbiInformation abi;
    AbiRegisterCountSystemV needed_registers;
};

fn AbiSystemVClassifyArgumentTypeResult abi_system_v_classify_argument_type(Module* module, Type* semantic_argument_type, AbiSystemVClassifyArgumentTypeOptions options)
{
    auto classify_result = abi_system_v_classify_type(semantic_argument_type, AbiSystemVClassify{
        .base_offset = 0,
        .is_variable_argument = !options.is_named_argument,
        .is_register_call = options.is_reg_call,
    });

    auto low_class = classify_result.r[0];
    auto high_class = classify_result.r[1];

    AbiRegisterCountSystemV needed_registers = {};

    Type* low_type = 0;

    switch (low_class)
    {
        case AbiSystemVClass::none: unreachable();
        case AbiSystemVClass::integer:
            {
                needed_registers.gpr += 1;
                low_type = abi_system_v_get_integer_type_at_offset(module, semantic_argument_type, 0, semantic_argument_type, 0);

                if (high_class == AbiSystemVClass::none && low_type->id == TypeId::integer)
                {
                    // TODO: if enumerator

                    if (is_integral_or_enumeration_type(semantic_argument_type) && is_promotable_integer_type_for_abi(semantic_argument_type))
                    {
                        return { abi_system_v_get_extend({
                            .semantic_type = semantic_argument_type,
                            .sign = type_is_signed(semantic_argument_type),
                        }), needed_registers };
                    }
                }
            } break;
        case AbiSystemVClass::memory:
            {
                return { abi_system_v_get_indirect_result(module, semantic_argument_type, options.available_gpr), needed_registers };
            } break;
        default: unreachable();
    }

    Type* high_type = 0;

    switch (high_class)
    {
        case AbiSystemVClass::none:
            break;
        case AbiSystemVClass::integer:
            {
                needed_registers.gpr += 1;
                high_type = abi_system_v_get_integer_type_at_offset(module, semantic_argument_type, 8, semantic_argument_type, 8);

                if (low_class == AbiSystemVClass::none)
                {
                    trap();
                }
            } break;
        default: unreachable();
    }

    Type* result_type = low_type;
    if (high_type)
    {
        result_type = get_by_value_argument_pair(module, low_type, high_type);
    }

    return {
        abi_system_v_get_direct(module, DirectOptions{
            .semantic_type = semantic_argument_type,
            .type = result_type,
        }),
        needed_registers,
    };
}

struct AbiSystemVClassifyArgumentOptions
{
    Type* type;
    u16 abi_start;
    bool is_reg_call = false;
    bool is_named_argument;
};

fn AbiInformation abi_system_v_classify_argument(Module* module, AbiRegisterCountSystemV* available_registers, Slice<LLVMTypeRef> llvm_abi_argument_type_buffer, Slice<Type*> abi_argument_type_buffer, AbiSystemVClassifyArgumentOptions options)
{
    auto semantic_argument_type = options.type;
    if (options.is_reg_call)
    {
        trap();
    }

    auto result = abi_system_v_classify_argument_type(module, semantic_argument_type, {
        .available_gpr = available_registers->gpr,
        .is_named_argument = options.is_named_argument,
        .is_reg_call = options.is_reg_call,
    });
    auto abi = result.abi;
    auto needed_registers = result.needed_registers;

    AbiInformation argument_abi;
    if (available_registers->gpr >= needed_registers.gpr && available_registers->sse >= needed_registers.sse)
    {
        available_registers->gpr -= needed_registers.gpr;
        available_registers->sse -= needed_registers.sse;
        argument_abi = abi;
    }
    else
    {
        argument_abi = abi_system_v_get_indirect_result(module, semantic_argument_type, available_registers->gpr);
    }

    if (argument_abi.get_padding_type())
    {
        trap();
    }

    argument_abi.abi_start = options.abi_start;

    u16 count = 0;

    switch (argument_abi.flags.kind)
    {
        case AbiKind::direct:
        case AbiKind::extend:
            {
                auto coerce_to_type = argument_abi.get_coerce_to_type();
                resolve_type_in_place(module, coerce_to_type);

                auto is_flattened_struct = argument_abi.flags.kind == AbiKind::direct && argument_abi.get_can_be_flattened() && coerce_to_type->id == TypeId::structure;

                count = is_flattened_struct ? coerce_to_type->structure.fields.length : 1;

                if (is_flattened_struct)
                {
                    for (u64 i = 0; i < coerce_to_type->structure.fields.length; i += 1)
                    {
                        auto& field = coerce_to_type->structure.fields[i];
                        auto field_type = field.type;
                        llvm_abi_argument_type_buffer[argument_abi.abi_start + i] = field_type->llvm.abi;
                        abi_argument_type_buffer[argument_abi.abi_start + i] = field_type;
                    }
                }
                else
                {
                    llvm_abi_argument_type_buffer[argument_abi.abi_start] = coerce_to_type->llvm.abi;
                    abi_argument_type_buffer[argument_abi.abi_start] = coerce_to_type;
                }
            } break;
        case AbiKind::indirect:
            {
                auto indirect_type = get_pointer_type(module, argument_abi.semantic_type);
                auto abi_index = argument_abi.abi_start;
                abi_argument_type_buffer[abi_index] = indirect_type;
                resolve_type_in_place(module, indirect_type);
                llvm_abi_argument_type_buffer[abi_index] = indirect_type->llvm.abi;
                count = 1;
            } break;
        default: unreachable();
    }

    assert(count);
    argument_abi.abi_count = count;

    return argument_abi;
}

fn AbiInformation abi_system_v_get_indirect_return_result(Type* type)
{
    if (type_is_aggregate_type_for_abi(type))
    {
        return abi_system_v_get_natural_align_indirect({
            .semantic_type = type,
        });
    }
    else
    {
        trap();
    }
}

fn AbiInformation abi_system_classify_return_type(Module* module, Type* semantic_return_type)
{
    auto type_classes = abi_system_v_classify_type(semantic_return_type, {});
    auto low_class = type_classes.r[0];
    auto high_class = type_classes.r[1];
    assert(high_class != AbiSystemVClass::memory || low_class == AbiSystemVClass::memory);
    assert(high_class != AbiSystemVClass::sse_up || low_class == AbiSystemVClass::sse);

    Type* low_type = 0;

    switch (low_class)
    {
        case AbiSystemVClass::none:
            {
                if (high_class == AbiSystemVClass::none)
                {
                    return abi_system_v_get_ignore(module, semantic_return_type);
                }

                trap();
            } break;
        case AbiSystemVClass::integer:
            {
                low_type = abi_system_v_get_integer_type_at_offset(module, semantic_return_type, 0, semantic_return_type, 0);

                if (high_class == AbiSystemVClass::none && low_type->id == TypeId::integer)
                {
                    if (semantic_return_type->id == TypeId::enumerator)
                    {
                        trap();
                    }

                    if (is_integral_or_enumeration_type(semantic_return_type) && is_promotable_integer_type_for_abi(semantic_return_type))
                    {
                        return abi_system_v_get_extend({
                            .semantic_type = semantic_return_type,
                            .sign = type_is_signed(semantic_return_type),
                        });
                    }
                }
            } break;
        case AbiSystemVClass::memory:
            {
                return abi_system_v_get_indirect_return_result(semantic_return_type);
            } break;
        default: unreachable();
    }

    Type* high_type = 0;

    switch (high_class)
    {
        case AbiSystemVClass::none:
            break;
        case AbiSystemVClass::integer:
            {
                u64 high_offset = 8;
                high_type = abi_system_v_get_integer_type_at_offset(module, semantic_return_type, high_offset, semantic_return_type, high_offset);
                if (low_class == AbiSystemVClass::none)
                {
                    trap();
                }
            } break;
                                        
        default: unreachable();
    }

    if (high_type)
    {
        low_type = get_by_value_argument_pair(module, low_type, high_type);
    }

    auto result = abi_system_v_get_direct(module, {
        .semantic_type = semantic_return_type,
        .type = low_type,
    });
    return result;
}

struct AttributeBuildOptions
{
    AbiInformation return_abi;
    Slice<AbiInformation> argument_abis;
    Slice<Type*> abi_argument_types;
    Type* abi_return_type;
    FunctionAttributes attributes;
    bool call_site;
};

struct AllocaOptions
{
    Type* type;
    String name = string_literal("");
    u32 alignment;
};

fn LLVMValueRef create_alloca(Module* module, AllocaOptions options)
{
    auto abi_type = options.type;
    resolve_type_in_place(module, abi_type);

    u32 alignment;
    if (options.alignment)
    {
        alignment = options.alignment;
    }
    else
    {
        alignment = get_byte_alignment(abi_type);
    }

    auto alloca = llvm_builder_create_alloca(module->llvm.builder, abi_type->llvm.memory, 0, alignment, options.name);
    return alloca;
}

struct StoreOptions
{
    LLVMValueRef source;
    LLVMValueRef destination;
    Type* type;
    u32 alignment;
};

fn void create_store(Module* module, StoreOptions options)
{
    assert(options.source);
    assert(options.destination);
    assert(options.type);

    auto resolved_type = resolve_alias(module, options.type);
    resolve_type_in_place(module, resolved_type);

    LLVMValueRef source_value;

    LLVMTypeRef memory_type = resolved_type->llvm.memory;
    if (resolved_type->llvm.abi == memory_type)
    {
        source_value = options.source;
    }
    else
    {
        source_value = LLVMBuildIntCast2(module->llvm.builder, options.source, memory_type, type_is_signed(resolved_type), "");
    }

    u32 alignment;
    if (options.alignment)
    {
        alignment = options.alignment;
    }
    else
    {
        alignment = get_byte_alignment(resolved_type);
    }

    auto store = LLVMBuildStore(module->llvm.builder, source_value, options.destination);
    LLVMSetAlignment(store, alignment);
}

struct LoadOptions
{
    Type* type;
    LLVMValueRef pointer;
    u32 alignment;
    TypeKind kind;
};

fn LLVMValueRef create_load(Module* module, LoadOptions options)
{
    resolve_type_in_place(module, options.type);

    u32 alignment;
    if (options.alignment)
    {
        alignment = options.alignment;
    }
    else
    {
        alignment = get_byte_alignment(options.type);
    }

    auto result = LLVMBuildLoad2(module->llvm.builder, options.type->llvm.memory, options.pointer, "");
    LLVMSetAlignment(result, alignment);

    switch (options.kind)
    {
    case TypeKind::abi:
        {
            if (options.type->llvm.memory == options.type->llvm.abi)
            {
                break;
            }
            else
            {
                result = LLVMBuildIntCast2(module->llvm.builder, result, options.type->llvm.abi, type_is_signed(options.type), "");
            }
        } break;
    case TypeKind::memory: break;
    }

    return result;
}

struct GEPOptions
{
    LLVMTypeRef type;
    LLVMValueRef pointer;
    Slice<LLVMValueRef> indices;
    bool inbounds = true;
};

fn LLVMValueRef create_gep(Module* module, GEPOptions options)
{
    assert(options.indices.length);
    auto* gep_function = options.inbounds ? &LLVMBuildInBoundsGEP2 : &LLVMBuildGEP2;
    auto gep = gep_function(module->llvm.builder, options.type, options.pointer, options.indices.pointer, (u32)options.indices.length, "");
    return gep;
}

fn BBLLVMAttributeList build_attribute_list(Module* module, AttributeBuildOptions options)
{
    resolve_type_in_place(module, options.return_abi.semantic_type);
    BBLLVMAttributeListOptions attributes = {};

    attributes.return_ = {
        .semantic_type = options.return_abi.semantic_type->llvm.memory,
        .abi_type = options.abi_return_type->llvm.abi,
        .dereferenceable_bytes = 0,
        .alignment = 0,
        .no_alias = false,
        .non_null = false,
        .no_undef = false,
        .sign_extend = options.return_abi.flags.kind == AbiKind::extend and options.return_abi.flags.sign_extension,
        .zero_extend = options.return_abi.flags.kind == AbiKind::extend and !options.return_abi.flags.sign_extension,
        .in_reg = false,
        .no_fp_class = 0, // TODO: this is a struct
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
    };

    BBLLVMArgumentAttributes argument_attribute_buffer[128];
    Slice<BBLLVMArgumentAttributes> argument_attributes = { .pointer = argument_attribute_buffer, .length = options.abi_argument_types.length };
    attributes.argument_pointer = argument_attributes.pointer;
    attributes.argument_count = argument_attributes.length;

    u64 total_abi_count = 0;
    if (options.return_abi.flags.kind == AbiKind::indirect)
    {
        auto abi_index = options.return_abi.flags.sret_after_this;
        auto argument_attribute = &argument_attributes[abi_index];
        *argument_attribute = {
            .semantic_type = options.return_abi.semantic_type->llvm.memory,
            .abi_type = options.abi_argument_types[abi_index]->llvm.abi,
            .dereferenceable_bytes = 0,
            .alignment = get_byte_alignment(options.return_abi.semantic_type),
            .no_alias = true,
            .non_null = false,
            .no_undef = false,
            .sign_extend = false,
            .zero_extend = false,
            .in_reg = options.return_abi.flags.in_reg,
            .no_fp_class = {},
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
        };
        total_abi_count += 1;
    }

    for (const auto& abi: options.argument_abis)
    {
        for (auto abi_index = abi.abi_start; abi_index < abi.abi_start + abi.abi_count; abi_index += 1)
        {
            auto& attributes = argument_attributes[abi_index];
            resolve_type_in_place(module, abi.semantic_type);

            auto abi_type = options.abi_argument_types[abi_index];
            resolve_type_in_place(module, abi_type);

            attributes = {
                .semantic_type = abi.semantic_type->llvm.memory,
                .abi_type = abi_type->llvm.abi,
                .dereferenceable_bytes = 0,
                .alignment = (u32)(abi.flags.kind == AbiKind::indirect ? 8 : 0),
                .no_alias = false,
                .non_null = false,
                .no_undef = false,
                .sign_extend = abi.flags.kind == AbiKind::extend and abi.flags.sign_extension,
                .zero_extend = abi.flags.kind == AbiKind::extend and !abi.flags.sign_extension,
                .in_reg = abi.flags.in_reg,
                .no_fp_class = {},
                .struct_return = false,
                .writable = false,
                .dead_on_unwind = false,
                .in_alloca = false,
                .dereferenceable = false,
                .dereferenceable_or_null = false,
                .nest = false,
                .by_value = abi.flags.indirect_by_value,
                .by_reference = false,
                .no_capture = false,
            };
            total_abi_count += 1;
        }
    }
    assert(total_abi_count == options.abi_argument_types.length);

    attributes.function = {
        .prefer_vector_width = {},
        .stack_protector_buffer_size = {},
        .definition_probe_stack = {},
        .definition_stack_probe_size = {},
        .flags0 = {
            .noreturn = options.return_abi.semantic_type == noreturn_type(module),
            .cmse_ns_call = false,
            .nounwind = true,
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
            .no_inline = options.attributes.inline_behavior == InlineBehavior::no_inline,
            .always_inline = options.attributes.inline_behavior == InlineBehavior::always_inline,
            .guard_no_cf = false,
            // TODO: branch protection function attributes
            // TODO: cpu features

            // CALL-SITE ATTRIBUTES
            .call_no_builtins = false,

            // DEFINITION-SITE ATTRIBUTES
            .definition_frame_pointer_kind = module->has_debug_info ? BBLLVMFramePointerKind::all : BBLLVMFramePointerKind::none,
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
            .definition_zero_call_used_registers = ZeroCallUsedRegsKind::all,
            // TODO: denormal builtins
            .definition_non_lazy_bind = false,
            .definition_cmse_nonsecure_entry = false,
            .definition_unwind_table_kind = BBLLVMUWTableKind::None,
        },
        .flags1 = {
            .definition_disable_tail_calls = false,
            .definition_stack_protect_strong = false,
            .definition_stack_protect = false,
            .definition_stack_protect_req = false,
            .definition_aarch64_new_za = false,
            .definition_aarch64_new_zt0 = false,
            .definition_optimize_none = false,
            .definition_naked = !options.call_site and options.attributes.naked,
            .definition_inline_hint = !options.call_site and options.attributes.inline_behavior == InlineBehavior::inline_hint,
        },
    };

    auto attribute_list = llvm_attribute_list_build(module->llvm.context, &attributes, options.call_site);
    return attribute_list;
}

fn void check_types(Module* module, Type* expected, Type* source)
{
    assert(expected);
    assert(source);

    if (expected != source)
    {
        auto resolved_expected = resolve_alias(module, expected);
        auto resolved_source = resolve_alias(module, source);

        if (resolved_expected != resolved_source)
        {
            auto is_dst_p_and_source_int = resolved_expected->id == TypeId::pointer && resolved_source->id == TypeId::integer;
            if (!is_dst_p_and_source_int)
            {
                report_error();
            }
        }
    }
}

fn void typecheck(Module* module, Type* expected, Type* source)
{
    if (expected)
    {
        check_types(module, expected, source);
    }
}

fn bool unary_is_boolean(UnaryId id)
{
    switch (id)
    {
        case UnaryId::exclamation:
            return true;
        case UnaryId::minus:
        case UnaryId::plus:
        case UnaryId::ampersand:
        case UnaryId::tilde:
        case UnaryId::enum_name:
        case UnaryId::extend:
        case UnaryId::truncate:
        case UnaryId::pointer_cast:
        case UnaryId::int_from_enum:
        case UnaryId::int_from_pointer:
        case UnaryId::va_end:
        case UnaryId::bitwise_not:
        case UnaryId::dereference:
        case UnaryId::pointer_from_int:
            return false;
    }
}

fn bool binary_is_boolean(BinaryId id)
{
    switch (id)
    {
        case BinaryId::add:
        case BinaryId::sub:
        case BinaryId::mul:
        case BinaryId::div:
        case BinaryId::rem:
        case BinaryId::bitwise_and:
        case BinaryId::bitwise_or:
        case BinaryId::bitwise_xor:
        case BinaryId::shift_left:
        case BinaryId::shift_right:
            return false;
        case BinaryId::compare_equal:
        case BinaryId::compare_not_equal:
        case BinaryId::compare_greater:
        case BinaryId::compare_less:
        case BinaryId::compare_greater_equal:
        case BinaryId::compare_less_equal:
        case BinaryId::logical_and:
        case BinaryId::logical_or:
        case BinaryId::logical_and_shortcircuit:
        case BinaryId::logical_or_shortcircuit:
            return true;
    }
}

fn bool binary_is_shortcircuiting(BinaryId id)
{
    switch (id)
    {
        case BinaryId::logical_and_shortcircuit:
        case BinaryId::logical_or_shortcircuit:
            return true;
        default:
            return false;
    }
}

fn void analyze_type(Module* module, Value* value, Type* expected_type);

fn void analyze_binary_type(Module* module, Value* left, Value* right, bool is_boolean, Type* expected_type)
{
    auto left_constant = left->is_constant();
    auto right_constant = right->is_constant();

    if (!expected_type)
    {
        if (left_constant && right_constant)
        {
            if (!left->type && !right->type)
            {
                auto are_string_literal = left->id == ValueId::string_literal && right->id == ValueId::string_literal;

                if (are_string_literal)
                {
                    expected_type = get_slice_type(module, uint8(module));
                }
                else
                {
                    report_error();
                }
            }
        }
    }

    if (is_boolean || !expected_type)
    {
        if (left_constant)
        {
            analyze_type(module, right, 0);
            analyze_type(module, left, right->type);
        }
        else 
        {
            analyze_type(module, left, 0);
            analyze_type(module, right, left->type);
        }
    }
    else if (!is_boolean && expected_type)
    {
        analyze_type(module, left, expected_type);
        analyze_type(module, right, expected_type);
    }
    else
    {
        report_error(); // TODO: this might not be an error necessarily?
    }

    assert(left->type);
    assert(right->type);
}

fn Type* get_va_list_type(Module* module)
{
    if (!module->va_list_type)
    {
        auto u32_type = uint32(module);
        auto void_pointer = get_pointer_type(module, uint8(module));
        auto fields = arena_allocate<Field>(module->arena, 4);
        fields[0] = { .name = string_literal("gp_offset"), .type = u32_type, .offset = 0 };
        fields[1] = { .name = string_literal("fp_offset"), .type = u32_type, .offset = 4 };
        fields[2] = { .name = string_literal("overflow_arg_area"), .type = void_pointer, .offset = 8 };
        fields[3] = { .name = string_literal("reg_save_area"), .type = void_pointer, .offset = 16 };

        auto va_list_struct = type_allocate_init(module, {
            .structure = {
                .fields = fields,
                .byte_size = 24,
                .byte_alignment = 16,
            },
            .id = TypeId::structure,
            .name = string_literal("va_list"),
        });

        module->va_list_type = get_array_type(module, va_list_struct, 1);
    }

    assert(module->va_list_type);

    return module->va_list_type;
}

fn Global* get_enum_name_array_global(Module* module, Type* enum_type)
{
    assert(enum_type->id == TypeId::enumerator);

    if (!enum_type->enumerator.name_array)
    {
        auto fields = enum_type->enumerator.fields;
        auto u8_type = uint8(module);
        auto u64_type = uint64(module);
        resolve_type_in_place(module, u8_type);
        resolve_type_in_place(module, u64_type);
        LLVMValueRef name_before = 0;
        LLVMValueRef name_constant_buffer[64];

        for (u32 i = 0; i < fields.length; i += 1)
        {
            auto null_terminate = true;
            auto& field = fields[i];
            auto is_constant = true;
            String name_parts[] = {
                string_literal("string."),
                enum_type->name,
                string_literal("."),
                field.name,
            };
            unsigned address_space = 0;
            auto name_global = llvm_module_create_global_variable(module->llvm.module, LLVMArrayType2(u8_type->llvm.abi, field.name.length + null_terminate), is_constant, LLVMInternalLinkage, LLVMConstStringInContext2(module->llvm.context, (char*)field.name.pointer, field.name.length, false), arena_join_string(module->arena, array_to_slice(name_parts)), name_before, LLVMNotThreadLocal, address_space, false);
            name_before = name_global;
            LLVMValueRef constants[] = {
                name_global,
                LLVMConstInt(u64_type->llvm.abi, field.name.length, false),
            };
            auto slice_constant = LLVMConstStructInContext(module->llvm.context, constants, array_length(constants), false);
            name_constant_buffer[i] = slice_constant;
        }

        auto slice_type = get_slice_type(module, u8_type);
        auto array_element_count = fields.length;
        auto name_array = LLVMConstArray2(slice_type->llvm.abi, name_constant_buffer, array_element_count);
        auto name_array_type = LLVMArrayType2(slice_type->llvm.abi, array_element_count);
        auto is_constant = true;
        unsigned address_space = 0;
        auto name_array_variable = llvm_module_create_global_variable(module->llvm.module, name_array_type, is_constant, LLVMInternalLinkage, name_array, string_literal("name.array.enum"), name_before, LLVMNotThreadLocal, address_space, false);
        LLVMSetAlignment(name_array_variable, get_byte_alignment(slice_type));
        LLVMSetUnnamedAddress(name_array_variable, LLVMGlobalUnnamedAddr);

        auto global_type = get_array_type(module, slice_type, array_element_count);
        resolve_type_in_place(module, global_type);

        auto storage_type = get_pointer_type(module, global_type);
        resolve_type_in_place(module, storage_type);

        auto global_storage = new_value(module);
        *global_storage = {
            .type = storage_type,
            .id = ValueId::global,
            .kind = ValueKind::left,
            .llvm = name_array_variable,
        };

        String name_parts[] = {
            string_literal("name.array.enum."),
            enum_type->name,
        };

        auto global = new_global(module);
        *global = {
            .variable = {
                .storage = global_storage,
                .initial_value = 0,
                .type = global_type,
                .scope = &module->scope,
                .name = arena_join_string(module->arena, array_to_slice(name_parts)),
                .line = 0,
                .column = 0,
            },
            .linkage = Linkage::internal,
        };
        global->emitted = true;

        enum_type->enumerator.name_array = global;
    }

    return enum_type->enumerator.name_array;
}

struct BlockCopy
{
    Block* source;
    Block* destination;
};
fn void copy_block(Module* module, Scope* parent_scope, BlockCopy copy);

fn Value* clone_value(Module* module, Scope* scope, Value* old_value)
{
    assert(old_value);

    Value* result = 0;
    if (old_value->id == ValueId::variable_reference)
    {
        result = reference_identifier(module, scope, old_value->variable_reference->name, old_value->kind);
    }
    else
    {
        result = new_value(module);
        *result = *old_value;

        switch (old_value->id)
        {
            case ValueId::variable_reference:
                {
                    unreachable();
                } break;
            case ValueId::binary:
                {
                    auto left = clone_value(module, scope, old_value->binary.left);
                    auto right = clone_value(module, scope, old_value->binary.right);

                    result->binary = {
                        .left = left,
                        .right = right,
                        .id = old_value->binary.id,
                    };
                } break;
            case ValueId::unary:
                {
                    auto unary_value = clone_value(module, scope, old_value->unary.value);
                    result->unary = {
                        .value = unary_value,
                        .id = old_value->unary.id,
                    };
                } break;
            case ValueId::unary_type:
                {
                    result->unary_type = old_value->unary_type;
                } break;
            case ValueId::unreachable:
                break;
            case ValueId::slice_expression:
                {
                    auto old_start = old_value->slice_expression.start;
                    auto old_end = old_value->slice_expression.end;

                    result->slice_expression = {
                        .array_like = clone_value(module, scope, old_value->slice_expression.array_like),
                        .start = old_start ? clone_value(module, scope, old_start) : 0,
                        .end = old_end ? clone_value(module, scope, old_end) : 0,
                    };
                } break;
            case ValueId::call:
                {
                    auto callable = clone_value(module, scope, old_value->call.callable);
                    auto old_arguments = old_value->call.arguments;
                    auto arguments = new_value_array(module, old_arguments.length);

                    for (u64 i = 0; i < arguments.length; i += 1)
                    {
                        arguments[i] = clone_value(module, scope, old_arguments[i]);
                    }

                    result->call = {
                        .callable = callable,
                        .arguments = arguments,
                        .function_type = old_value->call.function_type,
                    };
                } break;
            default: trap();
        }
    }

    assert(result);

    return result;
}

fn Statement* clone_statement(Module* module, Scope* scope, Statement* old_statement)
{
    auto new_statement = &arena_allocate<Statement>(module->arena, 1)[0];
    *new_statement = {};
    auto old_id = old_statement->id;
    new_statement->id = old_id; // TODO: is this right?
    new_statement->line = old_statement->line;
    new_statement->column = old_statement->column;

    switch (old_id)
    {
        case StatementId::return_st:
            {
                auto old_return_value = old_statement->return_st;
                new_statement->return_st = old_return_value ? clone_value(module, scope, old_return_value) : 0;
            } break;
        case StatementId::if_st:
            {
                auto condition = clone_value(module, scope, old_statement->if_st.condition);
                auto if_statement = clone_statement(module, scope, old_statement->if_st.if_statement);
                auto else_statement = old_statement->if_st.else_statement;
                else_statement = else_statement ? clone_statement(module, scope, else_statement) : 0;
                new_statement->if_st = {
                    .condition = condition,
                    .if_statement = if_statement,
                    .else_statement = else_statement,
                };
            } break;
        case StatementId::block:
            {
                auto block = &arena_allocate<Block>(module->arena, 1)[0];
                copy_block(module, scope, {
                    .source = old_statement->block,
                    .destination = block,
                });

                new_statement->block = block;
            } break;
        case StatementId::expression:
            {
                auto value = clone_value(module, scope, old_statement->expression);
                new_statement->expression = value;
            } break;
        case StatementId::local:
            {
                auto local_old = old_statement->local;
                auto local_new = new_local(module, scope);
                assert(!local_old->variable.storage);
                *local_new = {
                    .variable = {
                        .storage = 0,
                        .initial_value = clone_value(module, scope, local_old->variable.initial_value),
                        .type = local_old->variable.type ? resolve_type(module, local_old->variable.type) : 0,
                        .scope = scope,
                        .name = local_old->variable.name,
                        .line = local_old->variable.line,
                        .column = local_old->variable.column,
                    },
                };

                new_statement->local = local_new;
            } break;
        default: trap();
    }

    return new_statement;
}

fn void copy_block(Module* module, Scope* parent_scope, BlockCopy copy)
{
    auto source = copy.source;
    auto destination = copy.destination;

    *destination = {};
    auto scope = &destination->scope;
    *scope = source->scope;
    scope->parent = parent_scope;
    assert(!scope->llvm);

    Statement* last_statement = 0;
    for (Statement* old_statement = source->first_statement; old_statement; old_statement = old_statement->next)
    {
        auto statement = clone_statement(module, scope, old_statement);
        assert(!statement->next);
        if (last_statement)
        {
            last_statement->next = statement;
            last_statement = statement;
        }
        else
        {
            last_statement = statement;
            destination->first_statement = statement;
        }
    }
}

fn void analyze_type(Module* module, Value* value, Type* expected_type)
{
    assert(!value->type);
    assert(!value->llvm);

    if (expected_type && expected_type->id == TypeId::unresolved)
    {
        auto instantiation = module->current_macro_instantiation;
        if (!instantiation)
        {
            report_error();
        }

        auto declaration = instantiation->declaration;

        Type* resolved_type = 0;

        auto instantiation_arguments = instantiation->constant_arguments;
        auto declaration_arguments = declaration->constant_arguments;

        assert(instantiation_arguments.length == declaration_arguments.length);

        for (u64 i = 0; i < instantiation_arguments.length; i += 1)
        {
            auto& instantiation_argument = instantiation_arguments[i];
            auto& declaration_argument = declaration_arguments[i];

            assert(declaration_argument.id == instantiation_argument.id);

            if (declaration_argument.id == ConstantArgumentId::type && declaration_argument.type == expected_type)
            {
                resolved_type = instantiation_argument.type;
                resolve_type_in_place(module, resolved_type);
                break;
            }
        }

        if (!resolved_type)
        {
            report_error();
        }

        expected_type = resolved_type;
    }

    Type* value_type = 0;

    switch (value->id)
    {
        case ValueId::constant_integer:
            {
                if (!expected_type)
                {
                    report_error();
                }

                resolve_type_in_place(module, expected_type);
                auto* resolved_type = resolve_alias(module, expected_type);
                switch (resolved_type->id)
                {
                    case TypeId::integer:
                        {
                            if (value->constant_integer.is_signed)
                            {
                                if (resolved_type->integer.is_signed)
                                {
                                    report_error();
                                }

                                trap();
                            }
                            else
                            {
                                auto max_value = integer_max_value(resolved_type->integer.bit_count, resolved_type->integer.is_signed);
                                
                                if (value->constant_integer.value > max_value)
                                {
                                    report_error();
                                }

                                value_type = expected_type;
                            }
                        } break;
                    case TypeId::pointer: value_type = uint64(module); break;
                    default: trap();
                }

                typecheck(module, expected_type, value_type);
            } break;
        case ValueId::unary:
            {
                auto unary_id = value->unary.id;
                auto unary_value = value->unary.value;
                switch (unary_id)
                {
                    case UnaryId::extend:
                        {
                            if (!expected_type)
                            {
                                report_error();
                            }

                            auto extended_value = unary_value;
                            analyze_type(module, extended_value, 0);
                            auto source = extended_value->type;
                            assert(source);

                            auto source_bit_size = get_bit_size(source);
                            auto expected_bit_size = get_bit_size(expected_type);
                            if (source_bit_size > expected_bit_size)
                            {
                                report_error();
                            }
                            else if (source_bit_size == expected_bit_size && type_is_signed(source) == type_is_signed(expected_type))
                            {
                                report_error();
                            }

                            value_type = expected_type;
                        } break;
                    case UnaryId::truncate:
                        {
                            if (!expected_type)
                            {
                                report_error();
                            }

                            analyze_type(module, unary_value, 0);
                            auto expected_bit_size = get_bit_size(expected_type);
                            auto source_bit_size = get_bit_size(unary_value->type);

                            if (expected_bit_size >= source_bit_size)
                            {
                                report_error();
                            }

                            value_type = expected_type;
                        } break;
                    case UnaryId::dereference:
                        {
                            analyze_type(module, unary_value, 0);
                            if (value->kind == ValueKind::left)
                            {
                                report_error();
                            }
                            auto pointer_type = unary_value->type;
                            assert(pointer_type->id == TypeId::pointer);
                            auto dereference_type = pointer_type->pointer.element_type;

                            typecheck(module, expected_type, dereference_type);
                            value_type = dereference_type;
                        } break;
                    case UnaryId::int_from_enum:
                        {
                            analyze_type(module, unary_value, 0);

                            auto value_enum_type = unary_value->type;
                            if (value_enum_type->id != TypeId::enumerator)
                            {
                                report_error();
                            }

                            auto backing_type = value_enum_type->enumerator.backing_type;
                            typecheck(module, expected_type, backing_type);

                            value_type = backing_type;
                        } break;
                    case UnaryId::int_from_pointer:
                        {
                            analyze_type(module, unary_value, 0);

                            auto value_enum_type = unary_value->type;
                            if (value_enum_type->id != TypeId::pointer)
                            {
                                report_error();
                            }

                            value_type = uint64(module);
                            typecheck(module, expected_type, value_type);
                        } break;
                    case UnaryId::pointer_cast:
                        {
                            if (!expected_type)
                            {
                                report_error();
                            }

                            if (expected_type->id != TypeId::pointer)
                            {
                                report_error();
                            }

                            analyze_type(module, unary_value, 0);
                            auto value_pointer_type = unary_value->type;
                            if (value_pointer_type == expected_type)
                            {
                                report_error();
                            }

                            if (value_pointer_type->id != TypeId::pointer)
                            {
                                report_error();
                            }

                            value_type = expected_type;
                        } break;
                    case UnaryId::enum_name:
                        {
                            auto string_type = get_slice_type(module, uint8(module));
                            typecheck(module, expected_type, string_type);
                            analyze_type(module, unary_value, 0);
                            auto enum_type = unary_value->type;
                            if (enum_type->id != TypeId::enumerator)
                            {
                                report_error();
                            }

                            auto enum_to_string = enum_type->enumerator.enum_to_string_function;
                            if (!enum_to_string)
                            {
                                auto current_block = LLVMGetInsertBlock(module->llvm.builder);
                                auto enum_name_array_global = get_enum_name_array_global(module, enum_type);
                                LLVMTypeRef argument_types[] = {
                                    enum_type->llvm.abi,
                                };
                                auto llvm_function_type = LLVMFunctionType(string_type->llvm.memory, argument_types, array_length(argument_types), false);
                                String name_parts[] = {
                                    string_literal("enum_to_string."),
                                    enum_type->name,
                                };
                                auto function_name = arena_join_string(module->arena, array_to_slice(name_parts));
                                auto llvm_function = llvm_module_create_function(module->llvm.module, llvm_function_type, LLVMInternalLinkage, 0, function_name);
                                LLVMSetFunctionCallConv(llvm_function, LLVMFastCallConv);

                                LLVMValueRef llvm_argument;
                                LLVMGetParams(llvm_function, &llvm_argument);

                                auto* entry_block = llvm_context_create_basic_block(module->llvm.context, string_literal("entry"), llvm_function);
                                LLVMPositionBuilderAtEnd(module->llvm.builder, entry_block);

                                auto alloca = create_alloca(module, {
                                    .type = string_type,
                                    .name = string_literal("retval"),
                                });

                                auto* return_block = llvm_context_create_basic_block(module->llvm.context, string_literal("return_block"), llvm_function);
                                auto* else_block = llvm_context_create_basic_block(module->llvm.context, string_literal("else_block"), llvm_function);

                                auto enum_fields = enum_type->enumerator.fields;

                                auto switch_instruction = LLVMBuildSwitch(module->llvm.builder, llvm_argument, else_block, enum_fields.length);
                                auto backing_type = enum_type->llvm.abi;
                                assert(backing_type);
                                auto u64_type = uint64(module)->llvm.abi;

                                for (u64 i = 0; i < enum_fields.length; i += 1)
                                {
                                    auto& field = enum_fields[i];
                                    auto* case_block = llvm_context_create_basic_block(module->llvm.context, string_literal("case_block"), llvm_function);
                                    auto case_value = LLVMConstInt(backing_type, field.value, false);

                                    LLVMAddCase(switch_instruction, case_value, case_block);
                                    LLVMPositionBuilderAtEnd(module->llvm.builder, case_block);

                                    LLVMValueRef indices[] = {
                                        LLVMConstNull(u64_type),
                                        LLVMConstInt(u64_type, i, false),
                                    };

                                    auto case_value_result_pointer = create_gep(module, {
                                        .type = enum_name_array_global->variable.type->llvm.memory,
                                        .pointer = enum_name_array_global->variable.storage->llvm,
                                        .indices = array_to_slice(indices),
                                    });

                                    auto case_value_result = create_load(module, {
                                        .type = string_type,
                                        .pointer = case_value_result_pointer,
                                    });

                                    create_store(module, {
                                        .source = case_value_result,
                                        .destination = alloca,
                                        .type = string_type,
                                    });

                                    LLVMBuildBr(module->llvm.builder, return_block);
                                }

                                LLVMPositionBuilderAtEnd(module->llvm.builder, else_block);
                                LLVMBuildUnreachable(module->llvm.builder);

                                LLVMPositionBuilderAtEnd(module->llvm.builder, return_block);
                                auto function_result = create_load(module, {
                                    .type = string_type,
                                    .pointer = alloca,
                                });

                                LLVMBuildRet(module->llvm.builder, function_result);

                                if (current_block)
                                {
                                    LLVMPositionBuilderAtEnd(module->llvm.builder, current_block);
                                }

                                enum_to_string = llvm_function;
                                enum_type->enumerator.enum_to_string_function = enum_to_string;
                            }

                            assert(enum_to_string);

                            value_type = string_type;
                        } break;
                    case UnaryId::pointer_from_int:
                        {
                            if (!expected_type)
                            {
                                report_error();
                            }

                            if (expected_type->id != TypeId::pointer)
                            {
                                report_error();
                            }

                            analyze_type(module, unary_value, 0);
                            auto unary_value_type = unary_value->type;
                            if (unary_value_type->id != TypeId::integer)
                            {
                                report_error();
                            }

                            // TODO: is this correct?
                            if (get_bit_size(unary_value_type) != 64)
                            {
                                report_error();
                            }

                            value_type = expected_type;
                        } break;
                    default:
                        {
                            auto is_boolean = unary_is_boolean(unary_id);
                            if (is_boolean)
                            {
                                analyze_type(module, unary_value, 0);
                                value_type = uint1(module);
                            }
                            else
                            {
                                analyze_type(module, unary_value, expected_type);
                                value_type = unary_value->type;
                            }

                            typecheck(module, expected_type, value_type);
                        } break;
                }
            } break;
        case ValueId::unary_type:
            {
                auto unary_type = resolve_type(module, value->unary_type.type);
                value->unary_type.type = unary_type;
                auto unary_type_id = value->unary_type.id;

                if (expected_type)
                {
                    value_type = expected_type;
                }
                else
                {
                    value_type = unary_type;
                }

                assert(value_type);
                if (value_type->id != TypeId::integer)
                {
                    report_error();
                }

                u64 value;
                auto max_value = integer_max_value(value_type->integer.bit_count, value_type->integer.is_signed);
                switch (unary_type_id)
                {
                    case UnaryTypeId::align_of:
                        {
                            value = get_byte_alignment(unary_type);
                        } break;
                    case UnaryTypeId::byte_size:
                        {

                            value = get_byte_size(unary_type);
                        } break;
                    case UnaryTypeId::integer_max:
                        {
                            value = integer_max_value(unary_type->integer.bit_count, unary_type->integer.is_signed);
                        } break;
                }

                if (value > max_value)
                {
                    report_error();
                }

                typecheck(module, expected_type, value_type);
            } break;
        case ValueId::binary:
            {
                auto is_boolean = binary_is_boolean(value->binary.id);
                analyze_binary_type(module, value->binary.left, value->binary.right, is_boolean, expected_type);
                check_types(module, value->binary.left->type, value->binary.right->type);

                value_type = is_boolean ? uint1(module) : value->binary.left->type;
            } break;
        case ValueId::variable_reference:
            {
                switch (value->kind)
                {
                    case ValueKind::left: value_type = value->variable_reference->storage->type; break;
                    case ValueKind::right: value_type = value->variable_reference->type; break;
                }
                assert(value_type);
                typecheck(module, expected_type, value_type);
            } break;
        case ValueId::call:
            {
                auto call = &value->call;
                auto callable = call->callable;
                analyze_type(module, callable, 0);
                Type* function_type = 0;
                switch (callable->id)
                {
                    case ValueId::variable_reference:
                        {
                            auto variable_type = callable->variable_reference->type;
                            switch (variable_type->id)
                            {
                                case TypeId::function:
                                    function_type = variable_type; break;
                                case TypeId::pointer:
                                    {
                                        auto* element_type = variable_type->pointer.element_type;
                                        switch (element_type->id)
                                        {
                                            case TypeId::function: function_type = element_type; break;
                                            default: report_error();
                                        }
                                    } break;
                                default: report_error();
                            }
                        } break;
                    default:
                        report_error();
                }

                assert(function_type);
                call->function_type = function_type;

                auto semantic_argument_types = function_type->function.semantic_argument_types;
                auto call_arguments = call->arguments;
                if (function_type->function.is_variable_arguments)
                {
                    if (call_arguments.length < semantic_argument_types.length)
                    {
                        report_error();
                    }
                }
                else
                {
                    if (call_arguments.length != semantic_argument_types.length)
                    {
                        report_error();
                    }
                }
                    
                for (u64 i = 0; i < semantic_argument_types.length; i += 1)
                {
                    auto* argument_type = semantic_argument_types[i];
                    auto* call_argument = call_arguments[i];
                    analyze_type(module, call_argument, argument_type);
                    check_types(module, argument_type, call_argument->type);
                }

                for (u64 i = semantic_argument_types.length; i < call_arguments.length; i += 1)
                {
                    auto* call_argument = call_arguments[i];
                    analyze_type(module, call_argument, 0);
                }

                auto semantic_return_type = function_type->function.semantic_return_type;
                typecheck(module, expected_type, semantic_return_type);
                value_type = semantic_return_type;
            } break;
        case ValueId::array_initialization:
            {
                auto values = value->array_initialization.values;
                if (expected_type)
                {
                    if (expected_type->id != TypeId::array)
                    {
                        report_error();
                    }

                    if (expected_type->array.element_count == 0)
                    {
                        expected_type->array.element_count = values.length;
                        assert(expected_type->name.equal(string_literal("")));
                        expected_type->name = array_name(module, expected_type->array.element_type, expected_type->array.element_count);
                    }
                    else
                    {
                        if (expected_type->array.element_count != values.length)
                        {
                            report_error();
                        }
                    }

                    bool is_constant = true;

                    auto* element_type = expected_type->array.element_type;
                    for (auto value : values)
                    {
                        analyze_type(module, value, element_type);
                        is_constant = is_constant && value->is_constant();
                    }

                    value->array_initialization.is_constant = is_constant;

                    if (value->kind == ValueKind::left) // TODO: possible?
                    {
                        report_error();
                    }

                    value_type = expected_type;
                }
                else
                {
                    if (values.length == 0)
                    {
                        report_error();
                    }

                    Type* expected_type = 0;
                    bool is_constant = true;

                    for (auto value : values)
                    {
                        analyze_type(module, value, expected_type);

                        is_constant = is_constant && value->is_constant();

                        auto value_type = value->type;
                        if (expected_type)
                        {
                            if (expected_type != value_type)
                            {
                                report_error();
                            }
                        }
                        else
                        {
                            assert(value_type);
                            expected_type = value_type;
                        }
                    }

                    if (!expected_type)
                    {
                        report_error();
                    }

                    auto element_type = expected_type;
                    auto element_count = values.length;

                    auto array_type = get_array_type(module, element_type, element_count);
                    value_type = array_type;

                    if (value->kind == ValueKind::left)
                    {
                        value_type = get_pointer_type(module, array_type);
                    }
                }
            } break;
        case ValueId::array_expression:
            {
                analyze_type(module, value->array_expression.index, uint64(module));
                auto array_like = value->array_expression.array_like;
                array_like->kind = ValueKind::left;
                analyze_type(module, array_like, 0);
                assert(array_like->kind == ValueKind::left);
                auto array_like_type = array_like->type;
                if (array_like_type->id != TypeId::pointer)
                {
                    report_error();
                }
                auto pointer_element_type = array_like_type->pointer.element_type;

                Type* element_type = 0;
                switch (pointer_element_type->id)
                {
                    case TypeId::array:
                        {
                            element_type = pointer_element_type->array.element_type;
                        } break;
                    case TypeId::structure:
                        {
                            auto slice_type = pointer_element_type;
                            if (!slice_type->structure.is_slice)
                            {
                                report_error();
                            }
                            auto slice_pointer_type = slice_type->structure.fields[0].type;
                            assert(slice_pointer_type->id == TypeId::pointer);
                            element_type = slice_pointer_type->pointer.element_type;
                        } break;
                    case TypeId::pointer:
                        {
                            element_type = pointer_element_type->pointer.element_type;
                        } break;
                    default: report_error();
                }

                assert(element_type);

                value_type = element_type;
                if (value->kind == ValueKind::left)
                {
                    value_type = get_pointer_type(module, element_type);
                }

                typecheck(module, expected_type, value_type);
            } break;
        case ValueId::enum_literal:
            {
                if (!expected_type)
                {
                    report_error();
                }

                if (expected_type->id != TypeId::enumerator)
                {
                    report_error();
                }

                value_type = expected_type;
            } break;
        case ValueId::trap:
            {
                value_type = noreturn_type(module);
            } break;
        case ValueId::field_access:
            {
                auto aggregate = value->field_access.aggregate;
                auto field_name = value->field_access.field_name;
                analyze_type(module, aggregate, 0);

                if (aggregate->kind == ValueKind::right)
                {
                    report_error();
                }

                auto aggregate_type = aggregate->type;
                if (aggregate_type->id != TypeId::pointer)
                {
                    report_error();
                }

                auto aggregate_element_type = aggregate_type->pointer.element_type;
                Type* real_aggregate_type = aggregate_element_type->id == TypeId::pointer ? aggregate_element_type->pointer.element_type : aggregate_element_type;
                auto resolved_aggregate_type = resolve_alias(module, real_aggregate_type);

                switch (resolved_aggregate_type->id)
                {
                    case TypeId::structure:
                        {
                            Field* result_field = 0;
                            auto fields = resolved_aggregate_type->structure.fields;
                            for (u64 i = 0; i < fields.length; i += 1)
                            {
                                auto* field = &fields[i];
                                if (field_name.equal(field->name))
                                {
                                    result_field = field;
                                    break;
                                }
                            }

                            if (!result_field)
                            {
                                report_error();
                            }

                            auto field_type = result_field->type;
                            value_type = value->kind == ValueKind::left ? get_pointer_type(module, field_type) : field_type;
                        } break;
                    case TypeId::union_type:
                        {
                            UnionField* result_field = 0;
                            auto fields = resolved_aggregate_type->union_type.fields;
                            for (u64 i = 0; i < fields.length; i += 1)
                            {
                                auto* field = &fields[i];
                                if (field_name.equal(field->name))
                                {
                                    result_field = field;
                                    break;
                                }
                            }

                            if (!result_field)
                            {
                                report_error();
                            }

                            auto field_type = result_field->type;
                            value_type = value->kind == ValueKind::left ? get_pointer_type(module, field_type) : field_type;
                        } break;
                    case TypeId::bits:
                        {
                            if (value->kind == ValueKind::left)
                            {
                                report_error();
                            }

                            auto fields = resolved_aggregate_type->bits.fields;
                            u64 i;
                            for (i = 0; i < fields.length; i += 1)
                            {
                                auto field = fields[i];
                                if (field_name.equal(field.name))
                                {
                                    break;
                                }
                            }

                            if (i == fields.length)
                            {
                                report_error();
                            }

                            assert(value->kind == ValueKind::right);

                            auto field = fields[i];
                            value_type = field.type;
                        } break;
                    case TypeId::array:
                        {
                            if (!field_name.equal(string_literal("length")))
                            {
                                report_error();
                            }

                            if (expected_type)
                            {
                                if (expected_type->id != TypeId::integer)
                                {
                                    report_error();
                                }

                                value_type = expected_type;
                            }
                            else
                            {
                                trap();
                            }
                        } break;
                    case TypeId::pointer: report_error(); // Double indirection is not allowed
                    default: report_error();
                }

                assert(value_type);

                typecheck(module, expected_type, value_type);
            } break;
        case ValueId::slice_expression:
            {
                auto array_like = value->slice_expression.array_like;
                auto start = value->slice_expression.start;
                auto end = value->slice_expression.end;

                if (array_like->kind != ValueKind::left)
                {
                    report_error();
                }

                analyze_type(module, array_like, 0);

                auto pointer_type = array_like->type;
                if (pointer_type->id != TypeId::pointer)
                {
                    report_error();
                }

                Type* sliceable_type = pointer_type->pointer.element_type;

                Type* element_type = 0;

                switch (sliceable_type->id)
                {
                    case TypeId::pointer:
                        {
                            element_type = sliceable_type->pointer.element_type;
                        } break;
                    case TypeId::structure:
                        {
                            if (!sliceable_type->structure.is_slice)
                            {
                                report_error();
                            }
                            auto slice_pointer_type = sliceable_type->structure.fields[0].type;
                            assert(slice_pointer_type->id == TypeId::pointer);
                            auto slice_element_type = slice_pointer_type->pointer.element_type;
                            element_type = slice_element_type;
                        } break;
                    case TypeId::array:
                        {
                            element_type = sliceable_type->array.element_type;
                        } break;
                    default: unreachable();
                }

                assert(element_type);

                auto slice_type = get_slice_type(module, element_type);
                typecheck(module, expected_type, slice_type);

                auto index_type = uint64(module);

                Value* indices[] = { start, end };

                for (auto index : indices)
                {
                    if (index)
                    {
                        analyze_type(module, index, index_type);

                        if (index->type->id != TypeId::integer)
                        {
                            report_error();
                        }
                    }
                }

                value_type = slice_type;
            } break;
        case ValueId::string_literal:
            {
                auto slice_type = get_slice_type(module, uint8(module));
                typecheck(module, expected_type, slice_type);
                value_type = slice_type;
            } break;
        case ValueId::va_start:
            {
                auto va_list_type = get_va_list_type(module);
                typecheck(module, expected_type, va_list_type);
                value_type = va_list_type;
            } break;
        case ValueId::va_arg:
            {
                analyze_type(module, value->va_arg.va_list, get_pointer_type(module, get_va_list_type(module)));
                value_type = value->va_arg.type;
                typecheck(module, expected_type, value_type);
            } break;
        case ValueId::aggregate_initialization:
            {
                if (!expected_type)
                {
                    report_error();
                }

                auto resolved_type = resolve_alias(module, expected_type);
                value_type = resolved_type;

                assert(!value->aggregate_initialization.is_constant);
                bool is_constant = true;
                auto values = value->aggregate_initialization.values;
                auto names = value->aggregate_initialization.names;

                switch (resolved_type->id)
                {
                    case TypeId::structure:
                        {
                            bool is_ordered = true;
                            auto fields = resolved_type->structure.fields;

                            for (u32 initialization_index = 0; initialization_index < values.length; initialization_index += 1)
                            {
                                auto value = values[initialization_index];
                                auto name = names[initialization_index];

                                u32 declaration_index;
                                for (declaration_index = 0; declaration_index < fields.length; declaration_index += 1)
                                {
                                    auto& field = fields[declaration_index];

                                    if (name.equal(field.name))
                                    {
                                        break;
                                    }
                                }

                                if (declaration_index == fields.length)
                                {
                                    report_error();
                                }

                                is_ordered = is_ordered && declaration_index == initialization_index;

                                auto field = fields[declaration_index];
                                auto declaration_type = field.type;
                                analyze_type(module, value, declaration_type);
                                is_constant = is_constant && value->is_constant();
                            }

                            value->aggregate_initialization.is_constant = is_constant && is_ordered;
                        } break;
                    case TypeId::bits:
                        {
                            auto fields = resolved_type->bits.fields;


                            assert(values.length == names.length);

                            for (u32 initialization_index = 0; initialization_index < values.length; initialization_index += 1)
                            {
                                auto value = values[initialization_index];
                                auto name = names[initialization_index];

                                u32 declaration_index;
                                for (declaration_index = 0; declaration_index < fields.length; declaration_index += 1)
                                {
                                    auto& field = fields[declaration_index];

                                    if (name.equal(field.name))
                                    {
                                        break;
                                    }
                                }

                                if (declaration_index == fields.length)
                                {
                                    report_error();
                                }

                                auto field = fields[declaration_index];
                                auto declaration_type = field.type;
                                analyze_type(module, value, declaration_type);
                                is_constant = is_constant && value->is_constant();
                            }

                            value->aggregate_initialization.is_constant = is_constant;
                        } break;
                    case TypeId::union_type:
                        {
                            if (values.length != 1)
                            {
                                report_error();
                            }

                            auto initialization_value = values[0];
                            assert(names.length == 1);
                            auto initialization_name = names[0];

                            u64 i;
                            auto fields = resolved_type->union_type.fields;
                            for (i = 0; i < fields.length; i += 1)
                            {
                                auto& field = fields[i];
                                if (initialization_name.equal(field.name))
                                {
                                    break;
                                }
                            }

                            if (i == fields.length)
                            {
                                report_error();
                            }

                            auto field = &fields[i];
                            analyze_type(module, initialization_value, field->type);

                            value_type = expected_type;
                        } break;
                    default: report_error();
                }
            } break;
        case ValueId::zero:
            {
                if (!expected_type)
                {
                    report_error();
                }

                if (expected_type->id == TypeId::void_type || expected_type->id == TypeId::noreturn)
                {
                    report_error();
                }

                value_type = expected_type;
            } break;
        case ValueId::select:
            {
                auto condition = value->select.condition;
                auto true_value = value->select.true_value;
                auto false_value = value->select.false_value;
                analyze_type(module, condition, 0);
                auto is_boolean = false;
                analyze_binary_type(module, true_value, false_value, is_boolean, expected_type);

                auto left_type = true_value->type;
                auto right_type = false_value->type;
                check_types(module, left_type, right_type);

                assert(left_type == right_type);
                auto result_type = left_type;
                typecheck(module, expected_type, result_type);

                value_type = result_type;
            } break;
        case ValueId::unreachable:
            {
                value_type = noreturn_type(module);
            } break;
        case ValueId::string_to_enum:
            {
                auto enum_type = value->string_to_enum.type;
                auto enum_string_value = value->string_to_enum.string;
                if (enum_type->id != TypeId::enumerator)
                {
                    report_error();
                }

                if (!enum_type->enumerator.string_to_enum_function)
                {
                    resolve_type_in_place(module, enum_type);

                    auto fields = enum_type->enumerator.fields;
                    auto array_element_count = fields.length;
                    
                    auto insert_block = LLVMGetInsertBlock(module->llvm.builder);

                    auto u1_type = uint1(module);
                    auto u8_type = uint8(module);
                    auto u64_type = uint64(module);
                    resolve_type_in_place(module, u1_type);
                    resolve_type_in_place(module, u8_type);
                    resolve_type_in_place(module, u64_type);

                    auto u64_zero = LLVMConstNull(u64_type->llvm.abi);

                    auto enum_alignment = get_byte_alignment(enum_type);
                    auto enum_size = get_byte_size(enum_type);
                    auto byte_size = align_forward(enum_size + 1, enum_alignment);

                    auto struct_fields = arena_allocate<Field>(module->arena, 2);

                    struct_fields[0] = {
                        .name = string_literal("enum_value"),
                        .type = enum_type,
                    };

                    struct_fields[1] = {
                        .name = string_literal("is_valid"),
                        .type = u1_type,
                        .offset = enum_size,
                    };

                    auto struct_type = type_allocate_init(module, {
                        .structure = {
                            .fields = struct_fields,
                            .byte_size = byte_size,
                            .byte_alignment = enum_alignment,
                        },
                        .id = TypeId::structure,
                        .name = string_literal("string_to_enum"),
                    });
                    resolve_type_in_place(module, struct_type);

                    LLVMTypeRef argument_types[] = { module->llvm.pointer_type, u64_type->llvm.abi };
                    auto llvm_function_type = LLVMFunctionType(struct_type->llvm.abi, argument_types, array_length(argument_types), false);
                    auto slice_struct_type = get_slice_type(module, u8_type);

                    String name_parts[] = {
                        string_literal("string_to_enum."),
                        enum_type->name,
                    };
                    auto function_name = arena_join_string(module->arena, array_to_slice(name_parts));
                    auto llvm_function = llvm_module_create_function(module->llvm.module, llvm_function_type, LLVMInternalLinkage, 0, function_name);
                    LLVMSetFunctionCallConv(llvm_function, LLVMFastCallConv);

                    auto name_array_global = get_enum_name_array_global(module, enum_type);

                    auto enum_value_type = enum_type->llvm.memory;

                    LLVMValueRef value_constant_buffer[64];
                    for (u32 i = 0; i < fields.length; i += 1)
                    {
                        auto& field = fields[i];
                        auto global_value = LLVMConstInt(enum_value_type, field.value, false);
                        value_constant_buffer[i] = global_value;
                    }

                    auto value_array = LLVMConstArray2(enum_value_type, value_constant_buffer, array_element_count);
                    auto value_array_variable_type = LLVMArrayType2(enum_value_type, array_element_count);
                    auto is_constant = true;
                    LLVMValueRef before = 0;
                    LLVMThreadLocalMode thread_local_mode = LLVMNotThreadLocal;
                    unsigned address_space = 0;
                    auto externally_initialized = false;
                    auto value_array_variable = llvm_module_create_global_variable(module->llvm.module, value_array_variable_type, is_constant, LLVMInternalLinkage, value_array, string_literal("value.array.enum"), before, thread_local_mode, address_space, externally_initialized);
                    LLVMSetAlignment(value_array_variable, enum_alignment);
                    LLVMSetUnnamedAddress(value_array_variable, LLVMGlobalUnnamedAddr);

                    auto* entry_block = llvm_context_create_basic_block(module->llvm.context, string_literal("entry"), llvm_function);
                    auto* return_block = llvm_context_create_basic_block(module->llvm.context, string_literal("return_block"), llvm_function);
                    auto* loop_entry_block = llvm_context_create_basic_block(module->llvm.context, string_literal("loop.entry"), llvm_function);
                    auto* loop_body_block = llvm_context_create_basic_block(module->llvm.context, string_literal("loop.body"), llvm_function);
                    auto* loop_exit_block = llvm_context_create_basic_block(module->llvm.context, string_literal("loop.exit"), llvm_function);

                    LLVMPositionBuilderAtEnd(module->llvm.builder, entry_block);

                    LLVMValueRef arguments[2];
                    LLVMGetParams(llvm_function, arguments);

                    auto return_value_alloca = create_alloca(module, {
                        .type = enum_type,
                        .name = string_literal("retval"),
                    });

                    auto return_boolean_alloca = create_alloca(module, {
                        .type = u8_type,
                        .name = string_literal("retbool"),
                    });

                    auto index_alloca = create_alloca(module, {
                        .type = u64_type,
                        .name = string_literal("index"),
                    });

                    create_store(module, {
                        .source = u64_zero,
                        .destination = index_alloca,
                        .type = u64_type,
                    });

                    auto slice_pointer = arguments[0];
                    auto slice_length = arguments[1];
                    LLVMBuildBr(module->llvm.builder, loop_entry_block);

                    LLVMPositionBuilderAtEnd(module->llvm.builder, loop_entry_block);
                    auto index_load = create_load(module, {
                        .type = u64_type,
                        .pointer = index_alloca,
                    });
                    auto loop_compare = LLVMBuildICmp(module->llvm.builder, LLVMIntULT, index_load, LLVMConstInt(u64_type->llvm.abi, array_element_count, false), "");
                    LLVMBuildCondBr(module->llvm.builder, loop_compare, loop_body_block, loop_exit_block);

                    LLVMPositionBuilderAtEnd(module->llvm.builder, loop_body_block);
                    auto body_index_load = create_load(module, {
                        .type = u64_type,
                        .pointer = index_alloca,
                    });

                    LLVMValueRef indices[] = {
                        u64_zero,
                        body_index_load,
                    };
                    auto array_element_pointer = create_gep(module, {
                        .type = name_array_global->variable.type->llvm.memory,
                        .pointer = name_array_global->variable.storage->llvm,
                        .indices = array_to_slice(indices),
                    });

                    auto element_length_pointer = LLVMBuildStructGEP2(module->llvm.builder, slice_struct_type->llvm.abi, array_element_pointer, 1, "");
                    auto element_length = create_load(module, {
                        .type = u64_type,
                        .pointer = element_length_pointer,
                    });

                    auto length_comparison = LLVMBuildICmp(module->llvm.builder, LLVMIntEQ, slice_length, element_length, "");

                    auto* length_match_block = llvm_context_create_basic_block(module->llvm.context, string_literal("length.match"), llvm_function);
                    auto* length_mismatch_block = llvm_context_create_basic_block(module->llvm.context, string_literal("length.mismatch"), llvm_function);
                    LLVMBuildCondBr(module->llvm.builder, length_comparison, length_match_block, length_mismatch_block);

                    LLVMPositionBuilderAtEnd(module->llvm.builder, length_match_block);

                    auto s32_type = sint32(module);
                    resolve_type_in_place(module, s32_type);

                    LLVMValueRef memcmp = module->llvm.memcmp;
                    if (!memcmp)
                    {
                        memcmp = LLVMGetNamedFunction(module->llvm.module, "memcmp");
                        if (!memcmp)
                        {
                            LLVMTypeRef arguments[] = {
                                module->llvm.pointer_type,
                                module->llvm.pointer_type,
                                u64_type->llvm.abi,
                            };
                            auto llvm_function_type = LLVMFunctionType(s32_type->llvm.abi, arguments, array_length(arguments), false);
                            auto llvm_function = llvm_module_create_function(module->llvm.module, llvm_function_type, LLVMExternalLinkage, address_space, string_literal("memcmp"));
                            memcmp = llvm_function;
                        }

                        module->llvm.memcmp = memcmp;
                    }

                    assert(memcmp);
                    assert(module->llvm.memcmp);

                    auto length_index_load = create_load(module, {
                        .type = u64_type,
                        .pointer = index_alloca,
                    });

                    LLVMValueRef length_indices[] = { u64_zero, length_index_load };
                    auto length_array_element_pointer = create_gep(module, {
                        .type = name_array_global->variable.type->llvm.memory,
                        .pointer = name_array_global->variable.storage->llvm,
                        .indices = array_to_slice(length_indices),
                    });

                    auto element_pointer_pointer = LLVMBuildStructGEP2(module->llvm.builder, slice_struct_type->llvm.abi, length_array_element_pointer, 0, "");
                    auto element_pointer = create_load(module, {
                        .type = get_pointer_type(module, u8_type),
                        .pointer = element_pointer_pointer,
                    });

                    LLVMValueRef memcmp_arguments[] = {
                        slice_pointer,
                        element_pointer,
                        slice_length,
                    };
                    auto memcmp_return_result = LLVMBuildCall2(module->llvm.builder, LLVMGlobalGetValueType(memcmp), memcmp, memcmp_arguments, array_length(memcmp_arguments), "");
                    auto content_comparison = LLVMBuildICmp(module->llvm.builder, LLVMIntEQ, memcmp_return_result, LLVMConstNull(s32_type->llvm.abi), "");
                    auto* content_match_block = llvm_context_create_basic_block(module->llvm.context, string_literal("content.match"), llvm_function);
                    LLVMBuildCondBr(module->llvm.builder, content_comparison, content_match_block, length_mismatch_block);

                    LLVMPositionBuilderAtEnd(module->llvm.builder, content_match_block);

                    auto content_index_load = create_load(module, {
                        .type = u64_type,
                        .pointer = index_alloca,
                    });

                    LLVMValueRef value_array_indices[] = {
                        u64_zero,
                        content_index_load,
                    };
                    auto value_array_element_pointer = create_gep(module, {
                        .type = value_array_variable_type,
                        .pointer = value_array_variable,
                        .indices = array_to_slice(value_array_indices),
                    });

                    auto enum_value_load = create_load(module, {
                        .type = enum_type,
                        .pointer = value_array_element_pointer,
                    });

                    create_store(module, {
                        .source = enum_value_load,
                        .destination = return_value_alloca,
                        .type = enum_type,
                    });

                    create_store(module, {
                        .source = LLVMConstInt(u8_type->llvm.abi, 1, false),
                        .destination = return_boolean_alloca,
                        .type = u8_type,
                    });

                    LLVMBuildBr(module->llvm.builder, return_block);

                    LLVMPositionBuilderAtEnd(module->llvm.builder, length_mismatch_block);

                    auto inc_index_load = create_load(module, {
                        .type = u64_type,
                        .pointer = index_alloca,
                    });

                    auto inc = LLVMBuildAdd(module->llvm.builder, inc_index_load, LLVMConstInt(u64_type->llvm.abi, 1, false), "");

                    create_store(module, {
                        .source = inc,
                        .destination = index_alloca,
                        .type = u64_type,
                    });

                    LLVMBuildBr(module->llvm.builder, loop_entry_block);

                    LLVMPositionBuilderAtEnd(module->llvm.builder, loop_exit_block);

                    create_store(module, {
                        .source = LLVMConstNull(enum_type->llvm.memory),
                        .destination = return_value_alloca,
                        .type = enum_type,
                    });
                    create_store(module, {
                        .source = LLVMConstNull(u8_type->llvm.abi),
                        .destination = return_boolean_alloca,
                        .type = u8_type,
                    });
                    LLVMBuildBr(module->llvm.builder, return_block);

                    LLVMPositionBuilderAtEnd(module->llvm.builder, return_block);
                    auto value_load = create_load(module, {
                        .type = enum_type,
                        .pointer = return_value_alloca,
                        .kind = TypeKind::memory,
                    });

                    auto return_value = LLVMBuildInsertValue(module->llvm.builder, LLVMGetPoison(struct_type->llvm.memory), value_load, 0, "");
                    auto bool_load = create_load(module, {
                        .type = u8_type,
                        .pointer = return_boolean_alloca,
                    });

                    return_value = LLVMBuildInsertValue(module->llvm.builder, return_value, bool_load, 1, "");

                    LLVMBuildRet(module->llvm.builder, return_value);

                    // End of scope
                    LLVMPositionBuilderAtEnd(module->llvm.builder, insert_block);

                    enum_type->enumerator.string_to_enum_function = llvm_function;
                    enum_type->enumerator.string_to_enum_struct_type = struct_type;
                }

                auto struct_type = enum_type->enumerator.string_to_enum_struct_type;
                assert(struct_type);

                typecheck(module, expected_type, struct_type);

                auto string_type = get_slice_type(module, uint8(module));

                analyze_type(module, enum_string_value, string_type);
                value_type = struct_type;
            } break;
        case ValueId::undefined:
            {
                if (!expected_type)
                {
                    report_error();
                }

                if (expected_type->id == TypeId::void_type || expected_type->id == TypeId::noreturn)
                {
                    report_error();
                }

                value_type = expected_type;
            } break;
        case ValueId::macro_instantiation:
            {
                if (module->current_macro_declaration)
                {
                    report_error();
                }

                auto current_function = module->current_function;
                if (!current_function)
                {
                    report_error();
                }

                module->current_function = 0;

                auto current_macro_instantiation = module->current_macro_instantiation;

                auto macro_instantiation = &value->macro_instantiation;
                module->current_macro_instantiation = macro_instantiation;

                auto declaration = macro_instantiation->declaration;

                auto declaration_arguments = declaration->arguments;
                auto instantiation_declaration_arguments = arena_allocate<Argument>(module->arena, declaration_arguments.length);
                macro_instantiation->declaration_arguments = instantiation_declaration_arguments;

                LLVMMetadataRef subprogram = 0;
                if (module->has_debug_info)
                {
                    LLVMMetadataRef subroutine_type = 0;
                    auto is_local_to_unit = true;
                    auto is_definition = true;
                    LLVMDIFlags flags = {};
                    auto is_optimized = build_mode_is_optimized(module->build_mode);
                    subprogram = LLVMDIBuilderCreateFunction(module->llvm.di_builder, module->scope.llvm, (char*)declaration->name.pointer, declaration->name.length, (char*)declaration->name.pointer, declaration->name.length, module->llvm.file, macro_instantiation->scope.line, subroutine_type, is_local_to_unit, is_definition, macro_instantiation->scope.line, flags, is_optimized);
                }

                macro_instantiation->scope.llvm = subprogram;

                // First copy
                for (u64 i = 0; i < declaration_arguments.length; i += 1)
                {
                    auto& instantiation_declaration_argument = instantiation_declaration_arguments[i];
                    const auto& declaration_argument = declaration_arguments[i];
                    instantiation_declaration_argument = {
                        .variable = {
                            .initial_value = 0,
                            .type = declaration_argument.variable.type,
                            .scope = &macro_instantiation->scope,
                            .name = declaration_argument.variable.name,
                            .line = declaration_argument.variable.line,
                            .column = declaration_argument.variable.column,
                        },
                        .index = declaration_argument.index,
                    };
                }

                auto declaration_constant_arguments = declaration->constant_arguments;
                auto instantiation_constant_arguments = macro_instantiation->constant_arguments;

                for (u64 i = 0; i < declaration_constant_arguments.length; i += 1)
                {
                    const auto& declaration_constant_argument = declaration_constant_arguments[i];
                    auto& instantiation_constant_argument = instantiation_constant_arguments[i];

                    assert(declaration_constant_argument.id == instantiation_constant_argument.id);

                    instantiation_constant_argument.name = declaration_constant_argument.name;

                    switch (declaration_constant_argument.id)
                    {
                        case ConstantArgumentId::value:
                            {
                                trap();
                            } break;
                        case ConstantArgumentId::type:
                            {
                                auto declaration_type = declaration_constant_argument.type;
                                assert(declaration_type->id == TypeId::unresolved);

                                auto old_instantiation_type = instantiation_constant_argument.type;

                                auto instantiation_type = type_allocate_init(module, {
                                    .alias = {
                                        .type = old_instantiation_type,
                                        .scope = &macro_instantiation->scope,
                                        .line = macro_instantiation->line,
                                    },
                                    .id = TypeId::alias,
                                    .name = declaration_constant_argument.name,
                                });
                                instantiation_constant_argument.type = instantiation_type;
                            } break;
                    }
                }

                value_type = resolve_type(module, declaration->return_type);
                assert(value_type->id != TypeId::unresolved);
                macro_instantiation->return_type = value_type;

                for (auto& argument : macro_instantiation->declaration_arguments)
                {
                    argument.variable.type = resolve_type(module, argument.variable.type);
                }

                auto instantiation_arguments = macro_instantiation->instantiation_arguments;
                if (instantiation_arguments.length != instantiation_declaration_arguments.length)
                {
                    report_error();
                }

                if (module->has_debug_info)
                {
                    for (u64 i = 0; i < instantiation_arguments.length; i += 1)
                    {
                        auto& instantiation_argument = instantiation_arguments[i];
                        const auto& declaration_argument = instantiation_declaration_arguments[i];

                        auto argument_type = declaration_argument.variable.type;
                        assert(argument_type);
                        analyze_type(module, instantiation_argument, argument_type);
                    }

                    LLVMMetadataRef type_buffer[64];
                    auto type_count = instantiation_arguments.length + 1;

                    resolve_type_in_place_debug(module, value_type);
                    type_buffer[0] = value_type->llvm.debug;

                    for (u64 i = 0; i < instantiation_declaration_arguments.length; i += 1)
                    {
                        const auto& declaration_argument = instantiation_declaration_arguments[i];
                        auto type = declaration_argument.variable.type;
                        resolve_type_in_place_debug(module, type);
                        type_buffer[i + 1] = type->llvm.debug;
                    }

                    LLVMSetCurrentDebugLocation2(module->llvm.builder, 0);
                    LLVMDIFlags flags = {};
                    auto subroutine_type = LLVMDIBuilderCreateSubroutineType(module->llvm.di_builder, module->llvm.file, type_buffer, type_count, flags);
                    assert(macro_instantiation->scope.llvm);
                    llvm_subprogram_replace_type(subprogram, subroutine_type);
                }

                assert(!macro_instantiation->block);
                macro_instantiation->block = &arena_allocate<Block>(module->arena, 1)[0];

                copy_block(module, &macro_instantiation->scope, {
                    .source = declaration->block,
                    .destination = macro_instantiation->block,
                });

                resolve_type_in_place(module, value_type);
                typecheck(module, expected_type, value_type);

                if (!module->has_debug_info)
                {
                    for (u64 i = 0; i < instantiation_arguments.length; i += 1)
                    {
                        auto& instantiation_argument = instantiation_arguments[i];
                        const auto& declaration_argument = instantiation_declaration_arguments[i];

                        auto argument_type = declaration_argument.variable.type;
                        assert(argument_type);
                        analyze_type(module, instantiation_argument, argument_type);
                    }
                }

                // END of scope
                module->current_macro_instantiation = current_macro_instantiation;
                module->current_function = current_function;
            } break;
        default: unreachable();
    }

    assert(value_type);
    value->type = value_type;
}

fn LLVMTypeRef get_llvm_type(Type* type, TypeKind type_kind)
{
    switch (type_kind)
    {
        case TypeKind::abi:
            return type->llvm.abi;
        case TypeKind::memory:
            return type->llvm.memory;
    }
}

fn void analyze_value(Module* module, Value* value, Type* expected_type, TypeKind type_kind);

fn bool type_is_integer_backing(Type* type)
{
    switch (type->id)
    {
        case TypeId::enumerator:
        case TypeId::integer:
        case TypeId::bits:
        case TypeId::pointer:
            return true;
        default:
            return false;
    }
}

struct ValueTypePair
{
    LLVMValueRef value;
    Type* type;
};

fn ValueTypePair enter_struct_pointer_for_coerced_access(Module* module, LLVMValueRef source_value, Type* source_type, u64 destination_size)
{
    unused(module);
    assert(source_type->id == TypeId::structure && source_type->structure.fields.length > 0);
    auto first_field_type = source_type->structure.fields[0].type;
    auto first_field_size = get_byte_size(first_field_type);
    auto source_size = get_byte_size(source_type);

    if (!(first_field_size < destination_size && first_field_size < source_size))
    {
        trap();
    }

    return { source_value, source_type };
}

fn LLVMValueRef coerce_integer_or_pointer_to_integer_or_pointer(Module* module, LLVMValueRef source, Type* source_type, Type* destination_type)
{
    unused(module);
    unused(source_type);
    unused(destination_type);
    if (source_type != destination_type)
    {
        trap();
    }

    return source;
}

fn LLVMValueRef create_coerced_load(Module* module, LLVMValueRef source, Type* source_type, Type* destination_type)
{
    LLVMValueRef result = 0;

    if (type_is_abi_equal(module, source_type, destination_type))
    {
        trap();
    }
    else
    {
        auto destination_size = get_byte_size(destination_type);
        if (source_type->id == TypeId::structure)
        {
            auto src = enter_struct_pointer_for_coerced_access(module, source, source_type, destination_size);
            source = src.value;
            source_type = src.type;
        }

        if (type_is_integer_backing(source_type) && type_is_integer_backing(destination_type))
        {
            trap();
        }
        else
        {
            auto source_size = get_byte_size(source_type);

            auto is_source_type_scalable = false;
            auto is_destination_type_scalable = false;

            if (!is_source_type_scalable && !is_destination_type_scalable && source_size >= destination_size)
            {
                result = create_load(module, LoadOptions{ .type = destination_type, .pointer = source });
            }
            else
            {
                trap();
            }
        }
    }

    assert(result);

    return result;
}

fn void create_coerced_store(Module* module, LLVMValueRef source_value, Type* source_type, LLVMValueRef destination_value, Type* destination_type, u64 destination_size, bool destination_volatile)
{
    unused(destination_volatile);

    auto source_size = get_byte_size(source_type);

    if (!type_is_abi_equal(module, source_type, destination_type))
    {
        auto r = enter_struct_pointer_for_coerced_access(module, destination_value, destination_type, source_size);
        destination_value = r.value;
        destination_type = r.type;
    }

    auto is_scalable = false;

    if (is_scalable || source_size <= destination_size)
    {
        auto destination_alignment = get_byte_alignment(destination_type);

        if (source_type->id == TypeId::integer && destination_type->id == TypeId::pointer && source_size == align_forward(destination_size, destination_alignment))
        {
            trap();
        }
        else if (source_type->id == TypeId::structure)
        {
            auto fields = source_type->structure.fields;
            for (u32 i = 0; i < fields.length; i += 1)
            {
                auto& field = fields[i];
                auto gep = LLVMBuildStructGEP2(module->llvm.builder, source_type->llvm.abi, destination_value, i, "");
                auto field_value = LLVMBuildExtractValue(module->llvm.builder, source_value, i, "");
                create_store(module, {
                    .source = field_value,
                    .destination = gep,
                    .type = field.type,
                    .alignment = destination_alignment,
                });
            }
        }
        else
        {
            create_store(module, StoreOptions{
                .source = source_value,
                .destination = destination_value,
                .type = destination_type,
                .alignment = destination_alignment,
            });
        }
    }
    else if (type_is_integer_backing(source_type))
    {
        auto int_type = integer_type(module, { .bit_count = (u32)destination_size * 8, .is_signed = false });
        auto value = coerce_integer_or_pointer_to_integer_or_pointer(module, source_value, source_type, int_type);
        create_store(module, {
            .source = value,
            .destination = destination_value,
            .type = int_type,
        });
    }
    else
    {
        trap();
    }
}

struct SliceEmitResult
{
    LLVMValueRef values[2];
};

fn LLVMValueRef emit_slice_result(Module* module, SliceEmitResult slice, LLVMTypeRef slice_type)
{
    auto result = LLVMGetPoison(slice_type);
    result = LLVMBuildInsertValue(module->llvm.builder, result, slice.values[0], 0, "");
    result = LLVMBuildInsertValue(module->llvm.builder, result, slice.values[1], 1, "");
    return result;
}

fn SliceEmitResult emit_slice_expression(Module* module, Value* value)
{
    switch (value->id)
    {
        case ValueId::slice_expression:
            {
                auto value_type = value->type;
                assert(value_type);
                assert(type_is_slice(value_type));
                auto slice_pointer_type = value_type->structure.fields[0].type;
                assert(slice_pointer_type->id == TypeId::pointer);
                auto slice_element_type = slice_pointer_type->pointer.element_type;

                auto index_type = uint64(module);
                resolve_type_in_place(module, index_type);
                auto llvm_index_type = index_type->llvm.abi;
                auto index_zero = LLVMConstInt(llvm_index_type, 0, 0);

                auto array_like = value->slice_expression.array_like;
                auto start = value->slice_expression.start;
                auto end = value->slice_expression.end;

                assert(array_like->kind == ValueKind::left);
                emit_value(module, array_like, TypeKind::memory);

                auto pointer_type = array_like->type;
                assert(pointer_type->id == TypeId::pointer);
                auto sliceable_type = pointer_type->pointer.element_type;
                bool has_start = start;
                if (start && start->id == ValueId::constant_integer && start->constant_integer.value == 0)
                {
                    has_start = false;
                }

                if (start)
                {
                    emit_value(module, start, TypeKind::memory);
                }

                if (end)
                {
                    emit_value(module, end, TypeKind::memory);
                }

                switch (sliceable_type->id)
                {
                    case TypeId::pointer:
                        {
                            auto element_type = sliceable_type->pointer.element_type;
                            auto pointer_load = create_load(module, {
                                .type = sliceable_type,
                                .pointer = array_like->llvm,
                            });

                            auto slice_pointer = pointer_load;
                            if (has_start)
                            {
                                LLVMValueRef indices[] = { start->llvm };
                                slice_pointer = create_gep(module, {
                                    .type = element_type->llvm.memory,
                                    .pointer = pointer_load,
                                    .indices = array_to_slice(indices),
                                });
                            }

                            auto slice_length = end->llvm;

                            if (has_start)
                            {
                                slice_length = LLVMBuildSub(module->llvm.builder, slice_length, start->llvm, "");
                            }
                            return { slice_pointer, slice_length };
                        } break;
                    case TypeId::structure:
                        {
                            assert(sliceable_type->structure.is_slice);
                            auto slice_load = create_load(module, {
                                .type = sliceable_type,
                                .pointer = array_like->llvm,
                            });
                            auto old_slice_pointer = LLVMBuildExtractValue(module->llvm.builder, slice_load, 0, "");
                            auto slice_pointer = old_slice_pointer;

                            if (has_start)
                            {
                                LLVMValueRef indices[] = { start->llvm };
                                slice_pointer = create_gep(module, {
                                    .type = slice_element_type->llvm.memory,
                                    .pointer = old_slice_pointer,
                                    .indices = array_to_slice(indices),
                                });
                            }

                            auto slice_end = end ? end->llvm : LLVMBuildExtractValue(module->llvm.builder, slice_load, 1, "");
                            auto slice_length = slice_end;
                            if (has_start)
                            {
                                slice_length = LLVMBuildSub(module->llvm.builder, slice_end, start->llvm, "");
                            }

                            return { slice_pointer, slice_length };
                        } break;
                    case TypeId::array:
                        {
                            assert(sliceable_type->array.element_type == slice_element_type);
                            LLVMValueRef slice_pointer = array_like->llvm;
                            if (has_start)
                            {
                                LLVMValueRef indices[] = { index_zero, start->llvm };
                                slice_pointer = create_gep(module, {
                                    .type = sliceable_type->llvm.memory,
                                    .pointer = slice_pointer,
                                    .indices = array_to_slice(indices),
                                });
                            }

                            LLVMValueRef slice_length = 0;
                            if (has_start)
                            {
                                trap();
                            }
                            else if (end)
                            {
                                slice_length = end->llvm;
                            }
                            else
                            {
                                auto element_count = sliceable_type->array.element_count;
                                slice_length = LLVMConstInt(llvm_index_type, element_count, 0);
                            }

                            assert(slice_length);
                            return { slice_pointer, slice_length };
                        } break;
                    default: unreachable();
                }
            } break;
        default: unreachable();
    }
}


fn SliceEmitResult emit_string_literal(Module* module, Value* value)
{
    auto resolved_value_type = resolve_alias(module, value->type);
    switch (value->id)
    {
        case ValueId::string_literal:
            {
                bool null_terminate = true;
                auto length = value->string_literal.length;
                auto constant_string = LLVMConstStringInContext2(module->llvm.context, (char*)value->string_literal.pointer, length, !null_terminate);
                auto u8_type = uint8(module);
                resolve_type_in_place(module, u8_type);
                auto string_type = LLVMArrayType2(u8_type->llvm.abi, length + null_terminate);
                auto is_constant = true;
                LLVMValueRef before = 0;
                LLVMThreadLocalMode tlm = LLVMNotThreadLocal;
                bool externally_initialized = false;
                unsigned address_space = 0;
                auto global = llvm_module_create_global_variable(module->llvm.module, string_type, is_constant, LLVMInternalLinkage, constant_string, string_literal("conststring"), before, tlm, address_space, externally_initialized);
                LLVMSetUnnamedAddress(global, LLVMGlobalUnnamedAddr);
                auto slice_type = get_slice_type(module, u8_type);

                if (resolved_value_type->id != TypeId::structure)
                {
                    report_error();
                }

                if (!resolved_value_type->structure.is_slice)
                {
                    report_error();
                }

                if (slice_type != resolved_value_type)
                {
                    report_error();
                }

                return { global, LLVMConstInt(slice_type->structure.fields[1].type->llvm.abi, length, false) };
            } break;
        default: unreachable();
    }
}

fn LLVMValueRef emit_call(Module* module, Value* value, LLVMValueRef left_llvm, Type* left_type)
{
    switch (value->id)
    {
        case ValueId::call:
            {
                auto call = &value->call;

                auto raw_function_type = call->function_type;
                auto callable = call->callable;
                auto call_arguments = call->arguments;

                LLVMValueRef llvm_callable = 0;

                switch (callable->id)
                {
                    case ValueId::variable_reference:
                        {
                            auto variable = callable->variable_reference;
                            auto variable_type = variable->type;
                            switch (variable_type->id)
                            {
                                case TypeId::pointer:
                                    {
                                        auto element_type = variable_type->pointer.element_type;
                                        switch (element_type->id)
                                        {
                                            case TypeId::function:
                                                {
                                                    llvm_callable = create_load(module, LoadOptions{
                                                        .type = get_pointer_type(module, raw_function_type),
                                                        .pointer = variable->storage->llvm,
                                                    });
                                                } break;
                                            default: report_error();
                                        }
                                    } break;
                                case TypeId::function: llvm_callable = variable->storage->llvm; break;
                                default: report_error();
                            }
                        } break;
                    default: report_error();
                }

                assert(llvm_callable);

                LLVMValueRef llvm_abi_argument_value_buffer[64];
                LLVMTypeRef llvm_abi_argument_type_buffer[64];
                Type* abi_argument_type_buffer[64];
                AbiInformation argument_abi_buffer[64];

                u16 abi_argument_count = 0;

                bool uses_in_alloca = false;
                if (uses_in_alloca)
                {
                    trap();
                }

                LLVMValueRef llvm_indirect_return_value = 0;

                auto& return_abi = raw_function_type->function.return_abi;
                auto return_abi_kind = return_abi.flags.kind;
                switch (return_abi_kind)
                {
                    case AbiKind::indirect:
                    case AbiKind::in_alloca:
                    case AbiKind::coerce_and_expand:
                        {
                            // TODO: handle edge cases:
                            // - virtual function pointer thunk
                            // - return alloca already exists
                            LLVMValueRef pointer = 0;
                            auto semantic_return_type = return_abi.semantic_type;
                            if (left_llvm)
                            {
                                assert(left_type->pointer.element_type == semantic_return_type);
                                pointer = left_llvm;
                            }
                            else
                            {
                                trap();
                            }
                            assert(pointer);

                            auto has_sret = return_abi.flags.kind == AbiKind::indirect;
                            if (has_sret)
                            {
                                auto void_ty = void_type(module);
                                llvm_abi_argument_value_buffer[abi_argument_count] = pointer;
                                abi_argument_type_buffer[abi_argument_count] = void_ty;
                                llvm_abi_argument_type_buffer[abi_argument_count] = void_ty->llvm.abi;
                                abi_argument_count += 1;
                                llvm_indirect_return_value = pointer;
                            }
                            else if (return_abi.flags.kind == AbiKind::in_alloca)
                            {
                                trap();
                            }
                            else
                            {
                                trap();
                            }
                        } break;
                    default: break;
                }

                auto available_registers = raw_function_type->function.available_registers;

                auto declaration_semantic_argument_count = raw_function_type->function.semantic_argument_types.length;
                for (u64 call_argument_index = 0; call_argument_index < call_arguments.length; call_argument_index += 1)
                {
                    auto is_named_argument = call_argument_index < declaration_semantic_argument_count;
                    auto semantic_call_argument_value = call_arguments[call_argument_index];

                    Type* semantic_argument_type;
                    AbiInformation argument_abi;
                    Slice<LLVMTypeRef> llvm_abi_argument_type_buffer_slice = array_to_slice(llvm_abi_argument_type_buffer);
                    Slice<Type*> abi_argument_type_buffer_slice = array_to_slice(abi_argument_type_buffer);

                    if (is_named_argument)
                    {
                        argument_abi = raw_function_type->function.argument_abis[call_argument_index];
                        semantic_argument_type = argument_abi.semantic_type;
                    }
                    else
                    {
                        semantic_argument_type = semantic_call_argument_value->type;
                        argument_abi = abi_system_v_classify_argument(module, &available_registers.system_v, llvm_abi_argument_type_buffer_slice, abi_argument_type_buffer_slice, {
                            .type = resolve_alias(module, semantic_argument_type),
                            .abi_start = abi_argument_count,
                            .is_named_argument = false,
                        });
                    }

                    if (get_byte_size(semantic_argument_type) > 60 && argument_abi.flags.kind != AbiKind::indirect)
                    {
                        trap();
                    }

                    resolve_type_in_place(module, semantic_argument_type);

                    if (is_named_argument)
                    {
                        auto llvm_abi_argument_types = llvm_abi_argument_type_buffer_slice(argument_abi.abi_start)(0, argument_abi.abi_count);
                        auto destination_abi_argument_types = abi_argument_type_buffer_slice(argument_abi.abi_start)(0, argument_abi.abi_count);
                        auto source_abi_argument_types = raw_function_type->function.abi_argument_types(argument_abi.abi_start)(0, argument_abi.abi_count);
                        for (u16 i = 0; i < argument_abi.abi_count; i += 1)
                        {
                            llvm_abi_argument_types[i] = source_abi_argument_types[i]->llvm.abi;
                            destination_abi_argument_types[i] = source_abi_argument_types[i];
                        }
                    }

                    argument_abi_buffer[call_argument_index] = argument_abi;

                    if (argument_abi.padding.type)
                    {
                        trap();
                    }

                    assert(abi_argument_count == argument_abi.abi_start);
                    auto argument_abi_kind = argument_abi.flags.kind;
                    switch (argument_abi_kind)
                    {
                        case AbiKind::direct:
                        case AbiKind::extend:
                            {
                                auto coerce_to_type = argument_abi.get_coerce_to_type();
                                resolve_type_in_place(module, coerce_to_type);

                                if (coerce_to_type->id != TypeId::structure && type_is_abi_equal(module, semantic_argument_type, coerce_to_type) && argument_abi.attributes.direct.offset == 0)
                                {
                                    emit_value(module, semantic_call_argument_value, TypeKind::memory);

                                    auto evaluation_kind = get_evaluation_kind(argument_abi.semantic_type);
                                    Value* v;
                                    switch (evaluation_kind)
                                    {
                                        case EvaluationKind::scalar: v = semantic_call_argument_value; break;
                                        case EvaluationKind::aggregate: trap();
                                        case EvaluationKind::complex: trap();
                                    }

                                    if (!type_is_abi_equal(module, coerce_to_type, v->type))
                                    {
                                        trap();
                                    }

                                    llvm_abi_argument_value_buffer[abi_argument_count] = v->llvm;
                                    abi_argument_count += 1;
                                }
                                else
                                {
                                    if (coerce_to_type->id == TypeId::structure && argument_abi.flags.kind == AbiKind::direct && !argument_abi.flags.can_be_flattened)
                                    {
                                        trap();
                                    }

                                    auto evaluation_kind = get_evaluation_kind(semantic_argument_type);
                                    Value* src = 0;
                                    switch (evaluation_kind)
                                    {
                                        case EvaluationKind::scalar: trap();
                                        case EvaluationKind::aggregate: src = semantic_call_argument_value; break;
                                        case EvaluationKind::complex: trap();
                                    }
                                    assert(src);

                                    if (argument_abi.attributes.direct.offset != 0)
                                    {
                                        trap();
                                    }

                                    if (coerce_to_type->id == TypeId::structure && argument_abi.flags.kind == AbiKind::direct && argument_abi.flags.can_be_flattened)
                                    {
                                        auto source_type_is_scalable = false;
                                        if (source_type_is_scalable)
                                        {
                                            trap();
                                        }
                                        else
                                        {
                                            if (src->kind == ValueKind::right)
                                            {
                                                if (src->id == ValueId::variable_reference)
                                                {
                                                    src->type = 0;
                                                    src->kind = ValueKind::left;
                                                    analyze_type(module, src, 0);
                                                }
                                            }

                                            emit_value(module, semantic_call_argument_value, TypeKind::memory);
                                            auto destination_size = get_byte_size(coerce_to_type);
                                            auto source_size = get_byte_size(argument_abi.semantic_type);
                                            auto alignment = get_byte_alignment(argument_abi.semantic_type);

                                            LLVMValueRef source = src->llvm;
                                            if (source_size < destination_size)
                                            {
                                                trap();
                                            }

                                            auto coerce_fields = coerce_to_type->structure.fields;

                                            // TODO:
                                            assert(argument_abi.attributes.direct.offset == 0);

                                            switch (semantic_call_argument_value->kind)
                                            {
                                                case ValueKind::left:
                                                    {
                                                        for (u32 i = 0; i < (u32)coerce_fields.length; i += 1)
                                                        {
                                                            auto& field = coerce_fields[i];
                                                            auto gep = LLVMBuildStructGEP2(module->llvm.builder, coerce_to_type->llvm.memory, source, i, "");
                                                            auto maybe_undef = false;
                                                            if (maybe_undef)
                                                            {
                                                                trap();
                                                            }

                                                            auto load = create_load(module, {
                                                                .type = field.type,
                                                                .pointer = gep,
                                                                .alignment = alignment,
                                                            });
                                                            llvm_abi_argument_value_buffer[abi_argument_count] = load;
                                                            abi_argument_count += 1;
                                                        }
                                                    } break;
                                                case ValueKind::right:
                                                    {
                                                        if (type_is_abi_equal(module, coerce_to_type, semantic_argument_type))
                                                        {
                                                            for (u32 i = 0; i < (u32)coerce_fields.length; i += 1)
                                                            {
                                                                llvm_abi_argument_value_buffer[abi_argument_count] = LLVMBuildExtractValue(module->llvm.builder, source, i, "");
                                                                abi_argument_count += 1;
                                                            }
                                                        }
                                                        else
                                                        {
                                                            switch (semantic_call_argument_value->id)
                                                            {
                                                                case ValueId::aggregate_initialization:
                                                                    {
                                                                        auto is_constant = semantic_call_argument_value->aggregate_initialization.is_constant;

                                                                        if (is_constant)
                                                                        {
                                                                            bool is_constant = true;
                                                                            LLVMLinkage linkage_type = LLVMInternalLinkage;
                                                                            LLVMValueRef before = 0;
                                                                            LLVMThreadLocalMode thread_local_mode = {};
                                                                            u32 address_space = 0;
                                                                            bool externally_initialized = false;

                                                                            auto global = llvm_module_create_global_variable(module->llvm.module, semantic_argument_type->llvm.memory, is_constant, linkage_type, semantic_call_argument_value->llvm, string_literal("conststruct"), before, thread_local_mode, address_space, externally_initialized);
                                                                            LLVMSetUnnamedAddress(global, LLVMGlobalUnnamedAddr);

                                                                            auto alignment = get_byte_alignment(semantic_argument_type);
                                                                            LLVMSetAlignment(global, alignment);

                                                                            for (u32 i = 0; i < coerce_fields.length; i += 1)
                                                                            {
                                                                                auto gep = LLVMBuildStructGEP2(module->llvm.builder, coerce_to_type->llvm.abi, global, i, "");
                                                                                auto& field = coerce_fields[i];
                                                                                auto maybe_undef = false;
                                                                                if (maybe_undef)
                                                                                {
                                                                                    trap();
                                                                                }

                                                                                auto load = create_load(module, { .type = field.type, .pointer = gep, .alignment = alignment });

                                                                                llvm_abi_argument_value_buffer[abi_argument_count] = load;
                                                                                abi_argument_count += 1;
                                                                            }
                                                                        }
                                                                        else
                                                                        {
                                                                            trap();
                                                                        }
                                                                    } break;
                                                                default: trap();
                                                            }
                                                        }
                                                    } break;
                                            }
                                        }
                                    }
                                    else
                                    {
                                        assert(argument_abi.abi_count == 1);
                                        auto destination_type = coerce_to_type;

                                        LLVMValueRef v = 0;
                                        switch (src->id)
                                        {
                                            case ValueId::zero:
                                                {
                                                    trap();
                                                } break;
                                            default:
                                                {
                                                    if (src->type->id != TypeId::pointer)
                                                    {
                                                        assert(src->kind == ValueKind::right);
                                                        assert(src->type->id == TypeId::structure);
                                                        auto type = src->type;
                                                        assert(src->kind == ValueKind::right);
                                                        src->type = 0;
                                                        src->kind = ValueKind::left;
                                                        analyze_type(module, src, get_pointer_type(module, type));
                                                    }

                                                    assert(src->type->id == TypeId::pointer);
                                                    assert(src->type->llvm.abi == module->llvm.pointer_type);
                                                    emit_value(module, src, TypeKind::memory);

                                                    assert(src->type->id == TypeId::pointer);
                                                    auto source_type = src->type->pointer.element_type;
                                                    assert(source_type == argument_abi.semantic_type);
                                                    auto load = create_coerced_load(module, src->llvm, source_type, destination_type);

                                                    auto is_cmse_ns_call = false;
                                                    if (is_cmse_ns_call)
                                                    {
                                                        trap();
                                                    }

                                                    auto maybe_undef = false;
                                                    if (maybe_undef)
                                                    {
                                                        trap();
                                                    }

                                                    v = load;
                                                } break;
                                        }
                                        assert(v);

                                        llvm_abi_argument_value_buffer[abi_argument_count] = v;
                                        abi_argument_count += 1;
                                    }
                                }
                            } break;
                        case AbiKind::indirect:
                        case AbiKind::indirect_aliased:
                            {
                                auto evaluation_kind = get_evaluation_kind(semantic_argument_type);
                                auto do_continue = false;
                                if (evaluation_kind == EvaluationKind::aggregate)
                                {
                                    auto same_address_space = true;
                                    assert(argument_abi.abi_start >= raw_function_type->function.abi_argument_types.length || same_address_space);

                                    // TODO: handmade code, may contain bugs
                                    assert(argument_abi.abi_count == 1);
                                    auto abi_argument_type = abi_argument_type_buffer[argument_abi.abi_start];

                                    if (abi_argument_type == semantic_call_argument_value->type)
                                    {
                                        trap();
                                    }
                                    else if (abi_argument_type->id == TypeId::pointer && abi_argument_type->pointer.element_type == semantic_call_argument_value->type)
                                    {
                                        auto is_constant = semantic_call_argument_value->is_constant();

                                        if (is_constant)
                                        {
                                            emit_value(module, semantic_call_argument_value, TypeKind::memory);

                                            bool is_constant = true;
                                            LLVMLinkage linkage_type = LLVMInternalLinkage;
                                            LLVMValueRef before = 0;
                                            LLVMThreadLocalMode thread_local_mode = {};
                                            u32 address_space = 0;
                                            bool externally_initialized = false;

                                            auto global = llvm_module_create_global_variable(module->llvm.module, semantic_argument_type->llvm.memory, is_constant, linkage_type, semantic_call_argument_value->llvm, string_literal("conststruct"), before, thread_local_mode, address_space, externally_initialized);
                                            LLVMSetUnnamedAddress(global, LLVMGlobalUnnamedAddr);

                                            auto alignment = get_byte_alignment(semantic_argument_type);
                                            LLVMSetAlignment(global, alignment);

                                            llvm_abi_argument_value_buffer[abi_argument_count] = global;
                                            abi_argument_count += 1;
                                        }
                                        else
                                        {
                                            auto pointer_type = get_pointer_type(module, semantic_call_argument_value->type);

                                            switch (semantic_call_argument_value->id)
                                            {
                                                case ValueId::variable_reference:
                                                    {
                                                        semantic_call_argument_value->type = 0;
                                                        semantic_call_argument_value->kind = ValueKind::left;
                                                        analyze_value(module, semantic_call_argument_value, pointer_type, TypeKind::memory);
                                                        llvm_abi_argument_value_buffer[abi_argument_count] = semantic_call_argument_value->llvm;
                                                        abi_argument_count += 1;
                                                    } break;
                                                default:
                                                    {
                                                        assert(abi_argument_type->id == TypeId::pointer);
                                                        assert(abi_argument_type->pointer.element_type == semantic_call_argument_value->type);
                                                        auto alloca = create_alloca(module, {
                                                            .type = semantic_call_argument_value->type,
                                                        });
                                                        emit_assignment(module, alloca, pointer_type, semantic_call_argument_value);
                                                        llvm_abi_argument_value_buffer[abi_argument_count] = alloca;
                                                        abi_argument_count += 1;
                                                    } break;
                                            }
                                        }

                                        do_continue = true;
                                    }
                                    else
                                    {
                                        trap();
                                    }
                                }

                                if (!do_continue)
                                {
                                    trap();
                                }

                            } break;
                        case AbiKind::ignore: unreachable();
                        default: unreachable();
                    }

                    assert(abi_argument_count == argument_abi.abi_start + argument_abi.abi_count);
                }

                auto declaration_abi_argument_count = raw_function_type->function.abi_argument_types.length;

                if (raw_function_type->function.is_variable_arguments)
                {
                    assert(abi_argument_count >= declaration_abi_argument_count);
                }
                else
                {
                    assert(abi_argument_count == declaration_abi_argument_count);
                }

                assert(raw_function_type->llvm.abi);
                Slice<AbiInformation> argument_abis = { .pointer = argument_abi_buffer, .length = call_arguments.length };
                auto llvm_call = LLVMBuildCall2(module->llvm.builder, raw_function_type->llvm.abi, llvm_callable, llvm_abi_argument_value_buffer, abi_argument_count, "");
                auto attribute_list = build_attribute_list(module, {
                    .return_abi = return_abi,
                    .argument_abis = argument_abis,
                    .abi_argument_types = { .pointer = abi_argument_type_buffer, .length = abi_argument_count },
                    .abi_return_type = raw_function_type->function.abi_return_type,
                    .attributes = {},
                    .call_site = true,
                });
                LLVMSetInstructionCallConv(llvm_call, llvm_calling_convention(raw_function_type->function.calling_convention));
                llvm_call_base_set_attributes(llvm_call, attribute_list);
                switch (return_abi_kind)
                {
                    case AbiKind::ignore:
                        {
                            assert(return_abi.semantic_type == noreturn_type(module) || return_abi.semantic_type == void_type(module));
                            return llvm_call;
                        } break;
                    case AbiKind::direct:
                    case AbiKind::extend:
                        {
                            auto coerce_to_type = return_abi.get_coerce_to_type();

                            if (type_is_abi_equal(module, return_abi.semantic_type, coerce_to_type) && return_abi.attributes.direct.offset == 0)
                            {
                                auto evaluation_kind = get_evaluation_kind(coerce_to_type);

                                switch (evaluation_kind)
                                {
                                    case EvaluationKind::scalar: return llvm_call;
                                    case EvaluationKind::aggregate: break;
                                    case EvaluationKind::complex: unreachable();
                                }
                            }

                            // TODO: if
                            auto fixed_vector_type = false;
                            if (fixed_vector_type)
                            {
                                trap();
                            }

                            LLVMValueRef coerce_alloca = 0;

                            if (left_llvm)
                            {
                                assert(left_type->pointer.element_type == return_abi.semantic_type);
                                coerce_alloca = left_llvm;
                            }
                            else
                            {
                                coerce_alloca = create_alloca(module, {
                                    .type = return_abi.semantic_type,
                                    .name = string_literal("coerce"),
                                });
                            }

                            LLVMValueRef destination_pointer = coerce_alloca;
                            if (return_abi.attributes.direct.offset != 0)
                            {
                                trap();
                            }

                            auto destination_type = return_abi.semantic_type;

                            assert(return_abi.semantic_type->id == TypeId::structure);
                            if (return_abi.semantic_type->structure.fields.length > 0)
                            {
                                auto source_value = llvm_call;
                                auto source_type = raw_function_type->function.abi_return_type;
                                auto destination_size = get_byte_size(destination_type);
                                auto left_destination_size = destination_size - return_abi.attributes.direct.offset;
                                auto is_destination_volatile = false;
                                create_coerced_store(module, source_value, source_type, destination_pointer, destination_type, left_destination_size, is_destination_volatile);
                            }
                            else
                            {
                                trap();
                            }

                            assert(coerce_alloca);
                            if (left_llvm)
                            {
                                assert(destination_pointer == left_llvm);
                                return destination_pointer;
                            }
                            else
                            {
                                switch (value->kind)
                                {
                                    case ValueKind::right: return create_load(module, { .type = destination_type, .pointer = destination_pointer });
                                    case ValueKind::left: trap();
                                }
                            }
                        } break;
                    case AbiKind::indirect:
                        {
                            assert(llvm_indirect_return_value);
                            return llvm_indirect_return_value;
                        } break;
                    default: unreachable();
                }
            } break;
        default: unreachable();
    }
}

fn LLVMValueRef emit_va_arg_from_memory(Module* module, LLVMValueRef va_list_pointer, Type* va_list_struct, Type* argument_type)
{
    assert(va_list_struct->id == TypeId::structure);
    auto overflow_arg_area_pointer = LLVMBuildStructGEP2(module->llvm.builder, va_list_struct->llvm.abi, va_list_pointer, 2, "");
    auto overflow_arg_area_type = va_list_struct->structure.fields[2].type;
    auto overflow_arg_area = create_load(module, { .type = overflow_arg_area_type, .pointer = overflow_arg_area_pointer });
    if (get_byte_alignment(argument_type) > 8)
    {
        trap();
    }

    auto argument_type_size = get_byte_size(argument_type);

    auto raw_offset = align_forward(argument_type_size, 8);
    auto uint32_type = uint32(module)->llvm.abi;
    auto offset = LLVMConstInt(uint32_type, raw_offset, false);
    LLVMValueRef indices[] = {
        offset,
    };
    auto new_overflow_arg_area = create_gep(module, {
        .type = uint32_type,
        .pointer = overflow_arg_area,
        .indices = array_to_slice(indices),
        .inbounds = false,
    });
    create_store(module, {
        .source = new_overflow_arg_area,
        .destination = overflow_arg_area_pointer,
        .type = overflow_arg_area_type,
    });
    return overflow_arg_area;
}


fn LLVMValueRef emit_va_arg(Module* module, Value* value, LLVMValueRef left_llvm, Type* left_type)
{
    switch (value->id)
    {
        case ValueId::va_arg:
            {
                auto raw_va_list_type = get_va_list_type(module);

                auto va_list_value = value->va_arg.va_list;
                emit_value(module, va_list_value, TypeKind::memory);
                auto u64_type = uint64(module);
                resolve_type_in_place(module, u64_type);
                auto zero = LLVMConstNull(u64_type->llvm.memory);
                LLVMValueRef gep_indices[] = {zero, zero};
                auto va_list_value_llvm = create_gep(module, {
                    .type = raw_va_list_type->llvm.memory,
                    .pointer = va_list_value->llvm,
                    .indices = array_to_slice(gep_indices),
                });

                auto va_arg_type = value->va_arg.type;
                auto r = abi_system_v_classify_argument_type(module, va_arg_type, {});
                auto abi = r.abi;
                auto needed_registers = r.needed_registers;
                assert(abi.flags.kind != AbiKind::ignore);

                assert(raw_va_list_type->id == TypeId::array);
                auto va_list_struct = raw_va_list_type->array.element_type;
                LLVMValueRef address = 0;

                if (needed_registers.gpr == 0 && needed_registers.sse == 0)
                {
                    address = emit_va_arg_from_memory(module, va_list_value_llvm, va_list_struct, va_arg_type);
                }
                else
                {
                    auto va_list_struct_llvm = va_list_struct->llvm.memory;

                    LLVMValueRef gpr_offset_pointer = 0;
                    LLVMValueRef gpr_offset = 0;
                    if (needed_registers.gpr != 0)
                    {
                        gpr_offset_pointer = LLVMBuildStructGEP2(module->llvm.builder, va_list_struct_llvm, va_list_value_llvm, 0, "");
                        gpr_offset = create_load(module, {
                            .type = va_list_struct->structure.fields[0].type,
                            .pointer = gpr_offset_pointer,
                            .alignment = 16,
                        });
                    }
                    else
                    {
                        trap();
                    }

                    auto raw_in_regs = 48 - needed_registers.gpr * 8;
                    auto u32_type = uint32(module);
                    resolve_type_in_place(module, u32_type);
                    auto u32_llvm = u32_type->llvm.memory;
                    LLVMValueRef in_regs = 0;
                    if (needed_registers.gpr != 0)
                    {
                        in_regs = LLVMConstInt(u32_llvm, raw_in_regs, false);
                    }
                    else
                    {
                        trap();
                    }

                    if (needed_registers.gpr != 0)
                    {
                        in_regs = LLVMBuildICmp(module->llvm.builder, LLVMIntULE, gpr_offset, in_regs, "");
                    }
                    else
                    {
                        trap();
                    }

                    assert(in_regs);

                    LLVMValueRef fp_offset_pointer = 0;
                    if (needed_registers.sse)
                    {
                        trap();
                    }
                    LLVMValueRef fp_offset = 0;
                    if (needed_registers.sse)
                    {
                        trap();
                    }
                    
                    auto raw_fits_in_fp = 176 - needed_registers.sse * 16;
                    LLVMValueRef fits_in_fp = 0;
                    if (needed_registers.sse)
                    {
                        trap();
                    }

                    if (needed_registers.sse && needed_registers.gpr)
                    {
                        trap();
                    }

                    auto* in_reg_block = llvm_context_create_basic_block(module->llvm.context, string_literal("va_arg.in_reg"), 0);
                    auto* in_mem_block = llvm_context_create_basic_block(module->llvm.context, string_literal("va_arg.in_mem"), 0);
                    auto* end_block = llvm_context_create_basic_block(module->llvm.context, string_literal("va_arg.end"), 0);
                    LLVMBuildCondBr(module->llvm.builder, in_regs, in_reg_block, in_mem_block);

                    emit_block(module, in_reg_block);

                    auto reg_save_area_type = va_list_struct->structure.fields[3].type;
                    auto reg_save_area = create_load(module, {
                        .type = reg_save_area_type,
                        .pointer = LLVMBuildStructGEP2(module->llvm.builder, va_list_struct_llvm, va_list_value_llvm, 3, ""),
                        .alignment = 16,
                    });

                    LLVMValueRef register_address = 0;

                    if (needed_registers.gpr && needed_registers.sse)
                    {
                        trap();
                    }
                    else if (needed_registers.gpr)
                    {
                        auto t = reg_save_area_type->pointer.element_type;
                        resolve_type_in_place(module, t);

                        LLVMValueRef indices[] = { gpr_offset };
                        register_address = create_gep(module, {
                            .type = t->llvm.abi,
                            .pointer = reg_save_area,
                            .indices = array_to_slice(indices),
                            .inbounds = false,
                        });
                        if (get_byte_alignment(va_arg_type) > 8)
                        {
                            trap();
                        }
                    }
                    else if (needed_registers.sse == 1)
                    {
                        trap();
                    }
                    else if (needed_registers.sse == 2)
                    {
                        trap();
                    }
                    else
                    {
                        unreachable();
                    }

                    if (needed_registers.gpr)
                    {
                        auto raw_offset = needed_registers.gpr * 8;
                        auto new_offset = LLVMBuildAdd(module->llvm.builder, gpr_offset, LLVMConstInt(u32_llvm, raw_offset, false), "");
                        create_store(module, StoreOptions{
                            .source = new_offset,
                            .destination = gpr_offset_pointer,
                            .type = u32_type,
                        });
                    }

                    if (needed_registers.sse)
                    {
                        trap();
                    }

                    LLVMBuildBr(module->llvm.builder, end_block);

                    emit_block(module, in_mem_block);
                    auto memory_address = emit_va_arg_from_memory(module, va_list_value_llvm, va_list_struct, va_arg_type);

                    emit_block(module, end_block);

                    LLVMValueRef values[] = {
                        register_address,
                        memory_address,
                    };
                    LLVMBasicBlockRef blocks[] = {
                        in_reg_block,
                        in_mem_block,
                    };

                    auto phi = LLVMBuildPhi(module->llvm.builder, module->llvm.pointer_type, "");
                    LLVMAddIncoming(phi, values, blocks, array_length(values));

                    address = phi;

                    unused(fp_offset_pointer);
                    unused(fp_offset);
                    unused(raw_fits_in_fp);
                    unused(fits_in_fp);
                }

                assert(address);
                
                auto evaluation_kind = get_evaluation_kind(va_arg_type);

                LLVMValueRef result = 0;

                switch (evaluation_kind)
                {
                case EvaluationKind::scalar:
                    {
                        assert(!left_llvm);
                        assert(!left_type);
                        result = create_load(module, {
                            .type = va_arg_type,
                            .pointer = address,
                        });
                    } break;
                case EvaluationKind::aggregate:
                    {
                        if (left_llvm)
                        {
                            auto u64_type = uint64(module);
                            resolve_type_in_place(module, u64_type);
                            u64 memcpy_size = get_byte_size(va_arg_type);
                            auto alignment = get_byte_alignment(va_arg_type);
                            LLVMBuildMemCpy(module->llvm.builder, left_llvm, alignment, address, alignment, LLVMConstInt(u64_type->llvm.abi, memcpy_size, false));
                            return left_llvm;
                        }
                        else
                        {
                            trap();
                        }
                    } break;
                case EvaluationKind::complex:
                    {
                        trap();
                    } break;
                }

                assert(result);
                return result;
            } break;
        default: unreachable();
    }
}

fn LLVMValueRef emit_field_access(Module* module, Value* value, LLVMValueRef left_llvm, Type* left_type, TypeKind type_kind)
{
    unused(left_type);

    switch (value->id)
    {
        case ValueId::field_access:
            {
                auto aggregate = value->field_access.aggregate;
                auto field_name = value->field_access.field_name;

                emit_value(module, aggregate, TypeKind::memory);

                assert(aggregate->kind == ValueKind::left);
                auto aggregate_type = aggregate->type;
                assert(aggregate_type->id == TypeId::pointer);
                auto aggregate_element_type = aggregate_type->pointer.element_type;

                Type* real_aggregate_type = aggregate_element_type->id == TypeId::pointer ? aggregate_element_type->pointer.element_type : aggregate_element_type;
                auto resolved_aggregate_type = resolve_alias(module, real_aggregate_type);
                resolve_type_in_place(module, resolved_aggregate_type);
                unused(left_llvm);
                unused(left_type);
                unused(type_kind);
                LLVMValueRef v;
                if (real_aggregate_type != aggregate_element_type)
                {
                    v = create_load(module, {
                        .type = aggregate_element_type,
                        .pointer = aggregate->llvm,
                    });
                }
                else
                {
                    v = aggregate->llvm;
                }

                switch (resolved_aggregate_type->id)
                {
                    case TypeId::structure:
                    case TypeId::union_type:
                        {
                            struct StructLikeFieldAccess
                            {
                                Type* type;
                                u32 field_index;
                                LLVMTypeRef struct_type;
                            };

                            StructLikeFieldAccess field_access;
                            switch (resolved_aggregate_type->id)
                            {
                                case TypeId::structure:
                                    {
                                        u32 field_index;
                                        auto fields = resolved_aggregate_type->structure.fields;
                                        auto field_count = (u32)fields.length;
                                        for (field_index = 0; field_index < field_count; field_index += 1)
                                        {
                                            auto& field = fields[field_index];
                                            if (field_name.equal(field.name))
                                            {
                                                break;
                                            }
                                        }

                                        if (field_index == field_count)
                                        {
                                            report_error();
                                        }

                                        field_access = {
                                            .type = resolved_aggregate_type->structure.fields[field_index].type,
                                            .field_index = field_index,
                                            .struct_type = resolved_aggregate_type->llvm.memory,
                                        };
                                    } break;
                                case TypeId::union_type:
                                    {
                                        auto fields = resolved_aggregate_type->union_type.fields;
                                        u32 field_index;
                                        auto field_count = (u32)fields.length;
                                        for (field_index = 0; field_index < field_count; field_index += 1)
                                        {
                                            auto& field = fields[field_index];
                                            if (field_name.equal(field.name))
                                            {
                                                break;
                                            }
                                        }

                                        if (field_index == field_count)
                                        {
                                            report_error();
                                        }

                                        auto field_type = resolved_aggregate_type->union_type.fields[field_index].type;
                                        auto struct_type = LLVMStructTypeInContext(module->llvm.context, &field_type->llvm.memory, 1, false);
                                        assert(struct_type);

                                        field_access = {
                                            .type = field_type,
                                            .field_index = 0,
                                            .struct_type = struct_type,
                                        };
                                    } break;
                                default: unreachable();
                            }

                            auto gep = LLVMBuildStructGEP2(module->llvm.builder, field_access.struct_type, v, field_access.field_index, "");

                            if (left_llvm)
                            {
                                assert(get_evaluation_kind(field_access.type) == EvaluationKind::aggregate);
                                auto alignment = get_byte_alignment(field_access.type);
                                auto u64_type = uint64(module);
                                resolve_type_in_place(module, u64_type);
                                LLVMBuildMemCpy(module->llvm.builder, left_llvm, alignment, gep, alignment, LLVMConstInt(u64_type->llvm.abi, get_byte_size(field_access.type), false));
                                return gep;
                            }
                            else
                            {
                                switch (value->kind)
                                {
                                    case ValueKind::left:
                                        {
                                            return gep;
                                        } break;
                                    case ValueKind::right:
                                        {
                                            auto load = create_load(module, {
                                                .type = field_access.type,
                                                .pointer = gep,
                                            });
                                            return load;
                                        } break;
                                }
                            }
                        } break;
                    case TypeId::bits:
                        {
                            auto fields = resolved_aggregate_type->bits.fields;
                            u64 i;
                            for (i = 0; i < fields.length; i += 1)
                            {
                                auto& field = fields[i];
                                if (field_name.equal(field.name))
                                {
                                    break;
                                }
                            }

                            assert(i < fields.length);

                            auto& field = fields[i];
                            auto field_type = field.type;
                            resolve_type_in_place(module, field_type);

                            auto load = create_load(module, {
                                .type = resolved_aggregate_type,
                                .pointer = v,
                            });
                            auto shift = LLVMBuildLShr(module->llvm.builder, load, LLVMConstInt(resolved_aggregate_type->llvm.abi, field.offset, false), "");
                            auto trunc = LLVMBuildTrunc(module->llvm.builder, shift, field_type->llvm.abi, "");
                            if (left_llvm)
                            {
                                trap();
                            }

                            return trunc;
                        } break;
                    case TypeId::array:
                        {
                            assert(value->field_access.field_name.equal(string_literal("length")));
                            auto array_length_type = get_llvm_type(value->type, type_kind);
                            auto result = LLVMConstInt(array_length_type, resolved_aggregate_type->array.element_count, false);
                            return result;
                        } break;
                    default: unreachable();
                }

                trap();

                // auto resolved_element_type = resolve_alias(module, element_type);
                // auto base_child_type = base_type->pointer.element_type;
                // auto pointer_type = resolve_alias(module, base_child_type->id == TypeId::pointer ? base_child_type->pointer.element_type : base_type);
                // assert(pointer_type->id == TypeId::pointer);
                // auto element_type = pointer_type->pointer.element_type;
                // resolve_type_in_place(module, element_type);
                //

                // switch (resolved_element_type->id)
                // {
                //     default: unreachable();
                // }
            } break;
        default: unreachable();
    }
}

fn void emit_assignment(Module* module, LLVMValueRef left_llvm, Type* left_type, Value* right)
{
    assert(!right->llvm);
    auto pointer_type = left_type;
    auto value_type = right->type;
    assert(pointer_type);
    assert(value_type);
    resolve_type_in_place(module, pointer_type);
    resolve_type_in_place(module, value_type);

    auto resolved_pointer_type = resolve_alias(module, pointer_type);
    auto resolved_value_type = resolve_alias(module, value_type);
    assert(resolved_pointer_type->id == TypeId::pointer);
    assert(resolved_pointer_type->pointer.element_type == resolved_value_type);

    auto type_kind = TypeKind::memory;

    auto evaluation_kind = get_evaluation_kind(resolved_value_type);
    switch (evaluation_kind)
    {
        case EvaluationKind::scalar:
            {
                emit_value(module, right, type_kind);
                create_store(module, {
                    .source = right->llvm,
                    .destination = left_llvm,
                    .type = resolved_value_type,
                });
            } break;
        case EvaluationKind::aggregate:
            {
                switch (right->id)
                {
                    case ValueId::array_initialization:
                        {
                            auto values = right->array_initialization.values;
                            assert(resolved_value_type->id == TypeId::array);
                            auto uint64_type = uint64(module);
                            resolve_type_in_place(module, uint64_type);

                            if (right->array_initialization.is_constant)
                            {
                                emit_value(module, right, TypeKind::memory);

                                bool is_constant = true;
                                LLVMLinkage linkage_type = LLVMInternalLinkage;
                                LLVMValueRef before = 0;
                                LLVMThreadLocalMode thread_local_mode = {};
                                u32 address_space = 0;
                                bool externally_initialized = false;

                                auto global = llvm_module_create_global_variable(module->llvm.module, value_type->llvm.memory, is_constant, linkage_type, right->llvm, string_literal("constarray"), before, thread_local_mode, address_space, externally_initialized);

                                LLVMSetUnnamedAddress(global, LLVMGlobalUnnamedAddr);

                                auto alignment = get_byte_alignment(resolved_value_type);
                                LLVMSetAlignment(global, alignment);

                                auto element_type = resolved_value_type->array.element_type;
                                auto element_count = resolved_value_type->array.element_count;
                                assert(values.length == element_count);

                                u64 memcpy_size = get_byte_size(element_type) * element_count;
                                LLVMBuildMemCpy(module->llvm.builder, left_llvm, alignment, global, alignment, LLVMConstInt(uint64_type->llvm.abi, memcpy_size, false));
                            }
                            else
                            {
                                auto u64_zero = LLVMConstNull(uint64_type->llvm.abi);
                                auto pointer_to_element_type = get_pointer_type(module, resolved_value_type->array.element_type);

                                for (u64 i = 0; i < values.length; i += 1)
                                {
                                    LLVMValueRef indices[] = {
                                        u64_zero,
                                        LLVMConstInt(uint64_type->llvm.abi, i, false),
                                    };
                                    auto alloca_gep = create_gep(module, {
                                        .type = resolved_value_type->llvm.memory,
                                        .pointer = left_llvm,
                                        .indices = array_to_slice(indices),
                                    });

                                    emit_assignment(module, alloca_gep, pointer_to_element_type, values[i]);
                                }
                            }
                        } break;
                    case ValueId::string_literal:
                        {
                            auto string_literal = emit_string_literal(module, right);
                            auto slice_type = get_slice_type(module, uint8(module));

                            for (u32 i = 0; i < array_length(string_literal.values); i += 1)
                            {
                                auto member_pointer = LLVMBuildStructGEP2(module->llvm.builder, slice_type->llvm.abi, left_llvm, i, "");
                                auto slice_member_type = slice_type->structure.fields[i].type;
                                create_store(module, {
                                    .source = string_literal.values[i],
                                    .destination = member_pointer,
                                    .type = slice_member_type,
                                });
                            }
                        } break;
                    case ValueId::va_start:
                        {
                            assert(resolved_value_type == get_va_list_type(module));
                            assert(pointer_type->pointer.element_type == get_va_list_type(module));
                            LLVMTypeRef argument_types[] = {
                                module->llvm.pointer_type,
                            };
                            LLVMValueRef argument_values[] = {
                                left_llvm,
                            };
                            emit_intrinsic_call(module, IntrinsicIndex::va_start, array_to_slice(argument_types), array_to_slice(argument_values));
                        } break;
                    case ValueId::aggregate_initialization:
                        {
                            auto names = right->aggregate_initialization.names;
                            auto values = right->aggregate_initialization.values;
                            auto is_constant = right->aggregate_initialization.is_constant;
                            auto zero = right->aggregate_initialization.zero;
                            assert(names.length == values.length);

                            if (is_constant)
                            {
                                emit_value(module, right, TypeKind::memory);

                                LLVMLinkage linkage_type = LLVMInternalLinkage;
                                LLVMValueRef before = 0;
                                unsigned address_space = 0;
                                LLVMThreadLocalMode thread_local_mode = LLVMNotThreadLocal;
                                bool externally_initialized = false;
                                auto global = llvm_module_create_global_variable(module->llvm.module, value_type->llvm.memory, is_constant, linkage_type, right->llvm, string_literal("constarray"), before, thread_local_mode, address_space, externally_initialized);
                                LLVMSetUnnamedAddress(global, LLVMGlobalUnnamedAddr);
                                auto alignment = get_byte_alignment(value_type);
                                LLVMSetAlignment(global, alignment);
                                auto u64_type = uint64(module);
                                resolve_type_in_place(module, u64_type);
                                u64 memcpy_size = get_byte_size(value_type);
                                LLVMBuildMemCpy(module->llvm.builder, left_llvm, alignment, global, alignment, LLVMConstInt(u64_type->llvm.abi, memcpy_size, false));
                            }
                            else
                            {
                                switch (resolved_value_type->id)
                                {
                                    case TypeId::structure:
                                        {
                                            u64 max_field_index = 0;
                                            u64 field_mask = 0;
                                            auto fields = resolved_value_type->structure.fields;
                                            assert(fields.length <= 64);
                                            unused(field_mask);

                                            for (u32 initialization_index = 0; initialization_index < (u32)values.length; initialization_index += 1)
                                            {
                                                auto name = names[initialization_index];
                                                auto value = values[initialization_index];

                                                u32 declaration_index;
                                                for (declaration_index = 0; declaration_index < (u32)fields.length; declaration_index += 1)
                                                {
                                                    auto field = fields[declaration_index];

                                                    if (name.equal(field.name))
                                                    {
                                                        break;
                                                    }
                                                }

                                                assert(declaration_index < fields.length);

                                                field_mask |= 1 << declaration_index;
                                                max_field_index = MAX(max_field_index, declaration_index);
                                                auto& field = fields[declaration_index];
                                                auto destination_pointer = LLVMBuildStructGEP2(module->llvm.builder, resolved_value_type->llvm.memory, left_llvm, declaration_index, "");
                                                emit_assignment(module, destination_pointer, get_pointer_type(module, field.type), value);
                                            }

                                            if (zero)
                                            {
                                                u64 buffer_field_count = sizeof(field_mask) * 8;
                                                auto raw_end_uninitialized_field_count = clz(field_mask);
                                                auto unused_buffer_field_count = buffer_field_count - fields.length;
                                                auto end_uninitialized_field_count = raw_end_uninitialized_field_count - unused_buffer_field_count;
                                                auto initialized_field_count = __builtin_popcount(field_mask);
                                                auto uninitialized_field_count = fields.length - initialized_field_count;

                                                if (uninitialized_field_count != end_uninitialized_field_count)
                                                {
                                                    trap();
                                                }

                                                if (end_uninitialized_field_count == 0)
                                                {
                                                    report_error();
                                                }

                                                auto field_index_offset = fields.length - end_uninitialized_field_count;
                                                auto destination_pointer = LLVMBuildStructGEP2(module->llvm.builder, resolved_value_type->llvm.abi, left_llvm, field_index_offset, "");
                                                auto start_field = &fields[field_index_offset];
                                                auto memset_size = get_byte_size(resolved_value_type) - start_field->offset;
                                                auto u8_type = uint8(module);
                                                auto u64_type = uint64(module);
                                                resolve_type_in_place(module, u8_type);
                                                resolve_type_in_place(module, u64_type);
                                                LLVMBuildMemSet(module->llvm.builder, destination_pointer, LLVMConstNull(u8_type->llvm.memory), LLVMConstInt(u64_type->llvm.memory, memset_size, false), 1);
                                            }
                                        } break;
                                    case TypeId::union_type:
                                        {
                                            assert(names.length == 1);
                                            assert(values.length == 1);
                                            auto fields = resolved_value_type->union_type.fields;
                                            auto biggest_field_index = resolved_value_type->union_type.biggest_field;
                                            auto& biggest_field = fields[biggest_field_index];
                                            auto biggest_field_type = fields[biggest_field_index].type;
                                            auto value = values[0];
                                            auto field_value_type = value->type;
                                            auto field_type_size = get_byte_size(field_value_type);

                                            LLVMTypeRef struct_type;

                                            if (type_is_abi_equal(module, field_value_type, biggest_field_type))
                                            {
                                                struct_type = resolved_value_type->llvm.memory;
                                            }
                                            else
                                            {
                                                struct_type = LLVMStructTypeInContext(module->llvm.context, &field_value_type->llvm.memory, 1, false);
                                            }

                                            auto destination_pointer = LLVMBuildStructGEP2(module->llvm.builder, struct_type, left_llvm, 0, "");
                                            auto field_pointer_type = get_pointer_type(module, field_value_type);
                                            unused(biggest_field);
                                            emit_assignment(module, destination_pointer, field_pointer_type, value);

                                            auto union_size = resolved_value_type->union_type.byte_size;
                                            if (field_type_size < union_size)
                                            {
                                                trap();
                                            }
                                            else if (field_type_size > union_size)
                                            {
                                                unreachable();
                                            }
                                        } break;
                                    default: unreachable();
                                }
                            }
                        } break;
                    case ValueId::call:
                        {
                            auto result = emit_call(module, right, left_llvm, left_type);
                            assert(result == left_llvm);
                        } break;
                    case ValueId::va_arg:
                        {
                            auto result = emit_va_arg(module, right, left_llvm, left_type);
                            if (result != left_llvm)
                            {
                                trap();
                            }
                        } break;
                    case ValueId::slice_expression:
                        {
                            auto slice = emit_slice_expression(module, right);
                            auto slice_pointer_type = resolved_value_type->structure.fields[0].type;
                            create_store(module, {
                                .source = slice.values[0],
                                .destination = left_llvm,
                                .type = slice_pointer_type,
                            });

                            auto slice_length_destination = LLVMBuildStructGEP2(module->llvm.builder, resolved_value_type->llvm.abi, left_llvm, 1, "");
                            create_store(module, {
                                .source = slice.values[1],
                                .destination = slice_length_destination,
                                .type = uint64(module),
                            });
                        } break;
                    case ValueId::zero:
                        {
                            auto u8_type = uint8(module);
                            auto u64_type = uint64(module);
                            resolve_type_in_place(module, u8_type);
                            resolve_type_in_place(module, u64_type);

                            auto size = get_byte_size(resolved_value_type);
                            auto alignment = get_byte_alignment(resolved_value_type);
                            LLVMBuildMemSet(module->llvm.builder, left_llvm, LLVMConstNull(u8_type->llvm.memory), LLVMConstInt(u64_type->llvm.memory, size, false), alignment);
                        } break;
                    case ValueId::variable_reference:
                        {
                            auto* variable = right->variable_reference;
                            switch (right->kind)
                            {
                                case ValueKind::left:
                                    {
                                        trap();
                                    } break;
                                case ValueKind::right:
                                    {
                                        auto u64_type = uint64(module);
                                        resolve_type_in_place(module, u64_type);
                                        auto memcpy_size = get_byte_size(resolved_value_type);
                                        auto alignment = get_byte_alignment(resolved_value_type);
                                        LLVMBuildMemCpy(module->llvm.builder, left_llvm, alignment, variable->storage->llvm, alignment, LLVMConstInt(u64_type->llvm.abi, memcpy_size, false));
                                    } break;
                            }
                        } break;
                    case ValueId::string_to_enum:
                        {
                            emit_value(module, right, TypeKind::memory);

                            auto enum_type = right->string_to_enum.type;
                            auto s2e_struct_type = enum_type->enumerator.string_to_enum_struct_type;
                            create_store(module, {
                                .source = right->llvm,
                                .destination = left_llvm,
                                .type = s2e_struct_type,
                            });
                        } break;
                    case ValueId::undefined:
                        {
                            // TODO: do something?
                        } break;
                    case ValueId::macro_instantiation:
                        {
                            emit_macro_instantiation(module, right);
                            auto size = get_byte_size(resolved_value_type);
                            auto alignment = get_byte_alignment(resolved_value_type);
                            auto u64_type = uint64(module);
                            resolve_type_in_place(module, u64_type);
                            LLVMBuildMemCpy(module->llvm.builder, left_llvm, alignment, right->macro_instantiation.return_alloca, alignment, LLVMConstInt(u64_type->llvm.abi, size, false));
                        } break;
                    case ValueId::unary:
                    case ValueId::select:
                        {
                            emit_value(module, right, TypeKind::memory);
                            create_store(module, {
                                .source = right->llvm,
                                .destination = left_llvm,
                                .type = resolved_value_type,
                            });
                        } break;
                    case ValueId::field_access:
                        {
                            auto value = emit_field_access(module, right, left_llvm, left_type, TypeKind::memory);
                            right->llvm = value;
                        } break;
                    default: unreachable();
                }
            } break;
        default: unreachable();
    }
}

fn LLVMValueRef emit_binary(Module* module, LLVMValueRef left, Type* left_type, LLVMValueRef right, Type* right_type, BinaryId id, Type* resolved_value_type)
{
    switch (resolved_value_type->id)
    {
        case TypeId::integer:
            {
                switch (id)
                {
                    case BinaryId::shift_right:
                        if (resolved_value_type->integer.is_signed)
                        {
                            return LLVMBuildAShr(module->llvm.builder, left, right, "");
                        }
                        else
                        {
                            return LLVMBuildLShr(module->llvm.builder, left, right, "");
                        }
                        break;
                    case BinaryId::div:
                        if (resolved_value_type->integer.is_signed)
                        {
                            return LLVMBuildSDiv(module->llvm.builder, left, right, "");
                        }
                        else
                        {
                            return LLVMBuildUDiv(module->llvm.builder, left, right, "");
                        }
                        break;
                    case BinaryId::rem:
                        if (resolved_value_type->integer.is_signed)
                        {
                            return LLVMBuildSRem(module->llvm.builder, left, right, "");
                        }
                        else
                        {
                            return LLVMBuildURem(module->llvm.builder, left, right, "");
                        }
                        break;
                    case BinaryId::compare_equal:
                    case BinaryId::compare_not_equal:
                    case BinaryId::compare_greater:
                    case BinaryId::compare_less:
                    case BinaryId::compare_greater_equal:
                    case BinaryId::compare_less_equal:
                        {
                            LLVMIntPredicate predicate;
                            assert(left_type == right_type);
                            auto left_signed = type_is_signed(left_type);
                            auto right_signed = type_is_signed(right_type);
                            assert(left_signed == right_signed);
                            auto is_signed = left_signed;

                            switch (id)
                            {
                                case BinaryId::compare_equal: predicate = LLVMIntEQ; break;
                                case BinaryId::compare_not_equal: predicate = LLVMIntNE; break;
                                case BinaryId::compare_greater: predicate = is_signed ? LLVMIntSGT : LLVMIntUGT; break;
                                case BinaryId::compare_less: predicate = is_signed ? LLVMIntSLT : LLVMIntULT; break;
                                case BinaryId::compare_greater_equal: predicate = is_signed ? LLVMIntSGE : LLVMIntUGE; break;
                                case BinaryId::compare_less_equal: predicate = is_signed ? LLVMIntSLE : LLVMIntULE; break;
                                default: unreachable();
                            }
                            return LLVMBuildICmp(module->llvm.builder, predicate, left, right, "");
                        } break;
                    case BinaryId::add: return LLVMBuildAdd(module->llvm.builder, left, right, ""); break;
                    case BinaryId::sub: return LLVMBuildSub(module->llvm.builder, left, right, ""); break;
                    case BinaryId::mul: return LLVMBuildMul(module->llvm.builder, left, right, ""); break;
                    case BinaryId::logical_and:
                    case BinaryId::bitwise_and: return LLVMBuildAnd(module->llvm.builder, left, right, ""); break;
                    case BinaryId::logical_or:
                    case BinaryId::bitwise_or: return LLVMBuildOr(module->llvm.builder, left, right, ""); break;
                    case BinaryId::bitwise_xor: return LLVMBuildXor(module->llvm.builder, left, right, ""); break;
                    case BinaryId::shift_left: return LLVMBuildShl(module->llvm.builder, left, right, ""); break;
                    default: unreachable();
                }
            } break;
        case TypeId::pointer:
            {
                auto element_type = resolved_value_type->pointer.element_type;
                resolve_type_in_place(module, element_type);

                if (id != BinaryId::add && id != BinaryId::sub)
                {
                    report_error();
                }

                LLVMValueRef index = right;
                if (id == BinaryId::sub)
                {
                    index = LLVMBuildNeg(module->llvm.builder, index, "");
                }

                LLVMValueRef indices[] = { index };

                return create_gep(module, {
                        .type = element_type->llvm.abi,
                        .pointer = left,
                        .indices = array_to_slice(indices),
                        });
            } break;
        default: unreachable();
    }
}

fn void emit_local_storage(Module* module, Variable* variable)
{
    assert(!variable->storage);
    auto value_type = variable->type;
    resolve_type_in_place(module, value_type);
    auto pointer_type = get_pointer_type(module, value_type);
    auto storage = new_value(module);
    assert(variable->name.pointer);
    assert(variable->name.length);
    auto alloca = create_alloca(module, {
        .type = value_type,
        .name = variable->name,
    });
    *storage = Value{
        .type = pointer_type,
        .id = ValueId::local,
        .llvm = alloca,
    };
    variable->storage = storage;
}

fn LLVMMetadataRef null_expression(Module* module)
{
    return LLVMDIBuilderCreateExpression(module->llvm.di_builder, 0, 0);
}

fn void end_debug_local(Module* module, Variable* variable, LLVMMetadataRef llvm_local)
{
    auto debug_location = LLVMDIBuilderCreateDebugLocation(module->llvm.context, variable->line, variable->column, variable->scope->llvm, module->llvm.inlined_at);
    LLVMSetCurrentDebugLocation2(module->llvm.builder, debug_location);
    auto basic_block = LLVMGetInsertBlock(module->llvm.builder);
    assert(basic_block);
    LLVMDIBuilderInsertDeclareRecordAtEnd(module->llvm.di_builder, variable->storage->llvm, llvm_local, null_expression(module), debug_location, basic_block);
}

fn void emit_local_variable(Module* module, Local* local)
{
    emit_local_storage(module, &local->variable);
    assert(local->variable.storage);

    if (module->has_debug_info)
    {
        auto debug_type = local->variable.type->llvm.debug;
        assert(debug_type);
        bool always_preserve = true;
        LLVMDIFlags flags = {};

        auto scope = local->variable.scope->llvm;
        auto bit_alignment = get_byte_alignment(local->variable.storage->type->pointer.element_type) * 8;
        auto local_variable = LLVMDIBuilderCreateAutoVariable(module->llvm.di_builder, scope, (char*)local->variable.name.pointer, local->variable.name.length, module->llvm.file, local->variable.line, debug_type, always_preserve, flags, bit_alignment);

        end_debug_local(module, &local->variable, local_variable);
    }
}

fn void emit_argument(Module* module, Argument* argument)
{
    emit_local_storage(module, &argument->variable);
    assert(argument->variable.storage);

    if (module->has_debug_info)
    {
        auto debug_type = argument->variable.type->llvm.debug;
        assert(debug_type);
        auto scope = argument->variable.scope->llvm;
        auto always_preserve = true;
        LLVMDIFlags flags = {};
        auto argument_variable = LLVMDIBuilderCreateParameterVariable(module->llvm.di_builder, scope, (char*)argument->variable.name.pointer, argument->variable.name.length, argument->index, module->llvm.file, argument->variable.line, debug_type, always_preserve, flags);

        end_debug_local(module, &argument->variable, argument_variable);
    }
}

fn void emit_macro_instantiation(Module* module, Value* value)
{
    switch (value->id)
    {
        case ValueId::macro_instantiation:
            {
                auto current_function = module->current_function;
                if (!current_function)
                {
                    report_error();
                }
                module->current_function = 0;

                auto old_macro_instantiation = module->current_macro_instantiation;
                assert(!old_macro_instantiation);
                auto macro_instantiation = &value->macro_instantiation;
                module->current_macro_instantiation = macro_instantiation;


                for (Value* instantiation_argument: macro_instantiation->instantiation_arguments)
                {
                    emit_value(module, instantiation_argument, TypeKind::abi);
                }

                LLVMMetadataRef caller_debug_location = 0;
                if (module->has_debug_info)
                {
                    assert(!module->llvm.inlined_at);
                    caller_debug_location = LLVMDIBuilderCreateDebugLocation(module->llvm.context, macro_instantiation->line, macro_instantiation->column, macro_instantiation->scope.parent->llvm, 0);
                }
                auto older_inlined_at = module->llvm.inlined_at;
                assert(!older_inlined_at);
                module->llvm.inlined_at = caller_debug_location;

                auto llvm_function = current_function->variable.storage->llvm;
                auto* entry_block = llvm_context_create_basic_block(module->llvm.context, string_literal("macro.entry"), llvm_function);

                LLVMBuildBr(module->llvm.builder, entry_block);
                LLVMPositionBuilderAtEnd(module->llvm.builder, entry_block);

                LLVMValueRef return_alloca = 0;
                auto return_type = macro_instantiation->return_type;
                if (return_type->id != TypeId::void_type && return_type->id != TypeId::noreturn)
                {
                    return_alloca = create_alloca(module, {
                        .type = return_type,
                        .name = string_literal("macro.return"),
                    });
                }
                assert(!macro_instantiation->return_alloca);
                macro_instantiation->return_alloca = return_alloca;

                auto* return_block = llvm_context_create_basic_block(module->llvm.context, string_literal("macro.return_block"), llvm_function);
                assert(!macro_instantiation->return_block);
                macro_instantiation->return_block = return_block;

                auto declaration_arguments = macro_instantiation->declaration_arguments;
                auto instantiation_arguments = macro_instantiation->instantiation_arguments;
                assert(declaration_arguments.length == instantiation_arguments.length);

                for (u64 i = 0; i < declaration_arguments.length; i += 1)
                {
                    auto* declaration_argument = &declaration_arguments[i];
                    auto* instantiation_argument = instantiation_arguments[i];

                    emit_argument(module, declaration_argument);

                    auto type = declaration_argument->variable.type;
                    auto resolved_type = resolve_alias(module, type);
                    auto evaluation_kind = get_evaluation_kind(resolved_type);
                    auto llvm_instantiation_argument = instantiation_argument->llvm;
                    auto llvm_declaration_argument = declaration_argument->variable.storage->llvm;
                    switch (evaluation_kind)
                    {
                        case EvaluationKind::scalar:
                            {
                                create_store(module, {
                                    .source = llvm_instantiation_argument,
                                    .destination = llvm_declaration_argument,
                                    .type = type,
                                });
                            } break;
                        default:
                            trap();
                    }
                }
                
                analyze_block(module, macro_instantiation->block);

                if (LLVMGetInsertBlock(module->llvm.builder))
                {
                    LLVMBuildBr(module->llvm.builder, return_block);
                }

                LLVMPositionBuilderAtEnd(module->llvm.builder, return_block);

                // END OF SCOPE
                if (module->has_debug_info)
                {
                    LLVMSetCurrentDebugLocation2(module->llvm.builder, caller_debug_location);
                }
                module->llvm.inlined_at = older_inlined_at;
                module->current_macro_instantiation = old_macro_instantiation;
                module->current_function = current_function;
            } break;
        default: unreachable();
    }
}


fn void analyze_statement(Module* module, Scope* scope, Statement* statement, u32* last_line, u32* last_column, LLVMMetadataRef* last_debug_location);

fn void analyze_block(Module* module, Block* block)
{
    if (module->has_debug_info)
    {
        auto lexical_block = LLVMDIBuilderCreateLexicalBlock(module->llvm.di_builder, block->scope.parent->llvm, module->llvm.file, block->scope.line, block->scope.column);
        block->scope.llvm = lexical_block;
    }

    u32 last_line = 0;
    u32 last_column = 0;
    LLVMMetadataRef last_debug_location = 0;

    for (auto* statement = block->first_statement; statement; statement = statement->next)
    {
        analyze_statement(module, &block->scope, statement, &last_line, &last_column, &last_debug_location);
    }
}

fn void emit_value(Module* module, Value* value, TypeKind type_kind)
{
    assert(value->type);
    assert(!value->llvm);
    auto resolved_value_type = resolve_alias(module, value->type);
    resolve_type_in_place(module, resolved_value_type);

    auto must_be_constant = !module->current_function && !module->current_macro_instantiation;

    LLVMValueRef llvm_value = 0;
    switch (value->id)
    {
        case ValueId::constant_integer:
            {
                auto llvm_integer_type = get_llvm_type(resolved_value_type, type_kind);
                llvm_value = LLVMConstInt(llvm_integer_type, value->constant_integer.value, value->constant_integer.is_signed);
            } break;
        case ValueId::unary:
            {
                auto unary_value = value->unary.value;
                assert(!unary_value->llvm);
                auto unary_id = value->unary.id;
                auto resolved_unary_type = resolve_alias(module, unary_value->type);
                emit_value(module, unary_value, type_kind);
                if (unary_id == UnaryId::truncate || unary_id == UnaryId::enum_name)
                {
                    type_kind = TypeKind::abi;
                }
                auto destination_type = get_llvm_type(resolved_value_type, type_kind);
                assert(destination_type);
                auto llvm_unary_value = unary_value->llvm;
                assert(llvm_unary_value);

                switch (unary_id)
                {
                    case UnaryId::minus:
                        {
                            if (value->unary.value->is_constant())
                            {
                                llvm_value = LLVMConstNeg(llvm_unary_value);
                            }
                            else
                            {
                                llvm_value = LLVMBuildNeg(module->llvm.builder, llvm_unary_value, "");
                            }
                        } break;
                    case UnaryId::plus:
                        {
                            trap();
                        } break;
                    case UnaryId::ampersand:
                        {
                            assert(resolved_value_type == resolved_unary_type);
                            llvm_value = llvm_unary_value;
                        } break;
                    case UnaryId::exclamation:
                        {
                            if (resolved_value_type == resolved_unary_type)
                            {
                                llvm_value = LLVMBuildNot(module->llvm.builder, llvm_unary_value, "");
                            }
                            else
                            {
                                switch (resolved_unary_type->id)
                                {
                                    case TypeId::pointer:
                                        {
                                            llvm_value = LLVMBuildICmp(module->llvm.builder, LLVMIntEQ, llvm_unary_value, LLVMConstNull(resolved_unary_type->llvm.abi), "");
                                        } break;
                                    default: report_error();
                                }
                            }
                        } break;
                    case UnaryId::tilde:
                        {
                            trap();
                        } break;
                    case UnaryId::enum_name:
                        {
                            assert(type_kind == TypeKind::abi);
                            auto enum_type = resolved_unary_type;
                            assert(enum_type->id == TypeId::enumerator);
                            auto enum_to_string = enum_type->enumerator.enum_to_string_function;
                            assert(enum_to_string);
                            auto call = LLVMBuildCall2(module->llvm.builder, LLVMGlobalGetValueType(enum_to_string), enum_to_string, &llvm_unary_value, 1, "");
                            LLVMSetInstructionCallConv(call, LLVMFastCallConv);
                            llvm_value = call;
                        } break;
                    case UnaryId::extend:
                        {
                            assert(resolved_unary_type->id == TypeId::integer);
                            if (resolved_unary_type->integer.is_signed)
                            {
                                llvm_value = LLVMBuildSExt(module->llvm.builder, llvm_unary_value, destination_type, "");
                            }
                            else
                            {
                                llvm_value = LLVMBuildZExt(module->llvm.builder, llvm_unary_value, destination_type, "");
                            }
                        } break;
                    case UnaryId::truncate:
                        {
                            if (type_kind != TypeKind::abi)
                            {
                                assert(resolved_value_type->llvm.abi == resolved_value_type->llvm.memory);
                            }

                            llvm_value = LLVMBuildTrunc(module->llvm.builder, llvm_unary_value, destination_type, "");
                        } break;
                    case UnaryId::pointer_cast:
                    case UnaryId::int_from_enum:
                        {
                            llvm_value = llvm_unary_value;
                        } break;
                    case UnaryId::int_from_pointer:
                        {
                            llvm_value = LLVMBuildPtrToInt(module->llvm.builder, llvm_unary_value, resolved_value_type->llvm.abi, "");
                        } break;
                    case UnaryId::va_end:
                        {
                            LLVMTypeRef argument_types[] = { module->llvm.pointer_type };
                            LLVMValueRef argument_values[] = { llvm_unary_value };
                            llvm_value = emit_intrinsic_call(module, IntrinsicIndex::va_end, array_to_slice(argument_types), array_to_slice(argument_values));
                        } break;
                    case UnaryId::bitwise_not:
                        {
                            llvm_value = LLVMBuildNot(module->llvm.builder, llvm_unary_value, "");
                        } break;
                    case UnaryId::dereference:
                        {
                            switch (value->kind)
                            {
                                case ValueKind::right:
                                    {
                                        auto pointer_type = unary_value->type;
                                        assert(pointer_type->id == TypeId::pointer);
                                        auto child_type = resolve_alias(module, pointer_type->pointer.element_type);
                                        assert(child_type == resolved_value_type);
                                        auto load = create_load(module, LoadOptions{
                                            .type = child_type,
                                            .pointer = unary_value->llvm,
                                            .kind = type_kind,
                                        });
                                        llvm_value = load;
                                    } break;
                                case ValueKind::left:
                                    trap();
                            }
                        } break;
                    case UnaryId::pointer_from_int:
                        {
                            llvm_value = LLVMBuildIntToPtr(module->llvm.builder, llvm_unary_value, resolved_value_type->llvm.abi, "");
                        } break;
                }
            } break;
        case ValueId::unary_type:
            {
                auto unary_type = value->unary_type.type;
                auto unary_type_id = value->unary_type.id;

                resolve_type_in_place(module, unary_type);

                switch (unary_type_id)
                {
                    case UnaryTypeId::align_of:
                        {
                            assert(resolved_value_type->id == TypeId::integer);
                            auto constant_integer = LLVMConstInt(resolved_value_type->llvm.abi, get_byte_alignment(unary_type), false);
                            llvm_value = constant_integer;
                        } break;
                    case UnaryTypeId::byte_size:
                        {
                            assert(resolved_value_type->id == TypeId::integer);
                            auto constant_integer = LLVMConstInt(resolved_value_type->llvm.abi, get_byte_size(unary_type), false);
                            llvm_value = constant_integer;
                        } break;
                    case UnaryTypeId::integer_max:
                        {
                            assert(unary_type->id == TypeId::integer);
                            auto is_signed = unary_type->integer.is_signed;
                            auto max_value = integer_max_value(resolved_value_type->integer.bit_count, is_signed);
                            auto constant_integer = LLVMConstInt(resolved_value_type->llvm.abi, max_value, is_signed);
                            llvm_value = constant_integer;
                        } break;
                }
            } break;
        case ValueId::binary:
            {
                auto binary_id = value->binary.id;
                bool is_shorcircuiting = binary_is_shortcircuiting(binary_id);
                Value* values[2] = { value->binary.left, value->binary.right };

                if (is_shorcircuiting)
                {
                    enum class ShortcircuitingOperation
                    {
                        boolean_and,
                        boolean_or,
                    };

                    ShortcircuitingOperation shorcircuiting_op;
                    switch (binary_id)
                    {
                        case BinaryId::logical_and_shortcircuit:
                            shorcircuiting_op = ShortcircuitingOperation::boolean_and;
                            break;
                        case BinaryId::logical_or_shortcircuit:
                            shorcircuiting_op = ShortcircuitingOperation::boolean_or;
                            break;
                        default:
                            unreachable();
                    }

                    auto* left = value->binary.left;
                    if (left->llvm)
                    {
                        assert(false); // TODO: check if this if is really necessary
                    }
                    else
                    {
                        emit_value(module, left, TypeKind::abi);
                    }

                    auto left_llvm = left->llvm;

                    LLVMValueRef left_condition = 0;

                    switch (left->type->id)
                    {
                        case TypeId::integer:
                            {
                                switch (left->type->integer.bit_count)
                                {
                                    case 1:
                                        left_condition = left_llvm;
                                        break;
                                    default: trap();
                                }
                            } break;
                        default: trap();
                    }

                    assert(left_condition);

                    auto llvm_function = module->current_function->variable.storage->llvm;
                    assert(llvm_function);

                    auto current_basic_block = LLVMGetInsertBlock(module->llvm.builder);
                    
                    auto* right_block = llvm_context_create_basic_block(module->llvm.context, string_literal("shortcircuit.right"), llvm_function);
                    auto* end_block = llvm_context_create_basic_block(module->llvm.context, string_literal("shortcircuit.end"), llvm_function);

                    LLVMBasicBlockRef true_block;
                    LLVMBasicBlockRef false_block;

                    switch (shorcircuiting_op)
                    {
                        case ShortcircuitingOperation::boolean_and:
                            true_block = right_block;
                            false_block = end_block;
                            break;
                        case ShortcircuitingOperation::boolean_or:
                            true_block = end_block;
                            false_block = right_block;
                            break;
                    }

                    LLVMBuildCondBr(module->llvm.builder, left_condition, true_block, false_block);

                    LLVMPositionBuilderAtEnd(module->llvm.builder, right_block);

                    auto* right = value->binary.right;
                    if (right->llvm)
                    {
                        assert(false); // TODO: check if this if is really necessary
                    }
                    else
                    {
                        emit_value(module, right, TypeKind::abi);
                    }

                    auto right_llvm = right->llvm;

                    LLVMValueRef right_condition = 0;

                    switch (right->type->id)
                    {
                        case TypeId::integer:
                            {
                                switch (right->type->integer.bit_count)
                                {
                                    case 1:
                                        right_condition = right_llvm;
                                        break;
                                    default: trap();
                                }
                            } break;
                        default: trap();
                    }

                    assert(right_condition);

                    LLVMBuildBr(module->llvm.builder, end_block);

                    LLVMPositionBuilderAtEnd(module->llvm.builder, end_block);

                    auto boolean_type = uint1(module);
                    resolve_type_in_place(module, boolean_type);
                    auto boolean = boolean_type->llvm.abi;
                    

                    LLVMValueRef incoming_left = 0;

                    switch (shorcircuiting_op)
                    {
                        case ShortcircuitingOperation::boolean_and:
                            incoming_left = LLVMConstNull(boolean);
                            break;
                        case ShortcircuitingOperation::boolean_or:
                            incoming_left = LLVMConstInt(boolean, 1, false);
                            break;
                    }

                    assert(incoming_left);
                    
                    LLVMValueRef incoming_values[] = {
                        incoming_left,
                        right_condition,
                    };

                    LLVMBasicBlockRef blocks[] = {
                        current_basic_block,
                        right_block,
                    };
                    static_assert(array_length(incoming_values) == array_length(blocks));

                    auto phi = LLVMBuildPhi(module->llvm.builder, boolean, "");
                    LLVMAddIncoming(phi, incoming_values, blocks, array_length(blocks));

                    llvm_value = phi;

                    switch (type_kind)
                    {
                        case TypeKind::abi:
                            break;
                        case TypeKind::memory:
                            trap();
                    }
                }
                else
                {
                    LLVMValueRef llvm_values[2];
                    for (u64 i = 0; i < array_length(values); i += 1)
                    {
                        auto* binary_value = values[i];
                        if (binary_value->llvm)
                        {
                            assert(false); // TODO: check if this if is really necessary
                        }
                        else
                        {
                            emit_value(module, binary_value, TypeKind::abi);
                        }

                        llvm_values[i] = binary_value->llvm;
                    }

                    llvm_value = emit_binary(module, llvm_values[0], values[0]->type, llvm_values[1], values[1]->type, value->binary.id, resolved_value_type);
                }
            } break;
        case ValueId::variable_reference:
            {
                auto* variable = value->variable_reference;

                auto resolved_variable_value_type = resolve_alias(module, variable->type);
                auto resolved_variable_pointer_type = resolve_alias(module, variable->storage->type);

                switch (value->kind)
                {
                    case ValueKind::left:
                        {
                            if (resolved_variable_pointer_type == resolved_value_type)
                            {
                                llvm_value = variable->storage->llvm;
                            }
                            else
                            {
                                trap();
                            }
                        } break;
                    case ValueKind::right:
                        {
                            if (resolved_variable_value_type != resolved_value_type)
                            {
                                report_error();
                            }

                            if (must_be_constant)
                            {
                                if (variable->scope->kind != ScopeKind::global)
                                {
                                    report_error();
                                }

                                llvm_value = variable->initial_value->llvm;
                                assert(llvm_value);
                            }
                            else
                            {
                                assert(get_byte_size(resolved_value_type) <= 16);

                                auto evaluation_kind = get_evaluation_kind(resolved_value_type);
                                switch (evaluation_kind)
                                {
                                case EvaluationKind::scalar:
                                case EvaluationKind::aggregate:
                                    {
                                        llvm_value = create_load(module, {
                                            .type = resolved_value_type,
                                            .pointer = variable->storage->llvm,
                                        });
                                    } break;
                                case EvaluationKind::complex:
                                    trap();
                                }
                            }
                        } break;
                }
            } break;
        case ValueId::call:
            {
                auto call = emit_call(module, value, 0, 0);
                llvm_value = call;
            } break;
        case ValueId::array_initialization:
            {
                auto values = value->array_initialization.values;
                auto element_count = values.length;

                if (value->array_initialization.is_constant)
                {
                    assert(value->kind == ValueKind::right);
                    auto element_type = resolved_value_type->array.element_type;
                    LLVMValueRef value_buffer[64];

                    resolve_type_in_place(module, element_type);

                    for (u64 i = 0; i < element_count; i += 1)
                    {
                        auto* v = values[i];
                        emit_value(module, v, TypeKind::memory);
                        value_buffer[i] = v->llvm;
                    }

                    auto constant_array = LLVMConstArray2(element_type->llvm.memory, value_buffer, element_count);
                    llvm_value = constant_array;
                }
                else
                {
                    switch (value->kind)
                    {
                        case ValueKind::right:
                            {
                                trap();
                            } break;
                        case ValueKind::left:
                            {
                                assert(resolved_value_type->id == TypeId::pointer);
                                auto array_type = resolved_value_type->pointer.element_type;
                                assert(array_type->id == TypeId::array);
                                auto alloca = create_alloca(module, {
                                    .type = array_type,
                                });

                                auto pointer_to_element_type = get_pointer_type(module, array_type->array.element_type);
                                auto u64_type = uint64(module);
                                resolve_type_in_place(module, u64_type);
                                auto llvm_u64_type = u64_type->llvm.abi;
                                auto u64_zero = LLVMConstNull(llvm_u64_type);

                                LLVMTypeRef llvm_array_type = array_type->llvm.memory;

                                for (u64 i = 0; i < values.length; i += 1)
                                {
                                    LLVMValueRef indices[] = {
                                        u64_zero,
                                        LLVMConstInt(llvm_u64_type, i, false),
                                    };
                                    auto alloca_gep = create_gep(module, {
                                        .type = llvm_array_type,
                                        .pointer = alloca,
                                        .indices = array_to_slice(indices),
                                    });
                                    auto value = values[i];
                                    emit_assignment(module, alloca_gep, pointer_to_element_type, value);
                                }

                                llvm_value = alloca;
                            } break;
                    }
                }
            } break;
        case ValueId::array_expression:
            {
                auto* array_like = value->array_expression.array_like;
                auto* index = value->array_expression.index;

                switch (array_like->kind)
                {
                    case ValueKind::left:
                        {
                            emit_value(module, array_like, TypeKind::memory);
                            emit_value(module, index, TypeKind::memory);

                            auto array_like_type = array_like->type;
                            assert(array_like_type->id == TypeId::pointer);
                            auto pointer_element_type = array_like_type->pointer.element_type;

                            switch (pointer_element_type->id) 
                            {
                                case TypeId::array:
                                    {
                                        auto array_type = pointer_element_type;

                                        auto uint64_type = uint64(module);
                                        resolve_type_in_place(module, uint64_type);
                                        auto zero_index = LLVMConstNull(uint64_type->llvm.abi);
                                        LLVMValueRef indices[] = { zero_index, index->llvm };
                                        auto gep = create_gep(module, {
                                            .type = array_type->llvm.memory,
                                            .pointer = array_like->llvm,
                                            .indices = array_to_slice(indices),
                                        });
                                        auto element_type = array_type->array.element_type;

                                        switch (value->kind)
                                        {
                                            case ValueKind::left:
                                                llvm_value = gep;
                                                break;
                                            case ValueKind::right:
                                                llvm_value = create_load(module, LoadOptions{
                                                    .type = element_type,
                                                    .pointer = gep,
                                                });
                                                break;
                                        }
                                    } break;
                                case TypeId::structure:
                                    {
                                        auto slice_type = pointer_element_type;
                                        assert(slice_type->structure.is_slice);
                                        auto slice_pointer_type = slice_type->structure.fields[0].type;
                                        auto slice_element_type = slice_pointer_type->pointer.element_type;
                                        resolve_type_in_place(module, slice_element_type);

                                        auto pointer_load = create_load(module, {
                                            .type = slice_pointer_type,
                                            .pointer = array_like->llvm,
                                        });
                                        LLVMValueRef indices[1] = {
                                            index->llvm,
                                        };
                                        auto gep = create_gep(module, {
                                            .type = slice_element_type->llvm.memory,
                                            .pointer = pointer_load,
                                            .indices = array_to_slice(indices),
                                        });

                                        switch (value->kind)
                                        {
                                            case ValueKind::left:
                                                llvm_value = gep;
                                                break;
                                            case ValueKind::right:
                                                llvm_value = create_load(module, LoadOptions{
                                                    .type = slice_element_type,
                                                    .pointer = gep,
                                                });
                                                break;
                                        }
                                    } break;
                                case TypeId::pointer:
                                    {
                                        auto element_type = pointer_element_type->pointer.element_type;
                                        // TODO: consider not emitting the and doing straight GEP?
                                        auto pointer_load = create_load(module, {
                                            .type = pointer_element_type,
                                            .pointer = array_like->llvm,
                                        });
                                        LLVMValueRef indices[] = { index->llvm };
                                        auto gep = create_gep(module, {
                                            .type = element_type->llvm.memory,
                                            .pointer = pointer_load,
                                            .indices = array_to_slice(indices),
                                        });

                                        llvm_value = gep;

                                        if (value->kind == ValueKind::right)
                                        {
                                            llvm_value = create_load(module, {
                                                .type = element_type,
                                                .pointer = gep,
                                            });
                                        }
                                    } break;
                                default: unreachable();
                            }
                        } break;
                    case ValueKind::right:
                        {
                            trap();
                        } break;
                }
            } break;
        case ValueId::enum_literal:
            {
                assert(resolved_value_type->id == TypeId::enumerator);
                auto enum_name = value->enum_literal;
                bool found = false;
                u64 i;
                for (i = 0; i < resolved_value_type->enumerator.fields.length; i += 1)
                {
                    auto& field = resolved_value_type->enumerator.fields[i];
                    if (enum_name.equal(field.name))
                    {
                        found = true;
                        break;
                    }
                }

                if (!found)
                {
                    report_error();
                }

                auto& field = resolved_value_type->enumerator.fields[i];
                auto llvm_type = get_llvm_type(resolved_value_type, type_kind);
                llvm_value = LLVMConstInt(llvm_type, field.value, type_is_signed(resolved_value_type));
            } break;
        case ValueId::trap:
            {
                auto call = emit_intrinsic_call(module, IntrinsicIndex::trap, {}, {});
                LLVMBuildUnreachable(module->llvm.builder);
                LLVMClearInsertionPosition(module->llvm.builder);
                llvm_value = call;
            } break;
        case ValueId::field_access:
            {
                llvm_value = emit_field_access(module, value, 0, 0, type_kind);
            } break;
        case ValueId::slice_expression:
            {
                auto slice = emit_slice_expression(module, value);
                llvm_value = emit_slice_result(module, slice, resolved_value_type->llvm.abi);
            } break;
        case ValueId::va_arg:
            {
                llvm_value = emit_va_arg(module, value, 0, 0);
            } break;
        case ValueId::aggregate_initialization:
            {
                auto names = value->aggregate_initialization.names;
                auto values = value->aggregate_initialization.values;
                assert(names.length == values.length);
                auto is_constant = value->aggregate_initialization.is_constant;
                auto zero = value->aggregate_initialization.zero;

                switch (resolved_value_type->id)
                {
                    case TypeId::structure:
                        {
                            auto fields = resolved_value_type->structure.fields;

                            if (is_constant)
                            {
                                LLVMValueRef constant_buffer[64];
                                u32 constant_count = (u32)values.length;

                                for (u64 i = 0; i < values.length; i += 1)
                                {
                                    auto* value = values[i];
                                    emit_value(module, value, TypeKind::memory);
                                    auto llvm_value = value->llvm;
                                    assert(llvm_value);
                                    assert(LLVMIsAConstant(llvm_value));
                                    constant_buffer[i] = llvm_value;
                                }


                                if (zero)
                                {
                                    if (values.length == fields.length)
                                    {
                                        unreachable();
                                    }

                                    for (u64 i = values.length; i < fields.length; i += 1)
                                    {
                                        auto& field = fields[i];
                                        auto field_type = field.type;
                                        resolve_type_in_place(module, field_type);
                                        constant_buffer[i] = LLVMConstNull(field_type->llvm.memory);
                                        constant_count += 1;
                                    }
                                }

                                assert(constant_count == fields.length);

                                llvm_value = LLVMConstNamedStruct(get_llvm_type(resolved_value_type, type_kind), constant_buffer, constant_count);
                            }
                            else
                            {
                                trap();
                            }
                        } break;
                    case TypeId::union_type:
                        {
                            trap();
                        } break;
                    case TypeId::bits:
                        {
                            auto fields = resolved_value_type->bits.fields;
                            Type* backing_type = resolved_value_type->bits.backing_type;
                            resolve_type_in_place(module, backing_type);
                            auto abi_type = get_llvm_type(backing_type, type_kind);

                            if (is_constant)
                            {
                                u64 bits_value = 0;

                                for (u32 initialization_index = 0; initialization_index < values.length; initialization_index += 1)
                                {
                                    auto value = values[initialization_index];
                                    auto name = names[initialization_index];

                                    u32 declaration_index;
                                    for (declaration_index = 0; declaration_index < fields.length; declaration_index += 1)
                                    {
                                        auto& field = fields[declaration_index];

                                        if (name.equal(field.name))
                                        {
                                            break;
                                        }
                                    }

                                    if (declaration_index == fields.length)
                                    {
                                        unreachable();
                                    }

                                    const auto& field = fields[declaration_index];
                                    u64 field_value;
                                    switch (value->id)
                                    {
                                        case ValueId::constant_integer:
                                            {
                                                field_value = value->constant_integer.value;
                                            } break;
                                        default: unreachable();
                                    }

                                    bits_value |= field_value << field.offset;
                                }

                                llvm_value = LLVMConstInt(abi_type, bits_value, false);
                            }
                            else
                            {
                                llvm_value = LLVMConstNull(abi_type);

                                for (u32 initialization_index = 0; initialization_index < values.length; initialization_index += 1)
                                {
                                    auto value = values[initialization_index];
                                    auto name = names[initialization_index];

                                    u32 declaration_index;
                                    for (declaration_index = 0; declaration_index < fields.length; declaration_index += 1)
                                    {
                                        auto& field = fields[declaration_index];

                                        if (name.equal(field.name))
                                        {
                                            break;
                                        }
                                    }

                                    if (declaration_index == fields.length)
                                    {
                                        unreachable();
                                    }

                                    const auto& field = fields[declaration_index];

                                    emit_value(module, value, TypeKind::memory);

                                    auto extended = LLVMBuildZExt(module->llvm.builder, value->llvm, abi_type, "");
                                    auto shl = LLVMBuildShl(module->llvm.builder, extended, LLVMConstInt(abi_type, field.offset, false), "");
                                    auto or_value = LLVMBuildOr(module->llvm.builder, llvm_value, shl, "");
                                    llvm_value = or_value;
                                }
                            }
                        } break;
                    default: unreachable();
                }
            } break;
        case ValueId::zero:
            {
                llvm_value = LLVMConstNull(get_llvm_type(resolved_value_type, type_kind));
            } break;
        case ValueId::select:
            {
                auto condition = value->select.condition;
                auto true_value = value->select.true_value;
                auto false_value = value->select.false_value;
                emit_value(module, condition, TypeKind::abi);
                LLVMValueRef llvm_condition = condition->llvm;
                auto condition_type = condition->type;

                switch (condition_type->id)
                {
                    case TypeId::integer:
                        {
                            if (condition_type->integer.bit_count != 1)
                            {
                                trap();
                            }
                        } break;
                    default: trap();
                }

                emit_value(module, true_value, type_kind);
                emit_value(module, false_value, type_kind);

                llvm_value = LLVMBuildSelect(module->llvm.builder, llvm_condition, true_value->llvm, false_value->llvm, "");
            } break;
        case ValueId::unreachable:
            {
                llvm_value = LLVMBuildUnreachable(module->llvm.builder);
                LLVMClearInsertionPosition(module->llvm.builder);
            } break;
        case ValueId::string_to_enum:
            {
                auto enum_type = value->string_to_enum.type;
                auto string_value = value->string_to_enum.string;
                emit_value(module, string_value, TypeKind::memory);
                auto llvm_string_value = string_value->llvm;

                auto s2e = enum_type->enumerator.string_to_enum_function;
                auto first_field = LLVMBuildExtractValue(module->llvm.builder, llvm_string_value, 0, "");
                auto second_field = LLVMBuildExtractValue(module->llvm.builder, llvm_string_value, 1, "");
                LLVMValueRef fields[] = {
                    first_field,
                    second_field,
                };
                auto call = LLVMBuildCall2(module->llvm.builder, LLVMGlobalGetValueType(s2e), s2e, fields, array_length(fields), "");
                LLVMSetInstructionCallConv(call, LLVMFastCallConv);
                llvm_value = call;
            } break;
        case ValueId::string_literal:
            {
                assert(type_is_slice(resolved_value_type));
                auto string_literal = emit_string_literal(module, value);
                llvm_value = emit_slice_result(module, string_literal, resolved_value_type->llvm.abi);
            } break;
        case ValueId::macro_instantiation:
            {
                emit_macro_instantiation(module, value);

                auto macro_instantiation = &value->macro_instantiation;
                auto return_type = macro_instantiation->return_type;
                auto return_alloca = macro_instantiation->return_alloca;

                // TODO: more professional
                switch (return_type->id)
                {
                    case TypeId::void_type:
                    case TypeId::noreturn:
                        {
                            return;
                        }
                    default:
                        {
                            llvm_value = create_load(module, {
                                .type = return_type,
                                .pointer = return_alloca,
                                .kind = type_kind,
                            });
                        } break;
                }
            } break;
        case ValueId::undefined:
            {
                llvm_value = LLVMGetPoison(get_llvm_type(resolved_value_type, type_kind));
            } break;
        default: unreachable();
    }

    assert(llvm_value);
    value->llvm = llvm_value;
}

fn void analyze_value(Module* module, Value* value, Type* expected_type, TypeKind type_kind)
{
    analyze_type(module, value, expected_type);
    emit_value(module, value, type_kind);
}

fn void analyze_statement(Module* module, Scope* scope, Statement* statement, u32* last_line, u32* last_column, LLVMMetadataRef* last_debug_location)
{
    Global* parent_function_global;
    if (module->current_function)
    {
        parent_function_global = module->current_function;
    }
    else if (module->current_macro_instantiation)
    {
        parent_function_global = module->current_macro_instantiation->instantiation_function;
    }
    else
    {
        report_error();
    }

    auto* llvm_function = parent_function_global->variable.storage->llvm;
    assert(llvm_function);

    if (module->has_debug_info)
    {
        if (statement->line != *last_line || statement->column != *last_column)
        {
            auto new_location = LLVMDIBuilderCreateDebugLocation(module->llvm.context, statement->line, statement->column, scope->llvm, module->llvm.inlined_at);
            *last_debug_location = new_location;
            LLVMSetCurrentDebugLocation2(module->llvm.builder, new_location);
            *last_line = statement->line;
            *last_column = statement->column;
        }
    }

    switch (statement->id)
    {
        case StatementId::return_st:
            {
                auto return_value = statement->return_st;

                if (module->current_function)
                {
                    assert(!module->current_macro_instantiation);
                    auto& function_type = parent_function_global->variable.storage->type->pointer.element_type->function;
                    auto& return_abi = function_type.return_abi;

                    switch (return_abi.semantic_type->id)
                    {
                        case TypeId::void_type:
                            {
                                if (return_value)
                                {
                                    report_error();
                                }
                            } break;
                        case TypeId::noreturn:
                            {
                                report_error();
                            } break;
                        default:
                            {
                                if (module->has_debug_info)
                                {
                                    LLVMSetCurrentDebugLocation2(module->llvm.builder, *last_debug_location);
                                }

                                auto return_alloca = module->current_function->variable.storage->function.llvm.return_alloca;
                                if (!return_alloca)
                                {
                                    report_error();
                                }

                                if (!return_value)
                                {
                                    report_error();
                                }

                                analyze_type(module, return_value, return_abi.semantic_type);
                                auto pointer_type = get_pointer_type(module, return_abi.semantic_type);
                                emit_assignment(module, return_alloca, pointer_type, return_value);
                            } break;
                    }

                    auto return_block = module->current_function->variable.storage->function.llvm.return_block;
                    LLVMBuildBr(module->llvm.builder, return_block);
                    LLVMClearInsertionPosition(module->llvm.builder);
                }
                else if (module->current_macro_instantiation)
                {
                    auto macro_instantiation = module->current_macro_instantiation;
                    auto return_type = macro_instantiation->return_type;
                    assert(return_type);
                    analyze_type(module, return_value, return_type);
                    emit_assignment(module, macro_instantiation->return_alloca, get_pointer_type(module, return_type), return_value);
                    LLVMBuildBr(module->llvm.builder, macro_instantiation->return_block);
                    LLVMClearInsertionPosition(module->llvm.builder);
                }
                else
                {
                    report_error();
                }
            } break;
        case StatementId::local:
            {
                auto local = statement->local;
                auto expected_type = local->variable.type;
                assert(!local->variable.storage);
                analyze_type(module, local->variable.initial_value, expected_type);
                local->variable.type = expected_type ? expected_type : local->variable.initial_value->type;
                assert(local->variable.type);
                if (expected_type)
                {
                    assert(expected_type == local->variable.type);
                }
                emit_local_variable(module, local);
                emit_assignment(module, local->variable.storage->llvm, local->variable.storage->type, local->variable.initial_value);
            } break;
        case StatementId::if_st:
            {
                auto* taken_block = llvm_context_create_basic_block(module->llvm.context, string_literal("if.taken"), llvm_function);
                auto* not_taken_block = llvm_context_create_basic_block(module->llvm.context, string_literal("if.not_taken"), llvm_function);
                auto* exit_block = llvm_context_create_basic_block(module->llvm.context, string_literal("if.exit"), llvm_function);

                auto condition = statement->if_st.condition;
                analyze_value(module, condition, 0, TypeKind::abi);
                auto condition_type = condition->type;

                LLVMValueRef llvm_condition = 0;
                assert(condition_type->id == TypeId::integer || condition_type->id == TypeId::pointer);

                llvm_condition = condition->llvm;

                if (!(condition_type->id == TypeId::integer && condition_type->integer.bit_count == 1))
                {
                    llvm_condition = LLVMBuildICmp(module->llvm.builder, LLVMIntNE, llvm_condition, LLVMConstNull(condition_type->llvm.abi), "");
                }

                assert(llvm_condition);

                LLVMBuildCondBr(module->llvm.builder, llvm_condition, taken_block, not_taken_block);
                LLVMPositionBuilderAtEnd(module->llvm.builder, taken_block);

                analyze_statement(module, scope, statement->if_st.if_statement, last_line, last_column, last_debug_location);

                if (LLVMGetInsertBlock(module->llvm.builder))
                {
                    LLVMBuildBr(module->llvm.builder, exit_block);
                }

                LLVMPositionBuilderAtEnd(module->llvm.builder, not_taken_block);
                auto else_statement = statement->if_st.else_statement;
                if (else_statement)
                {
                    analyze_statement(module, scope, else_statement, last_line, last_column, last_debug_location);
                }

                if (LLVMGetInsertBlock(module->llvm.builder))
                {
                    LLVMBuildBr(module->llvm.builder, exit_block);
                }

                LLVMPositionBuilderAtEnd(module->llvm.builder, exit_block);
            } break;
        case StatementId::block:
            {
                analyze_block(module, statement->block);
            } break;
        case StatementId::expression:
            {
                analyze_value(module, statement->expression, 0, TypeKind::memory);
            } break;
        case StatementId::while_st:
            {
                auto* entry_block = llvm_context_create_basic_block(module->llvm.context, string_literal("while.entry"), llvm_function);
                LLVMBuildBr(module->llvm.builder, entry_block);
                LLVMPositionBuilderAtEnd(module->llvm.builder, entry_block);

                auto body_block = llvm_context_create_basic_block(module->llvm.context, string_literal("while.body"), llvm_function);
                auto continue_block = llvm_context_create_basic_block(module->llvm.context, string_literal("while.continue"), llvm_function);
                auto exit_block = llvm_context_create_basic_block(module->llvm.context, string_literal("while.exit"), llvm_function);

                auto previous_continue_block = module->llvm.continue_block;
                auto previous_exit_block = module->llvm.exit_block;
                module->llvm.continue_block = continue_block;
                module->llvm.exit_block = exit_block;

                auto condition = statement->while_st.condition;
                auto block = statement->while_st.block;

                if (condition->is_constant())
                {
                    switch (condition->id)
                    {
                        case ValueId::constant_integer:
                            {
                                if (condition->constant_integer.value == 0)
                                {
                                    report_error();
                                }
                            } break;
                        default: unreachable();
                    }

                    LLVMBuildBr(module->llvm.builder, body_block);
                }
                else
                {
                    analyze_value(module, condition, 0, TypeKind::abi);

                    auto boolean = uint1(module);

                    LLVMValueRef llvm_condition = condition->llvm;
                    auto condition_type = condition->type;
                    if (condition_type != boolean)
                    {
                        switch (condition_type->id)
                        {
                            case TypeId::integer:
                                {
                                    llvm_condition = LLVMBuildICmp(module->llvm.builder, LLVMIntNE, llvm_condition, LLVMConstNull(condition_type->llvm.abi), "");
                                } break;
                            default: unreachable();
                        }
                    }

                    LLVMBuildCondBr(module->llvm.builder, llvm_condition, body_block, exit_block);
                }

                LLVMPositionBuilderAtEnd(module->llvm.builder, body_block);

                analyze_block(module, block);

                if (LLVMGetInsertBlock(module->llvm.builder))
                {
                    LLVMBuildBr(module->llvm.builder, continue_block);
                }

                LLVMPositionBuilderAtEnd(module->llvm.builder, continue_block);

                LLVMBuildBr(module->llvm.builder, entry_block);

                if (llvm_value_use_empty((LLVMValueRef)body_block))
                {
                    trap();
                }

                if (llvm_value_use_empty((LLVMValueRef)exit_block))
                {
                    trap();
                }

                LLVMPositionBuilderAtEnd(module->llvm.builder, exit_block);

                module->llvm.continue_block = previous_continue_block;
                module->llvm.exit_block = previous_exit_block;
            } break;
        case StatementId::assignment:
            {
                auto left = statement->assignment.left;
                auto right = statement->assignment.right;
                auto id = statement->assignment.id;
                analyze_value(module, left, 0, TypeKind::memory);

                auto left_type = left->type;
                if (left_type->id != TypeId::pointer)
                {
                    report_error();
                }
                auto element_type = left_type->pointer.element_type;
                auto left_llvm = left->llvm;

                switch (id)
                {
                    case StatementAssignmentId::assign:
                        {
                            analyze_type(module, right, element_type);
                            emit_assignment(module, left_llvm, left_type, right);
                        } break;
                    case StatementAssignmentId::assign_add:
                    case StatementAssignmentId::assign_sub:
                    case StatementAssignmentId::assign_mul:
                    case StatementAssignmentId::assign_div:
                    case StatementAssignmentId::assign_rem:
                    case StatementAssignmentId::assign_shift_left:
                    case StatementAssignmentId::assign_shift_right:
                    case StatementAssignmentId::assign_and:
                    case StatementAssignmentId::assign_or:
                    case StatementAssignmentId::assign_xor:
                        {
                            auto evaluation_kind = get_evaluation_kind(element_type);
                            assert(evaluation_kind == EvaluationKind::scalar);
                            auto load = create_load(module, {
                                .type = element_type,
                                .pointer = left_llvm,
                                .kind = TypeKind::abi,
                            });
                            analyze_value(module, right, element_type, TypeKind::abi);
                            auto a = load;
                            auto b = right->llvm;

                            BinaryId binary_id;
                            switch (id)
                            {
                                case StatementAssignmentId::assign: unreachable();
                                case StatementAssignmentId::assign_add: binary_id = BinaryId::add; break;
                                case StatementAssignmentId::assign_sub: binary_id = BinaryId::sub; break;
                                case StatementAssignmentId::assign_mul: binary_id = BinaryId::mul; break;
                                case StatementAssignmentId::assign_div: binary_id = BinaryId::div; break;
                                case StatementAssignmentId::assign_rem: binary_id = BinaryId::rem; break;
                                case StatementAssignmentId::assign_shift_left: binary_id = BinaryId::shift_left; break;
                                case StatementAssignmentId::assign_shift_right: binary_id = BinaryId::shift_right; break;
                                case StatementAssignmentId::assign_and: binary_id = BinaryId::bitwise_and; break;
                                case StatementAssignmentId::assign_or: binary_id = BinaryId::bitwise_or; break;
                                case StatementAssignmentId::assign_xor: binary_id = BinaryId::bitwise_xor; break;
                            }

                            auto op = emit_binary(module, a, element_type, b, right->type, binary_id, element_type);

                            create_store(module, {
                                .source = op,
                                .destination = left_llvm,
                                .type = element_type,
                            });
                        } break;
                }
            } break;
        case StatementId::switch_st:
            {
                auto* exit_block = llvm_context_create_basic_block(module->llvm.context, string_literal("switch.exit"), llvm_function);

                auto discriminant = statement->switch_st.discriminant;
                auto clauses = statement->switch_st.clauses;
                analyze_value(module, discriminant, 0, TypeKind::abi);
                
                auto discriminant_type = discriminant->type;

                switch (discriminant_type->id)
                {
                    case TypeId::enumerator:
                        {
                            u32 invalid_clause_index = ~(u32)0;
                            u32 else_clause_index = invalid_clause_index;
                            u32 discriminant_case_count = 0;

                            for (u64 i = 0; i < clauses.length; i += 1)
                            {
                                auto& clause = clauses[i];
                                clause.basic_block = llvm_context_create_basic_block(module->llvm.context, clause.values.length == 0 ? string_literal("switch.else_case_block") : string_literal("switch.case_block"), llvm_function);
                                discriminant_case_count += clause.values.length;

                                if (clause.values.length == 0)
                                {
                                    if (else_clause_index != invalid_clause_index)
                                    {
                                        report_error();
                                    }

                                    else_clause_index = i;
                                }
                                else
                                {
                                    for (auto value: clause.values)
                                    {
                                        analyze_value(module, value, discriminant_type, TypeKind::abi);
                                        if (!value->is_constant())
                                        {
                                            report_error();
                                        }
                                    }
                                }
                            }

                            LLVMBasicBlockRef else_block;
                            if (else_clause_index != invalid_clause_index)
                            {
                                else_block = clauses[else_clause_index].basic_block;
                            }
                            else
                            {
                                else_block = llvm_context_create_basic_block(module->llvm.context, string_literal("switch.else_case_block"), llvm_function);
                            }

                            auto switch_instruction = LLVMBuildSwitch(module->llvm.builder, discriminant->llvm, else_block, discriminant_case_count);
                            bool all_blocks_terminated = true;

                            for (auto& clause : clauses)
                            {
                                for (auto value : clause.values)
                                {
                                    LLVMAddCase(switch_instruction, value->llvm, clause.basic_block);
                                }

                                LLVMPositionBuilderAtEnd(module->llvm.builder, clause.basic_block);

                                analyze_block(module, clause.block);

                                if (LLVMGetInsertBlock(module->llvm.builder))
                                {
                                    all_blocks_terminated = false;
                                    LLVMBuildBr(module->llvm.builder, exit_block);
                                    LLVMClearInsertionPosition(module->llvm.builder);
                                }
                            }

                            if (else_clause_index == invalid_clause_index)
                            {
                                LLVMPositionBuilderAtEnd(module->llvm.builder, else_block);
                                LLVMBuildUnreachable(module->llvm.builder);
                                LLVMClearInsertionPosition(module->llvm.builder);
                            }

                            LLVMPositionBuilderAtEnd(module->llvm.builder, exit_block);

                            if (all_blocks_terminated)
                            {
                                LLVMBuildUnreachable(module->llvm.builder);
                                LLVMClearInsertionPosition(module->llvm.builder);
                            }
                        } break;
                    default: trap();
                }
            } break;
        case StatementId::for_each:
            {
                if (module->has_debug_info)
                {
                    auto lexical_block = LLVMDIBuilderCreateLexicalBlock(module->llvm.di_builder, statement->for_each.scope.parent->llvm, module->llvm.file, statement->for_each.scope.line, statement->for_each.scope.column);
                    statement->for_each.scope.llvm = lexical_block;
                }

                auto index_type = uint64(module);
                resolve_type_in_place(module, index_type);
                auto index_zero = LLVMConstNull(index_type->llvm.abi);

                auto* entry_block = llvm_context_create_basic_block(module->llvm.context, string_literal("for_each.entry"), llvm_function);
                auto* body_block = llvm_context_create_basic_block(module->llvm.context, string_literal("for_each.body"), llvm_function);
                auto* continue_block = llvm_context_create_basic_block(module->llvm.context, string_literal("for_each.continue"), llvm_function);
                auto* exit_block = llvm_context_create_basic_block(module->llvm.context, string_literal("for_each.exit"), llvm_function);

                auto previous_continue_block = module->llvm.continue_block;
                auto previous_exit_block = module->llvm.exit_block;

                module->llvm.continue_block = continue_block;
                module->llvm.exit_block = exit_block;

                auto left_values = statement->for_each.left_values;
                auto right_values = statement->for_each.right_values;

                switch (statement->for_each.kind)
                {
                    case ForEachKind::slice:
                        {
                            assert(left_values.length == right_values.length);

                            Local* local = statement->for_each.first_local;

                            for (u64 i = 0; i < right_values.length; i += 1, local = local->next)
                            {
                                auto kind = left_values[i];
                                auto right = right_values[i];
                                assert(right->kind == ValueKind::left);
                                analyze_type(module, right, 0);

                                auto pointer_type = right->type;
                                if (pointer_type->id != TypeId::pointer)
                                {
                                    report_error();
                                }

                                auto aggregate_type = pointer_type->pointer.element_type;

                                Type* child_type = 0;

                                switch (aggregate_type->id)
                                {
                                    case TypeId::array:
                                        {
                                            child_type = aggregate_type->array.element_type;
                                        } break;
                                    case TypeId::structure:
                                        {
                                            if (!aggregate_type->structure.is_slice)
                                            {
                                                report_error();
                                            }
                                            child_type = aggregate_type->structure.fields[0].type->pointer.element_type;
                                        } break;
                                    default: trap();
                                }

                                assert(child_type);
                                assert(!local->variable.type);

                                Type* local_type = 0;

                                switch (kind)
                                {
                                    case ValueKind::left: local_type = get_pointer_type(module, child_type); break;
                                    case ValueKind::right: local_type = child_type; break;
                                }

                                assert(local_type);

                                local->variable.type = local_type;

                                emit_local_variable(module, local);
                                emit_value(module, right, TypeKind::memory);
                            }

                            assert(!local);

                            LLVMValueRef length_value = 0;

                            // TODO: make it right
                            for (auto value : right_values)
                            {
                                auto pointer_type = value->type;
                                if (pointer_type->id != TypeId::pointer)
                                {
                                    report_error();
                                }

                                auto aggregate_type = pointer_type->pointer.element_type;
                                switch (aggregate_type->id)
                                {
                                    case TypeId::array:
                                        {
                                            length_value = LLVMConstInt(index_type->llvm.abi, aggregate_type->array.element_count, false);
                                        } break;
                                    case TypeId::structure:
                                        {
                                            assert(aggregate_type->structure.is_slice);

                                            auto gep = LLVMBuildStructGEP2(module->llvm.builder, aggregate_type->llvm.abi, value->llvm, 1, "slice.length.pointer");
                                            auto load = create_load(module, {
                                                .type = index_type,
                                                .pointer = gep,
                                            });
                                            length_value = load;
                                        } break;
                                    default: unreachable();
                                }

                                break;
                            }

                            assert(length_value);

                            auto index_alloca = create_alloca(module, { .type = index_type, .name = string_literal("for_each.index")  });
                            create_store(module, { .source = index_zero, .destination = index_alloca, .type = index_type });

                            LLVMBuildBr(module->llvm.builder, entry_block);

                            LLVMPositionBuilderAtEnd(module->llvm.builder, entry_block);

                            auto header_index_load = create_load(module, { .type = index_type, .pointer = index_alloca });
                            auto index_compare = LLVMBuildICmp(module->llvm.builder, LLVMIntULT, header_index_load, length_value, "");
                            LLVMBuildCondBr(module->llvm.builder, index_compare, body_block, exit_block);

                            LLVMPositionBuilderAtEnd(module->llvm.builder, body_block);
                            auto body_index_load = create_load(module, { .type = index_type, .pointer = index_alloca });

                            local = statement->for_each.first_local;

                            for (u64 i = 0; i < right_values.length; i += 1, local = local->next)
                            {
                                auto kind = left_values[i];
                                auto right = right_values[i];

                                auto aggregate_type = right->type->pointer.element_type;

                                LLVMValueRef element_pointer_value = 0;

                                switch (aggregate_type->id)
                                {
                                    case TypeId::array:
                                        {
                                            LLVMValueRef indices[] = {
                                                index_zero,
                                                body_index_load,
                                            };
                                            element_pointer_value = create_gep(module, {
                                                .type = right->type->pointer.element_type->llvm.memory,
                                                .pointer = right->llvm,
                                                .indices = array_to_slice(indices),
                                            });
                                        } break;
                                    case TypeId::structure:
                                        {
                                            assert(aggregate_type->structure.is_slice);

                                            auto load = create_load(module, {
                                                .type = aggregate_type,
                                                .pointer = right->llvm,
                                            });
                                            auto extract_pointer = LLVMBuildExtractValue(module->llvm.builder, load, 0, "");

                                            LLVMValueRef indices[] = {
                                                body_index_load,
                                            };
                                            auto gep = create_gep(module, {
                                                .type = aggregate_type->structure.fields[0].type->pointer.element_type->llvm.memory,
                                                .pointer = extract_pointer,
                                                .indices = array_to_slice(indices),
                                            });
                                            element_pointer_value = gep;
                                        } break;
                                    default: unreachable();
                                }

                                assert(element_pointer_value);

                                auto local_type = local->variable.type;

                                switch (kind)
                                {
                                    case ValueKind::right:
                                        {
                                            auto evaluation_kind = get_evaluation_kind(local_type);
                                            if (evaluation_kind == EvaluationKind::scalar || (aggregate_type->id == TypeId::structure && aggregate_type->structure.is_slice))
                                            {
                                                auto load = create_load(module, {
                                                    .type = local_type,
                                                    .pointer = element_pointer_value,
                                                });

                                                create_store(module, {
                                                    .source = load,
                                                    .destination = local->variable.storage->llvm,
                                                    .type = local_type,
                                                });
                                            }
                                            else
                                            {
                                                trap();
                                            }
                                        } break;
                                    case ValueKind::left:
                                        {
                                            create_store(module, {
                                                .source = element_pointer_value,
                                                .destination = local->variable.storage->llvm,
                                                .type = local_type,
                                            });
                                        } break;
                                }
                            }

                            analyze_statement(module, &statement->for_each.scope, statement->for_each.predicate, last_line, last_column, last_debug_location);

                            if (LLVMGetInsertBlock(module->llvm.builder))
                            {
                                LLVMBuildBr(module->llvm.builder, continue_block);
                            }

                            LLVMPositionBuilderAtEnd(module->llvm.builder, continue_block);

                            auto continue_index_load = create_load(module, { .type = index_type, .pointer = index_alloca });
                            auto inc = LLVMBuildAdd(module->llvm.builder, continue_index_load, LLVMConstInt(index_type->llvm.abi, 1, false), "");
                            create_store(module, { .source = inc, .destination = index_alloca, .type = index_type });

                            LLVMBuildBr(module->llvm.builder, entry_block);

                            LLVMPositionBuilderAtEnd(module->llvm.builder, exit_block);
                        } break;
                    case ForEachKind::range:
                        {
                            Local* local = statement->for_each.first_local;
                            // Assert there is only one
                            assert(local);
                            assert(!local->next);
                            assert(!local->variable.type);

                            assert(left_values.length == 1);

                            if (right_values.length == 2)
                            {
                                auto start = right_values[0];
                                auto end = right_values[1];

                                Type* local_type = 0;

                                switch (start->id)
                                {
                                    case ValueId::constant_integer:
                                        {
                                            switch (end->id)
                                            {
                                                case ValueId::constant_integer:
                                                    {
                                                        auto start_signed = start->constant_integer.is_signed;
                                                        auto end_signed = end->constant_integer.is_signed;
                                                        auto is_signed = !(!start_signed && !end_signed);
                                                        local_type = integer_type(module, { .bit_count = 64, .is_signed = is_signed });
                                                    } break;
                                                default:
                                                    {
                                                        analyze_type(module, end, 0);
                                                        auto end_type = end->type;
                                                        assert(end_type);
                                                        start->type = end_type;
                                                        local_type = end_type;
                                                    } break;
                                            }
                                        } break;
                                    default: trap();
                                }

                                assert(local_type);

                                for (auto right: right_values)
                                {
                                    if (!right->type)
                                    {
                                        analyze_type(module, right, local_type);
                                    }
                                }

                                local->variable.type = local_type;
                                emit_local_variable(module, local);
                                emit_value(module, start, TypeKind::memory);

                                auto index_alloca = local->variable.storage->llvm;

                                create_store(module, {
                                    .source = start->llvm,
                                    .destination = index_alloca,
                                    .type = local_type,
                                });

                                LLVMBuildBr(module->llvm.builder, entry_block);
                                LLVMPositionBuilderAtEnd(module->llvm.builder, entry_block);

                                auto header_index_load = create_load(module, {
                                    .type = local_type,
                                    .pointer = index_alloca,
                                });
                                emit_value(module, end, TypeKind::abi);
                                auto length_value = end->llvm;
                                auto index_compare = LLVMBuildICmp(module->llvm.builder, LLVMIntULT, header_index_load, length_value, "");
                                LLVMBuildCondBr(module->llvm.builder, index_compare, body_block, exit_block);

                                LLVMPositionBuilderAtEnd(module->llvm.builder, body_block);
                                analyze_statement(module, &statement->for_each.scope, statement->for_each.predicate, last_line, last_column, last_debug_location);

                                if (LLVMGetInsertBlock(module->llvm.builder))
                                {
                                    LLVMBuildBr(module->llvm.builder, continue_block);
                                }

                                LLVMPositionBuilderAtEnd(module->llvm.builder, continue_block);

                                auto continue_index_load = create_load(module, {
                                    .type = local_type,
                                    .pointer = index_alloca,
                                });

                                auto inc = LLVMBuildAdd(module->llvm.builder, continue_index_load, LLVMConstInt(local_type->llvm.abi, 1, false), "");
                                create_store(module, {
                                    .source = inc,
                                    .destination = index_alloca,
                                    .type = local_type,
                                });

                                LLVMBuildBr(module->llvm.builder, entry_block);

                                LLVMPositionBuilderAtEnd(module->llvm.builder, exit_block);
                            }
                            else
                            {
                                // TODO: case for reverse range
                                trap();
                            }
                        } break;
                }

                // END OF SCOPE
                module->llvm.continue_block = previous_continue_block;
                module->llvm.exit_block = previous_exit_block;
            } break;
        case StatementId::break_st:
            {
                auto exit_block = module->llvm.exit_block;
                if (!exit_block)
                {
                    report_error();
                }

                LLVMBuildBr(module->llvm.builder, exit_block);
                LLVMClearInsertionPosition(module->llvm.builder);
            } break;
        case StatementId::continue_st:
            {
                auto continue_block = module->llvm.continue_block;
                if (!continue_block)
                {
                    report_error();
                }

                LLVMBuildBr(module->llvm.builder, continue_block);
                LLVMClearInsertionPosition(module->llvm.builder);
            } break;
        default: unreachable();
    }
}

fn void emit_debug_argument(Module* module, Argument* argument, LLVMBasicBlockRef basic_block)
{
    assert(module->has_debug_info);
    resolve_type_in_place(module, argument->variable.type);
    bool always_preserve = true;
    LLVMDIFlags flags = {};
    LLVMMetadataRef scope = argument->variable.scope->llvm;
    auto parameter_variable = LLVMDIBuilderCreateParameterVariable(module->llvm.di_builder, scope, (char*)argument->variable.name.pointer, argument->variable.name.length, argument->index, module->llvm.file, argument->variable.line, argument->variable.type->llvm.debug, always_preserve, flags);
    auto inlined_at = module->llvm.inlined_at;
    auto debug_location = LLVMDIBuilderCreateDebugLocation(module->llvm.context, argument->variable.line, argument->variable.column, scope, inlined_at);
    LLVMDIBuilderInsertDeclareRecordAtEnd(module->llvm.di_builder, argument->variable.storage->llvm, parameter_variable, LLVMDIBuilderCreateExpression(module->llvm.di_builder, 0, 0), debug_location, basic_block);
}

struct ObjectGenerate
{
    String path;
    BBLLVMOptimizationLevel optimization_level;
    bool run_optimization_passes;
    bool has_debug_info;
};

fn BBLLVMCodeGenerationPipelineResult generate_object(LLVMModuleRef module, LLVMTargetMachineRef target_machine, ObjectGenerate options)
{
    llvm_module_set_target(module, target_machine);

    if (options.run_optimization_passes)
    {
        // BBLLVM
        bool prefer_speed = options.optimization_level == BBLLVMOptimizationLevel::O2 || options.optimization_level == BBLLVMOptimizationLevel::O3;
        BBLLVMOptimizationPipelineOptions optimization_options = {
            .optimization_level = (u64)options.optimization_level,
            .debug_info = options.has_debug_info,
            .loop_unrolling = prefer_speed,
            .loop_interleaving = prefer_speed,
            .loop_vectorization = prefer_speed,
            .slp_vectorization = prefer_speed,
            .merge_functions = prefer_speed,
            .call_graph_profile = false,
            .unified_lto = false,
            .assignment_tracking = options.has_debug_info,
            .verify_module = true,
        };
        llvm_module_run_optimization_pipeline(module, target_machine, optimization_options);
    }

    BBLLVMCodeGenerationPipelineOptions code_generation_options = {
        .output_file_path = options.path,
        .code_generation_file_type = (u64)BBLLVMCodeGenerationFileType::object_file,
        .optimize_when_possible = options.optimization_level > BBLLVMOptimizationLevel::O0,
        .verify_module = true,
    };
    auto result = llvm_module_run_code_generation_pipeline(module, target_machine, &code_generation_options);
    return result;
}

struct ArgBuilder
{
    const char* args[128];
    u32 argument_count = 0;

    void add(const char* arg)
    {
        assert(argument_count < array_length(args));
        args[argument_count] = arg;
        argument_count += 1;
    }

    Slice<const char*> flush()
    {
        assert(argument_count < array_length(args));
        args[argument_count] = 0;
        return { args, argument_count };
    }
};

void link(Module* module)
{
    Arena* arena = module->arena;
    ArgBuilder builder;
    builder.add("ld.lld");
    builder.add("--error-limit=0");
    builder.add("-o");
    assert(module->executable.pointer[module->executable.length] == 0);
    builder.add((char*)module->executable.pointer);
    for (String object: module->objects)
    {
        assert(object.pointer[object.length] == 0);
        builder.add((char*)object.pointer);
    }

    for (String library: module->libraries)
    {
        assert(library.pointer[library.length] == 0);
        builder.add((char*)library.pointer);
    }

    String candidate_library_paths[] = {
        string_literal("/usr/lib"),
        string_literal("/usr/lib/x86_64-linux-gnu"),
    };

    u64 index;
    String scrt1_object_path = {};
    for (index = 0; index < array_length(candidate_library_paths); index += 1)
    {
        auto directory_path = candidate_library_paths[index];
        String parts[] = {
            directory_path,
            string_literal("/Scrt1.o"),
        };
        scrt1_object_path = arena_join_string(arena, array_to_slice(parts));
        auto file = os_open(scrt1_object_path, { .read = 1}, {});
        if (file >= 0)
        {
            os_close(file);
            break;
        }
    }

    if (index == array_length(candidate_library_paths))
    {
        report_error();
    }

    {
        String parts[] = {
            string_literal("-L"),
            candidate_library_paths[index],
        };

        builder.add((char*)arena_join_string(arena, array_to_slice(parts)).pointer);
    }

    auto link_libcpp = false;
    if (link_libcpp)
    {
        builder.add("-lstdc++");
    }

    auto link_libc = true;
    auto dynamic_linker = true;

    if (dynamic_linker)
    {
        builder.add("-dynamic-linker");
        auto dynamic_linker_path = "/usr/lib64/ld-linux-x86-64.so.2";
        builder.add(dynamic_linker_path);
    }

    if (link_libc)
    {
        assert(scrt1_object_path.pointer);
        builder.add((char*)scrt1_object_path.pointer);
        builder.add("-lc");
    }

    auto args = builder.flush();
    auto result = lld_elf_link(args.pointer, args.length, true, false);
    if (!result.success)
    {
        print(string_literal("Command failed:\n"));
        for (auto arg : args)
        {
            auto a = c_string_to_slice(arg);
            print(a);
            print(string_literal(" "));
        }
        print(string_literal("\n"));
        assert(result.stdout_string.length == 0);
        assert(result.stderr_string.length != 0);
        print(result.stderr_string);
        print(string_literal("\n"));
        exit(1);
    }
}

void emit(Module* module)
{
    assert(!module->current_function);
    assert(!module->current_macro_instantiation);
    assert(!module->current_macro_declaration);
    llvm_initialize(module);

    for (auto* global = module->first_global; global; global = global->next)
    {
        assert(!module->current_function);
        assert(!module->current_macro_instantiation);
        assert(!module->current_macro_declaration);

        if (global->emitted)
        {
            continue;
        }

        switch (global->variable.storage->id)
        {
            case ValueId::function:
            case ValueId::external_function:
                {
                    auto function_type = &global->variable.storage->type->pointer.element_type->function;
                    auto semantic_argument_count = function_type->semantic_argument_types.length;
                    function_type->argument_abis = arena_allocate<AbiInformation>(module->arena, semantic_argument_count);
                    auto resolved_calling_convention = resolve_calling_convention(function_type->calling_convention);
                    auto is_reg_call = resolved_calling_convention == ResolvedCallingConvention::system_v && false; // TODO: regcall calling convention

                    LLVMTypeRef llvm_abi_argument_type_buffer[64];

                    switch (resolved_calling_convention)
                    {
                        case ResolvedCallingConvention::system_v:
                            {
                                function_type->available_registers = {
                                    .system_v = {
                                        .gpr = (u32)(is_reg_call ? 11 : 6),
                                        .sse = (u32)(is_reg_call ? 16 : 8),
                                    },
                                };
                                auto semantic_return_type = function_type->semantic_return_type;
                                function_type->return_abi = abi_system_classify_return_type(module, resolve_alias(module, semantic_return_type));
                                auto return_abi_kind = function_type->return_abi.flags.kind;

                                Type* abi_argument_type_buffer[64];
                                u16 abi_argument_type_count = 0;

                                Type* abi_return_type;
                                switch (return_abi_kind)
                                {
                                    case AbiKind::direct:
                                    case AbiKind::extend:
                                        {
                                            abi_return_type = function_type->return_abi.coerce_to_type;
                                        } break;
                                    case AbiKind::ignore:
                                    case AbiKind::indirect:
                                        {
                                            abi_return_type = void_type(module);
                                        } break;
                                    default: unreachable(); // TODO
                                }
                                assert(abi_return_type);
                                function_type->abi_return_type = abi_return_type;
                                resolve_type_in_place(module, abi_return_type);

                                if (function_type->return_abi.flags.kind == AbiKind::indirect)
                                {
                                    assert(!function_type->return_abi.flags.sret_after_this);
                                    function_type->available_registers.system_v.gpr -= 1;
                                    auto indirect_type = get_pointer_type(module, function_type->return_abi.semantic_type);
                                    resolve_type_in_place(module, indirect_type);

                                    auto abi_index = abi_argument_type_count;
                                    abi_argument_type_buffer[abi_index] = indirect_type;
                                    llvm_abi_argument_type_buffer[abi_index] = indirect_type->llvm.abi;
                                    abi_argument_type_count += 1;
                                }

                                for (u64 i = 0; i < semantic_argument_count; i += 1)
                                {
                                    auto& abi = function_type->argument_abis[i];
                                    auto semantic_argument_type = resolve_alias(module, function_type->semantic_argument_types[i]);
                                    auto is_named_argument = i < semantic_argument_count;
                                    assert(is_named_argument);

                                    abi = abi_system_v_classify_argument(module, &function_type->available_registers.system_v, array_to_slice(llvm_abi_argument_type_buffer), array_to_slice(abi_argument_type_buffer), {
                                        .type = semantic_argument_type,
                                        .abi_start = abi_argument_type_count,
                                        .is_named_argument = is_named_argument,
                                    });

                                    abi_argument_type_count += abi.abi_count;
                                }

                                auto abi_argument_types = new_type_array(module, abi_argument_type_count);
                                memcpy(abi_argument_types.pointer, abi_argument_type_buffer, sizeof(abi_argument_type_buffer[0]) * abi_argument_type_count);
                                function_type->abi_argument_types = abi_argument_types;
                            } break;
                        case ResolvedCallingConvention::win64:
                            {
                                report_error();
                            } break;
                        case ResolvedCallingConvention::count: unreachable();
                    }

                    auto llvm_function_type = LLVMFunctionType(function_type->abi_return_type->llvm.abi, llvm_abi_argument_type_buffer, (u32)function_type->abi_argument_types.length, function_type->is_variable_arguments);

                    LLVMMetadataRef subroutine_type = 0;
                    if (module->has_debug_info)
                    {
                        LLVMMetadataRef debug_argument_type_buffer[64];
                        Slice<LLVMMetadataRef> debug_argument_types = { .pointer = debug_argument_type_buffer, .length = function_type->argument_abis.length + 1 + function_type->is_variable_arguments };
                        debug_argument_types[0] = function_type->return_abi.semantic_type->llvm.debug;
                        assert(debug_argument_types[0]);

                        auto debug_argument_type_slice = debug_argument_types(1)(0, function_type->argument_abis.length);

                        for (u64 i = 0; i < function_type->argument_abis.length; i += 1)
                        {
                            auto& argument_abi = function_type->argument_abis[i];
                            auto* debug_argument_type = &debug_argument_type_slice[i];
                            *debug_argument_type = argument_abi.semantic_type->llvm.debug;
                            assert(*debug_argument_type);
                        }

                        if (function_type->is_variable_arguments)
                        {
                            auto void_ty = void_type(module);
                            assert(void_ty->llvm.debug);
                            debug_argument_types[function_type->argument_abis.length + 1] = void_ty->llvm.debug;
                        }

                        LLVMDIFlags flags = {};
                        subroutine_type = LLVMDIBuilderCreateSubroutineType(module->llvm.di_builder, module->llvm.file, debug_argument_types.pointer, (u32)debug_argument_types.length, flags);
                    }

                    global->variable.storage->type->pointer.element_type->llvm.abi = llvm_function_type;
                    global->variable.storage->type->pointer.element_type->llvm.debug = subroutine_type;

                    LLVMLinkage llvm_linkage_type;
                    switch (global->linkage)
                    {
                        case Linkage::internal: llvm_linkage_type = LLVMInternalLinkage; break;
                        case Linkage::external: llvm_linkage_type = LLVMExternalLinkage; break;
                    }
                    unsigned address_space = 0;
                    auto llvm_function = llvm_module_create_function(module->llvm.module, llvm_function_type, llvm_linkage_type, address_space, global->variable.name);
                    global->variable.storage->llvm = llvm_function;

                    LLVMCallConv cc;
                    switch (function_type->calling_convention)
                    {
                        case CallingConvention::c: cc = LLVMCCallConv; break;
                        case CallingConvention::count: unreachable();
                    }
                    LLVMSetFunctionCallConv(llvm_function, cc);

                    auto attribute_list = build_attribute_list(module, {
                        .return_abi = function_type->return_abi,
                        .argument_abis = function_type->argument_abis,
                        .abi_argument_types = function_type->abi_argument_types,
                        .abi_return_type = function_type->abi_return_type,
                        .attributes = global->variable.storage->function.attributes,
                        .call_site = false,
                    });
                    llvm_function_set_attributes(llvm_function, attribute_list);

                    LLVMMetadataRef subprogram = 0;
                    auto is_definition = global->variable.storage->id == ValueId::function;

                    if (module->has_debug_info)
                    {
                        auto is_local_to_unit = global->linkage == Linkage::internal;
                        auto line = global->variable.line;
                        auto scope_line = line + 1;
                        LLVMDIFlags flags = {};
                        auto is_optimized = build_mode_is_optimized(module->build_mode);
                        subprogram = LLVMDIBuilderCreateFunction(module->llvm.di_builder, module->scope.llvm, (char*)global->variable.name.pointer, global->variable.name.length, (char*)global->variable.name.pointer, global->variable.name.length, module->llvm.file, line, subroutine_type, is_local_to_unit, is_definition, scope_line, flags, is_optimized);
                        LLVMSetSubprogram(llvm_function, subprogram);
                    }

                    if (is_definition)
                    {
                        global->variable.storage->function.scope.llvm = subprogram;

                        module->current_function = global;

                        LLVMValueRef llvm_abi_argument_buffer[64];
                        Slice<LLVMValueRef> llvm_abi_arguments = { .pointer = llvm_abi_argument_buffer, .length = function_type->abi_argument_types.length };
                        LLVMGetParams(llvm_function, llvm_abi_argument_buffer);

                        auto* entry_block = llvm_context_create_basic_block(module->llvm.context, string_literal("entry"), llvm_function);
                        auto return_block = llvm_context_create_basic_block(module->llvm.context, string_literal("return_block"), 0);
                        global->variable.storage->function.llvm.return_block = return_block;

                        LLVMPositionBuilderAtEnd(module->llvm.builder, entry_block);
                        LLVMSetCurrentDebugLocation2(module->llvm.builder, 0);

                        auto return_abi_kind = function_type->return_abi.flags.kind;
                        switch (return_abi_kind)
                        {
                            case AbiKind::indirect:
                                {
                                    auto indirect_argument_index = function_type->return_abi.flags.sret_after_this;
                                    if (function_type->return_abi.flags.sret_after_this)
                                    {
                                        trap();
                                    }

                                    global->variable.storage->function.llvm.return_alloca = llvm_abi_arguments[indirect_argument_index];

                                    if (!function_type->return_abi.flags.indirect_by_value)
                                    {
                                        trap();
                                    }
                                } break;
                            case AbiKind::in_alloca:
                                {
                                    trap();
                                } break;
                            default:
                                {
                                    auto alloca = create_alloca(module, {
                                        .type = function_type->return_abi.semantic_type,
                                        .name = string_literal("retval"),
                                    });
                                    global->variable.storage->function.llvm.return_alloca = alloca;
                                } break;
                            case AbiKind::ignore: break;
                        }

                        auto arguments = global->variable.storage->function.arguments;
                        auto argument_abis = function_type->argument_abis;
                        assert(arguments.length == argument_abis.length);
                        for (u64 i = 0; i < semantic_argument_count; i += 1)
                        {
                            auto* argument = &arguments[i];
                            auto& argument_abi = argument_abis[i];
                            auto argument_abi_arguments = llvm_abi_arguments(argument_abi.abi_start)(0, argument_abi.abi_count);

                            LLVMValueRef semantic_argument_storage = 0;
                            switch (argument_abi.flags.kind)
                            {
                                case AbiKind::direct:
                                case AbiKind::extend:
                                    {
                                        auto first_argument = argument_abi_arguments[0];
                                        auto coerce_to_type = argument_abi.get_coerce_to_type();
                                        if (coerce_to_type->id != TypeId::structure && type_is_abi_equal(module, coerce_to_type, argument_abi.semantic_type) && argument_abi.attributes.direct.offset == 0)
                                        {
                                            assert(argument_abi.abi_count == 1);

                                            auto is_promoted = false;
                                            auto v = first_argument;
                                            if (coerce_to_type->llvm.abi != LLVMTypeOf(v))
                                            {
                                                trap();
                                            }

                                            if (is_promoted)
                                            {
                                                trap();
                                            }

                                            // TODO: this we can get rid of because we handle all of this inside `create_alloca`, load, stores, etc
                                            if (is_arbitrary_bit_integer(argument_abi.semantic_type))
                                            {
                                                auto bit_count = (u32)get_bit_size(argument_abi.semantic_type);
                                                auto abi_bit_count = align_bit_count(bit_count);
                                                bool is_signed = type_is_signed(argument_abi.semantic_type);
                                                auto destination_type = integer_type(module, { .bit_count = abi_bit_count, .is_signed = is_signed });
                                                auto alloca = create_alloca(module, {
                                                    .type = destination_type,
                                                    .name = argument->variable.name,
                                                });

                                                LLVMValueRef result;
                                                if (bit_count < abi_bit_count)
                                                {
                                                    if (is_signed)
                                                    {
                                                        result = LLVMBuildSExt(module->llvm.builder, first_argument, destination_type->llvm.memory, "");
                                                    }
                                                    else
                                                    {
                                                        result = LLVMBuildZExt(module->llvm.builder, first_argument, destination_type->llvm.memory, "");
                                                    }
                                                }
                                                else
                                                {
                                                    trap();
                                                }

                                                create_store(module, {
                                                    .source = result,
                                                    .destination = alloca,
                                                    .type = destination_type,
                                                });

                                                semantic_argument_storage = alloca;
                                            }
                                            else
                                            {
                                                auto alloca = create_alloca(module, {
                                                    .type = argument_abi.semantic_type,
                                                    .name = argument->variable.name,
                                                });
                                                create_store(module, {
                                                    .source = first_argument,
                                                    .destination = alloca,
                                                    .type = argument_abi.semantic_type,
                                                });

                                                semantic_argument_storage = alloca;
                                            }
                                        }
                                        else
                                        {
                                            auto is_fixed_vector_type = false;
                                            if (is_fixed_vector_type)
                                            {
                                                trap();
                                            }

                                            if (coerce_to_type->id == TypeId::structure && coerce_to_type->structure.fields.length > 1 && argument_abi.flags.kind == AbiKind::direct && !argument_abi.flags.can_be_flattened)
                                            {
                                                auto contains_homogeneous_scalable_vector_types = false;
                                                if (contains_homogeneous_scalable_vector_types)
                                                {
                                                    trap();
                                                }
                                            }

                                            auto alloca = create_alloca(module, { .type = argument_abi.semantic_type, .name = argument->variable.name });
                                            LLVMValueRef pointer;
                                            Type* pointer_type;
                                            if (argument_abi.attributes.direct.offset > 0)
                                            {
                                                trap();
                                            }
                                            else
                                            {
                                                pointer = alloca;
                                                pointer_type = argument_abi.semantic_type;
                                            }

                                            if (coerce_to_type->id == TypeId::structure && coerce_to_type->structure.fields.length > 1 && argument_abi.flags.kind == AbiKind::direct && argument_abi.flags.can_be_flattened)
                                            {
                                                auto struct_size = get_byte_size(coerce_to_type);
                                                auto pointer_element_size = get_byte_size(pointer_type);
                                                auto is_scalable = false;

                                                if (is_scalable)
                                                {
                                                    trap();
                                                }
                                                else
                                                {
                                                    auto source_size = struct_size;
                                                    auto destination_size = pointer_element_size;
                                                    auto address_alignment = get_byte_alignment(argument_abi.semantic_type);

                                                    LLVMValueRef address;
                                                    if (source_size <= destination_size)
                                                    {
                                                        address = alloca;
                                                    }
                                                    else
                                                    {
                                                        address = create_alloca(module, { .type = coerce_to_type, .name = string_literal("coerce"), .alignment = address_alignment });
                                                    }

                                                    assert(coerce_to_type->structure.fields.length == argument_abi.abi_count);

                                                    resolve_type_in_place(module, coerce_to_type);

                                                    for (u64 i = 0; i < coerce_to_type->structure.fields.length; i += 1)
                                                    {
                                                        auto gep = LLVMBuildStructGEP2(module->llvm.builder, coerce_to_type->llvm.abi, address, i, "");
                                                        create_store(module, {
                                                            .source = argument_abi_arguments[i],
                                                            .destination = gep,
                                                            .type = coerce_to_type->structure.fields[i].type,
                                                        });
                                                    }

                                                    if (source_size > destination_size)
                                                    {
                                                        unused(pointer);
                                                        trap();
                                                    }
                                                }
                                            }
                                            else
                                            {
                                                assert(argument_abi.abi_count == 1);
                                                auto abi_argument_type = function_type->abi_argument_types[argument_abi.abi_start];
                                                auto destination_size = get_byte_size(pointer_type) - argument_abi.attributes.direct.offset;
                                                auto is_volatile = false;
                                                create_coerced_store(module, argument_abi_arguments[0], abi_argument_type, pointer, pointer_type, destination_size, is_volatile);
                                            }

                                            semantic_argument_storage = alloca;
                                        }
                                    } break;
                                case AbiKind::indirect:
                                    {
                                        assert(argument_abi.abi_count == 1);
                                        auto evaluation_kind = get_evaluation_kind(argument_abi.semantic_type);
                                        switch (evaluation_kind)
                                        {
                                            default:
                                                {
                                                    if (argument_abi.flags.indirect_realign || argument_abi.flags.kind == AbiKind::indirect_aliased)
                                                    {
                                                        trap();
                                                    }

                                                    auto use_indirect_debug_address = !argument_abi.flags.indirect_by_value;
                                                    if (use_indirect_debug_address)
                                                    {
                                                        trap();
                                                    }

                                                    auto llvm_argument = argument_abi_arguments[0];
                                                    semantic_argument_storage = llvm_argument;
                                                } break;
                                            case EvaluationKind::scalar: trap();
                                        }
                                    } break;
                                default: unreachable();
                            }

                            assert(semantic_argument_storage);

                            auto storage = new_value(module);
                            auto value_type = argument->variable.type;
                            *storage = {
                                .type = get_pointer_type(module, value_type),
                                .id = ValueId::argument,
                                .llvm = semantic_argument_storage,
                            };
                            argument->variable.storage = storage;

                            if (module->has_debug_info)
                            {
                                emit_debug_argument(module, argument, entry_block);
                            }
                        }

                        analyze_block(module, global->variable.storage->function.block);

                        auto* current_basic_block = LLVMGetInsertBlock(module->llvm.builder);
                        if (current_basic_block)
                        {
                            assert(!LLVMGetBasicBlockTerminator(current_basic_block));

                            if (llvm_basic_block_is_empty(current_basic_block) || llvm_value_use_empty((LLVMValueRef)current_basic_block))
                            {
                                LLVMReplaceAllUsesWith((LLVMValueRef)return_block, (LLVMValueRef)current_basic_block);
                                llvm_basic_block_delete(return_block);
                            }
                            else
                            {
                                emit_block(module, return_block);
                            }
                        }
                        else
                        {
                            bool is_reachable = false;

                            if (llvm_value_has_one_use((LLVMValueRef)return_block))
                            {
                                auto user = llvm_basic_block_user_begin(return_block);
                                is_reachable = LLVMIsABranchInst(user) && !LLVMIsConditional(user) && LLVMGetSuccessor(user, 0) == return_block;
                                if (is_reachable)
                                {
                                    LLVMPositionBuilderAtEnd(module->llvm.builder, LLVMGetInstructionParent(user));
                                    LLVMInstructionEraseFromParent(user);
                                    llvm_basic_block_delete(return_block);
                                }
                            }

                            if (!is_reachable)
                            {
                                emit_block(module, return_block);
                            }
                        }

                        if (module->has_debug_info)
                        {
                            LLVMSetCurrentDebugLocation2(module->llvm.builder, 0);
                            auto subprogram = LLVMGetSubprogram(llvm_function);
                            LLVMDIBuilderFinalizeSubprogram(module->llvm.di_builder, subprogram);
                        }

                        if (function_type->return_abi.semantic_type == noreturn_type(module) || global->variable.storage->function.attributes.naked)
                        {
                            LLVMBuildUnreachable(module->llvm.builder);
                        }
                        else if (function_type->return_abi.semantic_type == void_type(module))
                        {
                            LLVMBuildRetVoid(module->llvm.builder);
                        }
                        else
                        {
                            LLVMValueRef return_value = 0; 

                            switch (return_abi_kind)
                            {
                                case AbiKind::direct:
                                case AbiKind::extend:
                                    {
                                        auto return_alloca = global->variable.storage->function.llvm.return_alloca;
                                        auto coerce_to_type = function_type->return_abi.get_coerce_to_type();
                                        auto return_semantic_type = function_type->return_abi.semantic_type;
                                        if (type_is_abi_equal(module, coerce_to_type, return_semantic_type) && function_type->return_abi.attributes.direct.offset == 0)
                                        {
                                            auto store = llvm_find_return_value_dominating_store(module->llvm.builder, return_alloca, return_semantic_type->llvm.abi);
                                            if (store)
                                            {
                                                return_value = LLVMGetOperand(store, 0);
                                                auto alloca = LLVMGetOperand(store, 1);
                                                assert(alloca == return_alloca);
                                                LLVMInstructionEraseFromParent(store);
                                                assert(llvm_value_use_empty(alloca));
                                                LLVMInstructionEraseFromParent(alloca);
                                            }
                                            else
                                            {
                                                return_value = create_load(module, LoadOptions{
                                                    .type = return_semantic_type,
                                                    .pointer = return_alloca,
                                                });
                                            }
                                        }
                                        else
                                        {
                                            LLVMValueRef source = 0;
                                            if (function_type->return_abi.attributes.direct.offset == 0)
                                            {
                                                source = return_alloca;
                                            }
                                            else
                                            {
                                                trap();
                                            }
                                            assert(source);

                                            auto source_type = function_type->return_abi.semantic_type;
                                            auto destination_type = coerce_to_type;
                                            auto result = create_coerced_load(module, source, source_type, destination_type);
                                            return_value = result;
                                        }
                                    } break;
                                case AbiKind::indirect:
                                    {
                                        auto evaluation_kind = get_evaluation_kind(function_type->return_abi.semantic_type);
                                        switch (evaluation_kind)
                                        {
                                            case EvaluationKind::scalar: trap();
                                            case EvaluationKind::aggregate: break;
                                            case EvaluationKind::complex: trap();
                                        }
                                    } break;
                                default: unreachable();
                            }

                            LLVMBuildRet(module->llvm.builder, return_value);
                        }

                        // END OF SCOPE
                        module->current_function = 0;
                    }
                } break;
            case ValueId::global:
                {
                    assert(!module->current_function);
                    analyze_value(module, global->variable.initial_value, global->variable.type, TypeKind::memory);

                    auto initial_value_type = global->variable.initial_value->type;

                    if (!global->variable.type)
                    {
                        global->variable.type = initial_value_type;
                    }

                    auto global_type = global->variable.type;

                    if (global_type != initial_value_type)
                    {
                        report_error();
                    }

                    resolve_type_in_place(module, global_type);

                    bool is_constant = false;
                    LLVMLinkage linkage;
                    switch (global->linkage)
                    {
                        case Linkage::internal: linkage = LLVMInternalLinkage; break;
                        case Linkage::external: linkage = LLVMExternalLinkage; break;
                    }

                    LLVMValueRef before = 0;
                    LLVMThreadLocalMode thread_local_mode = LLVMNotThreadLocal;
                    unsigned address_space = 0;
                    bool externally_initialized = false;

                    auto global_llvm = llvm_module_create_global_variable(module->llvm.module, global_type->llvm.memory, is_constant, linkage, global->variable.initial_value->llvm, global->variable.name, before, thread_local_mode, address_space, externally_initialized);
                    auto alignment = get_byte_alignment(global_type);
                    LLVMSetAlignment(global_llvm, alignment);
                    global->variable.storage->llvm = global_llvm;
                    global->variable.storage->type = get_pointer_type(module, global_type);

                    if (module->has_debug_info)
                    {
                        auto name = global->variable.name;
                        auto linkage_name = name;
                        auto local_to_unit = global->linkage == Linkage::internal;
                        auto global_debug = LLVMDIBuilderCreateGlobalVariableExpression(module->llvm.di_builder, module->scope.llvm, (char*)name.pointer, name.length, (char*)linkage_name.pointer, linkage_name.length, module->llvm.file, global->variable.line, global_type->llvm.debug, local_to_unit, null_expression(module), 0, alignment * 8);
                        LLVMGlobalSetMetadata(global_llvm, 0, global_debug);
                    }
                } break;
            default: report_error();
        }
    }

    if (module->has_debug_info)
    {
        LLVMDIBuilderFinalize(module->llvm.di_builder);
    }

    String verification_error_message = {};
    if (!llvm_module_verify(module->llvm.module, &verification_error_message))
    {
        dump_module(module);
        print(string_literal("\n==========================\nLLVM VERIFICATION ERROR\n==========================\n"));
        print(verification_error_message);
        bb_fail();
    }

    if (!module->silent)
    {
        dump_module(module);
    }

    BBLLVMCodeGenerationOptimizationLevel code_generation_optimization_level;
    switch (module->build_mode)
    {
        case BuildMode::debug_none:
        case BuildMode::debug:
            code_generation_optimization_level = BBLLVMCodeGenerationOptimizationLevel::none;
            break;
        case BuildMode::soft_optimize:
            code_generation_optimization_level = BBLLVMCodeGenerationOptimizationLevel::less;
            break;
        case BuildMode::optimize_for_speed:
        case BuildMode::optimize_for_size:
            code_generation_optimization_level = BBLLVMCodeGenerationOptimizationLevel::normal;
            break;
        case BuildMode::aggressively_optimize_for_speed:
        case BuildMode::aggressively_optimize_for_size:
            code_generation_optimization_level = BBLLVMCodeGenerationOptimizationLevel::aggressive;
            break;
        case BuildMode::count:
            unreachable();
    }
    BBLLVMTargetMachineCreate target_machine_options = {
        .target_triple = llvm_default_target_triple(),
        .cpu_model = llvm_host_cpu_name(),
        .cpu_features = llvm_host_cpu_features(),
        .relocation_model = BBLLVMRelocationModel::default_relocation,
        .code_model = BBLLVMCodeModel::none,
        .optimization_level = code_generation_optimization_level,
    };
    String error_message = {};
    auto target_machine = llvm_create_target_machine(&target_machine_options, &error_message);
    assert(target_machine);
    BBLLVMOptimizationLevel optimization_level;
    switch (module->build_mode)
    {
        case BuildMode::debug_none:
        case BuildMode::debug:
            optimization_level = BBLLVMOptimizationLevel::O0;
            break;
        case BuildMode::soft_optimize:
            optimization_level = BBLLVMOptimizationLevel::O1;
            break;
        case BuildMode::optimize_for_speed:
            optimization_level = BBLLVMOptimizationLevel::O2;
            break;
        case BuildMode::optimize_for_size:
            optimization_level = BBLLVMOptimizationLevel::Os;
            break;
        case BuildMode::aggressively_optimize_for_speed:
            optimization_level = BBLLVMOptimizationLevel::O3;
            break;
        case BuildMode::aggressively_optimize_for_size:
            optimization_level = BBLLVMOptimizationLevel::Oz;
            break;
        case BuildMode::count:
            unreachable();
    }
    auto object_generation_result = generate_object(module->llvm.module, target_machine, {
        .path = module->objects[0],
        .optimization_level = optimization_level,
        .run_optimization_passes = module->build_mode != BuildMode::debug_none,
        .has_debug_info = module->has_debug_info,
    });
    if (object_generation_result != BBLLVMCodeGenerationPipelineResult::success)
    {
        report_error();
    }

    link(module);
}
