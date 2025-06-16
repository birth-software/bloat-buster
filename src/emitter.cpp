#include <compiler.hpp>
#include <llvm.hpp>

fn LLVMValueRef llvm_module_create_function(Arena* arena, LLVMModuleRef module, LLVMTypeRef function_type, LLVMLinkage linkage_type, String name)
{
    assert(name.pointer[name.length] == 0);
    auto function = LLVMAddFunction(module, (char*)name.pointer, function_type);
    LLVMSetLinkage(function, linkage_type);
    return function;
}

fn LLVMValueRef llvm_create_global_variable(LLVMModuleRef module, LLVMTypeRef type, bool is_constant, LLVMLinkage linkage_type, LLVMValueRef initial_value, String name, LLVMThreadLocalMode thread_local_mode, bool externally_initialized, u32 alignment, LLVMUnnamedAddr unnamed_address)
{
    assert(name.pointer[name.length] == 0);
    auto global = LLVMAddGlobal(module, type, (char*)name.pointer);
    LLVMSetGlobalConstant(global, is_constant);
    LLVMSetLinkage(global, linkage_type);
    LLVMSetInitializer(global, initial_value);
    LLVMSetThreadLocalMode(global, thread_local_mode);
    LLVMSetExternallyInitialized(global, externally_initialized);
    LLVMSetAlignment(global, alignment);
    LLVMSetUnnamedAddress(global, unnamed_address);
    return global;
}

fn LLVMValueRef llvm_builder_create_alloca(LLVMBuilderRef b, LLVMTypeRef type, u32 alignment, String name)
{   
    assert(name.pointer[name.length] == 0);
    auto alloca = LLVMBuildAlloca(b, type, (char*)name.pointer);
    LLVMSetAlignment(alloca, alignment);
    return alloca;
}

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
fn void emit_value(Module* module, Value* value, TypeKind type_kind, bool must_be_constant);
fn void analyze_value(Module* module, Value* value, Type* expected_type, TypeKind type_kind, bool must_be_constant);

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

    assert(LLVMGetBasicBlockParent(basic_block));

    LLVMPositionBuilderAtEnd(module->llvm.builder, basic_block);
}

fn LLVMValueRef emit_condition(Module* module, Value* condition_value)
{
    auto condition_llvm_value = condition_value->llvm;
    auto condition_type = condition_value->type;
    assert(condition_type);
    assert(condition_llvm_value);

    assert(condition_type->id == TypeId::integer || condition_type->id == TypeId::pointer);
    if (!(condition_type->id == TypeId::integer && condition_type->integer.bit_count == 1))
    {
        condition_llvm_value = LLVMBuildICmp(module->llvm.builder, LLVMIntNE, condition_llvm_value, LLVMConstNull(condition_type->llvm.abi), "");
    }

    assert(condition_llvm_value);

    return condition_llvm_value;
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
        case TypeId::enum_array:
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
    char* host_triple;
    char* host_cpu_model;
    char* host_cpu_features;
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
        case TypeId::enumerator:
            return true;
        case TypeId::array:
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
        case TypeId::enumerator: return is_promotable_integer_type_for_abi(type->enumerator.backing_type);
        case TypeId::pointer: return false;
        default: unreachable();
    }
}

fn bool receives_type(Value* value)
{
    switch (value->id)
    {
        case ValueId::constant_integer:
        case ValueId::enum_literal:
        case ValueId::string_literal:
        case ValueId::zero:
            return true;
        case ValueId::array_expression:
        case ValueId::call:
            return false;
        case ValueId::variable_reference:
            {
                return value->kind == ValueKind::left && value->id == ValueId::global;
            } break;
        case ValueId::field_access:
            {
                auto aggregate = value->field_access.aggregate;
                auto field_name = value->field_access.field_name;

                if (field_name.equal(string_literal("length")) && aggregate->id == ValueId::variable_reference && aggregate->kind == ValueKind::left && aggregate->variable_reference->type->id == TypeId::array)
                {
                    return true;
                }
                else
                {
                    return false;
                }
            } break;
        case ValueId::unary:
            {
                auto unary_id = value->unary.id;
                auto unary_value = value->unary.value;

                switch (unary_id)
                {
                    case UnaryId::extend:
                    case UnaryId::truncate:
                    case UnaryId::pointer_cast:
                    case UnaryId::pointer_from_int:
                        return true;
                    case UnaryId::int_from_pointer:
                    case UnaryId::ampersand:
                    case UnaryId::dereference:
                    case UnaryId::va_end:
                    case UnaryId::leading_zeroes:
                    case UnaryId::trailing_zeroes:
                    case UnaryId::exclamation:
                    case UnaryId::int_from_enum:
                    case UnaryId::enum_from_int:
                    case UnaryId::enum_name:
                        return false;
                    case UnaryId::minus:
                    case UnaryId::plus:
                    case UnaryId::bitwise_not:
                        return receives_type(unary_value);
                }
            } break;
        case ValueId::binary:
            {
                auto left = value->binary.left;
                auto right = value->binary.right;
                auto binary_id = value->binary.id;

                return receives_type(left) && receives_type(right);
            } break;
        case ValueId::unary_type:
            {
                auto unary_type_id = value->unary_type.id;
                switch (unary_type_id)
                {
                    case UnaryTypeId::align_of:
                    case UnaryTypeId::byte_size:
                    case UnaryTypeId::integer_max:
                        return true;
                    default: trap();
                }
            } break;
        case ValueId::infer_or_ignore:
        case ValueId::forward_declared_function:
        case ValueId::function:
        case ValueId::macro_reference:
        case ValueId::macro_instantiation:
        case ValueId::global:
        case ValueId::array_initialization:
        case ValueId::slice_expression:
        case ValueId::trap:
        case ValueId::va_start:
        case ValueId::va_arg:
        case ValueId::aggregate_initialization:
        case ValueId::undefined:
        case ValueId::unreachable:
        case ValueId::select:
        case ValueId::string_to_enum:
        case ValueId::local:
        case ValueId::argument:
        case ValueId::build_mode:
        case ValueId::has_debug_info:
        case ValueId::field_parent_pointer:
            trap();
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
        .host_triple = LLVMGetDefaultTargetTriple(),
        .host_cpu_model = LLVMGetHostCPUName(),
        .host_cpu_features = LLVMGetHostCPUFeatures(),
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
    auto module_str = LLVMPrintModuleToString(module->llvm.module);
    print(c_string_to_slice(module_str));
}

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

fn void llvm_initialize(Module* module)
{
    llvm_initialize_all();

    auto context = LLVMContextCreate();
    auto m = LLVMModuleCreateWithNameInContext((char*)module->name.pointer, context);
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

    char* target_triple = {};
    char* cpu_model = {};
    char* cpu_features = {};

    if (target_compare(module->target, target_get_native()))
    {
        target_triple = llvm_global.host_triple;
        cpu_model = llvm_global.host_cpu_model;
        cpu_features = llvm_global.host_cpu_features;
    }
    else
    {
        // TODO
        report_error();
    }

    auto target_machine_options = LLVMCreateTargetMachineOptions();
    LLVMTargetMachineOptionsSetCPU(target_machine_options, cpu_model);
    LLVMTargetMachineOptionsSetFeatures(target_machine_options, cpu_features);

    LLVMCodeGenOptLevel code_generation_optimization_level;
    switch (module->build_mode)
    {
        case BuildMode::debug_none:
        case BuildMode::debug:
            code_generation_optimization_level = LLVMCodeGenLevelNone;
            break;
        case BuildMode::soft_optimize:
            code_generation_optimization_level = LLVMCodeGenLevelLess;
            break;
        case BuildMode::optimize_for_speed:
        case BuildMode::optimize_for_size:
            code_generation_optimization_level = LLVMCodeGenLevelDefault;
            break;
        case BuildMode::aggressively_optimize_for_speed:
        case BuildMode::aggressively_optimize_for_size:
            code_generation_optimization_level = LLVMCodeGenLevelAggressive;
            break;
        case BuildMode::count:
            unreachable();
    }
    LLVMTargetMachineOptionsSetCodeGenOptLevel(target_machine_options, code_generation_optimization_level);

    LLVMTargetRef target = 0;
    char* error_message = 0;
    auto result = LLVMGetTargetFromTriple(target_triple, &target, &error_message);
    if (result != 0)
    {
        report_error();
    }
    assert(!error_message);

    auto target_machine = LLVMCreateTargetMachineWithOptions(target, target_triple, target_machine_options);

    auto target_data = LLVMCreateTargetDataLayout(target_machine);
    LLVMSetModuleDataLayout(m, target_data);
    LLVMSetTarget(m, target_triple);

    module->llvm = {
        .context = context,
        .module = m,
        .builder = builder,
        .di_builder = di_builder,
        .file = di_file,
        .target_machine = target_machine,
        .target_data = target_data,
        .compile_unit = di_compile_unit,
        .pointer_type = LLVMPointerTypeInContext(context, 0),
        .void_type = LLVMVoidTypeInContext(context),
    };

    for (u64 i = 0; i < (u64)IntrinsicIndex::count; i += 1)
    {
        String name = intrinsic_names[i];
        auto intrinsic_id = LLVMLookupIntrinsicID((char*)name.pointer, name.length);
        assert(intrinsic_id != 0);
        module->llvm.intrinsic_table[i].n = intrinsic_id;
    }

    for (u64 i = 0; i < (u64)AttributeIndex::count; i += 1)
    {
        String name = attribute_names[i];
        auto attribute_id = LLVMGetEnumAttributeKindForName((char*)name.pointer, name.length);
        assert(attribute_id != 0);
        module->llvm.attribute_table[i].n = attribute_id;
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
                    for (auto& field: type->structure.fields)
                    {
                        auto field_offset = field.offset;
                        if (field_offset >= end)
                        {
                            break;
                        }

                        auto field_start = field_offset < start ? start - field_offset : 0;
                        if (!contains_no_user_data(field.type, field_start, end - field_offset))
                        {
                            return false;
                        }
                    }

                    return true;
                } break;
            case TypeId::array:
            case TypeId::enum_array:
                {
                    Type* element_type = 0;
                    u64 element_count = 0;

                    switch (type->id)
                    {
                        case TypeId::array:
                            {
                                element_type = type->array.element_type;
                                element_count = type->array.element_count;
                            } break;
                        case TypeId::enum_array:
                            {
                                auto enum_type = type->enum_array.enum_type;
                                assert(enum_type->id == TypeId::enumerator);
                                element_count = enum_type->enumerator.fields.length;
                                element_type = type->enum_array.element_type;
                            } break;
                        default: unreachable();
                    }

                    assert(element_type);
                    assert(element_count);

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
                if (offset == 0)
                {
                    auto bit_count = type->integer.bit_count;
                    auto start = source_offset + get_byte_size(type);
                    auto end = source_offset + 8;

                    bool type_contains_no_user_data = contains_no_user_data(source_type, start, end);
                    switch (bit_count)
                    {
                        case 64: return type;
                        case 32: case 16: case 8:
                                 {
                                     if (type_contains_no_user_data)
                                     {
                                         return type;
                                     }
                                 } break;
                        default: break;
                    }
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
        case TypeId::enumerator:
            {
                auto backing_type = type->enumerator.backing_type;
                return abi_system_v_get_integer_type_at_offset(module, backing_type, offset, source_type == type ? backing_type : source_type, source_offset);
            } break;
        case TypeId::array:
            {
                auto element_type = type->array.element_type;
                auto element_size = get_byte_size(element_type);
                auto element_offset = (offset / element_size) * element_size;
                return abi_system_v_get_integer_type_at_offset(module, element_type, offset - element_offset, source_type, source_offset);
            } break;
        default: unreachable();
    }

    auto source_size = get_byte_size(source_type);
    assert(source_size != source_offset);
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

                        if (byte_size > 16 && (byte_size != element_size || byte_size > vector_size))
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
                auto byte_size = get_byte_size(type);

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
            case TypeId::opaque:
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
                    auto llvm_size = LLVMStoreSizeOfType(module->llvm.target_data, result);
                    assert(llvm_size == type->structure.byte_size);
                } break;
            case TypeId::bits:
                {
                    auto backing_type = type->bits.backing_type;
                    resolve_type_in_place_abi(module, backing_type);
                    result = backing_type->llvm.abi;
                    auto llvm_size = LLVMStoreSizeOfType(module->llvm.target_data, result);
                    assert(llvm_size == get_byte_size(type));
                } break;
            case TypeId::union_type:
                {
                    auto biggest_type = type->union_type.fields[type->union_type.biggest_field].type;
                    resolve_type_in_place_memory(module, biggest_type);
                    result = LLVMStructTypeInContext(module->llvm.context, &biggest_type->llvm.memory, 1, false);
                    auto llvm_size = LLVMStoreSizeOfType(module->llvm.target_data, result);
                    assert(llvm_size == get_byte_size(type));
                } break;
            case TypeId::alias:
                {
                    auto aliased = type->alias.type;
                    resolve_type_in_place_abi(module, aliased);
                    result = aliased->llvm.abi;
                } break;
            case TypeId::enum_array:
                {
                    auto enum_type = type->enum_array.enum_type;
                    assert(enum_type->id == TypeId::enumerator);
                    auto element_type = type->enum_array.element_type;
                    resolve_type_in_place_memory(module, element_type);
                    auto element_count = enum_type->enumerator.fields.length;
                    assert(element_count);
                    auto array_type = LLVMArrayType2(element_type->llvm.memory, element_count);
                    result = array_type;
                    auto llvm_size = LLVMStoreSizeOfType(module->llvm.target_data, result);
                    assert(llvm_size == get_byte_size(type));
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
            case TypeId::opaque:
            case TypeId::array:
            case TypeId::structure:
            case TypeId::enum_array:
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
                        auto bit_count = dwarf_type == DwarfType::boolean ? 8 : type->integer.bit_count;
                        result = LLVMDIBuilderCreateBasicType(module->llvm.di_builder, (char*)type->name.pointer, type->name.length, bit_count, (u32)dwarf_type, flags);
                    } break;
                case TypeId::pointer:
                    {
                        resolve_type_in_place_debug(module, type->pointer.element_type);
                        result = type->llvm.debug;
                        if (!result)
                        {
                            u32 address_space = 0;
                            result = LLVMDIBuilderCreatePointerType(module->llvm.di_builder, type->pointer.element_type->llvm.debug, get_bit_size(type), get_byte_alignment(type) * 8, address_space, (char*)type->name.pointer, type->name.length);
                        }
                    } break;
                case TypeId::array:
                    {
                        auto array_element_type = type->array.element_type;
                        auto array_element_count = type->array.element_count;
                        assert(array_element_count);
                        resolve_type_in_place_debug(module, array_element_type);
                        auto bit_alignment = get_byte_alignment(type) * 8;
                        auto array_type = LLVMDIBuilderCreateArrayType(module->llvm.di_builder, get_bit_size(type), bit_alignment, array_element_type->llvm.debug, 0, 0);
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
                            auto enum_field = LLVMDIBuilderCreateEnumerator(module->llvm.di_builder, (char*)field.name.pointer, field.name.length, field.value, !type_is_signed(backing_type));
                            field_buffer[i] = enum_field;
                        }

                        auto debug_aligned_type = align_integer_type(module, backing_type);
                        resolve_type_in_place_debug(module, debug_aligned_type);

                        result = LLVMDIBuilderCreateEnumerationType(module->llvm.di_builder, module->scope.llvm, (char*)type->name.pointer, type->name.length, module->llvm.file, type->enumerator.line, get_bit_size(type), get_byte_alignment(type) * 8, field_buffer, type->enumerator.fields.length, debug_aligned_type->llvm.debug);
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
                            auto member_type = LLVMDIBuilderCreateMemberType(module->llvm.di_builder, module->scope.llvm, (char*)field.name.pointer, field.name.length, module->llvm.file, field.line, get_bit_size(field_type), get_byte_alignment(field_type) * 8, field.offset * 8, flags, field_type->llvm.debug);
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
                case TypeId::enum_array:
                    {
                        auto enum_type = type->enum_array.enum_type;
                        assert(enum_type->id == TypeId::enumerator);
                        auto element_type = type->enum_array.element_type;
                        auto element_count = enum_type->enumerator.fields.length;
                        resolve_type_in_place_debug(module, element_type);
                        assert(element_count);
                        auto bit_alignment = get_byte_alignment(type) * 8;
                        auto array_type = LLVMDIBuilderCreateArrayType(module->llvm.di_builder, element_count, bit_alignment, element_type->llvm.debug, 0, 0);
                        result = array_type;
                    } break;
                case TypeId::opaque:
                    {
                        // TODO: ?
                        return;
                    } break;
                case TypeId::function:
                    {
                        auto function_type = &type->function;
                        LLVMMetadataRef debug_argument_type_buffer[64];
                        Slice<LLVMMetadataRef> debug_argument_types = { .pointer = debug_argument_type_buffer, .length = function_type->abi.argument_abis.length + 1 + function_type->base.is_variable_arguments };
                        auto semantic_return_type = function_type->base.semantic_return_type;
                        resolve_type_in_place_debug(module, semantic_return_type);
                        debug_argument_types[0] = semantic_return_type->llvm.debug;
                        assert(debug_argument_types[0]);

                        auto semantic_argument_types = function_type->base.semantic_argument_types;
                        auto debug_argument_type_slice = debug_argument_types(1)(0, semantic_argument_types.length);

                        for (u64 i = 0; i < semantic_argument_types.length; i += 1)
                        {
                            auto* debug_argument_type = &debug_argument_type_slice[i];
                            auto semantic_type = semantic_argument_types[i];
                            resolve_type_in_place_debug(module, semantic_type);
                            *debug_argument_type = semantic_type->llvm.debug;
                            assert(*debug_argument_type);
                        }

                        if (function_type->base.is_variable_arguments)
                        {
                            auto void_ty = void_type(module);
                            assert(void_ty->llvm.debug);
                            debug_argument_types[function_type->base.semantic_argument_types.length + 1] = void_ty->llvm.debug;
                        }

                        LLVMDIFlags flags = {};
                        auto subroutine_type = LLVMDIBuilderCreateSubroutineType(module->llvm.di_builder, module->llvm.file, debug_argument_types.pointer, (u32)debug_argument_types.length, flags);
                        result = subroutine_type;
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
        case TypeId::enumerator:
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
    u64 high_offset = align_forward(get_byte_size(low), alignment);
    auto byte_size = align_forward(high_offset + get_byte_size(high), alignment);

    assert(low->scope);
    assert(high->scope);

    auto scope = low->scope->kind == ScopeKind::global ? high->scope : low->scope;

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
            .byte_size = byte_size,
            .byte_alignment = alignment,
        },
        .id = TypeId::structure,
        .name = string_literal(""),
        .scope = scope,
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
            return abi_system_v_get_direct(module, {
                .semantic_type = type,
                .type = integer_type(module, { .bit_count = size * 8, .is_signed = false }),
            });
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

fn AbiInformation abi_system_v_classify_return_type(Module* module, Type* semantic_return_type)
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
                    // TODO
                    // if (semantic_return_type->id == TypeId::enumerator)
                    // {
                    //     trap();
                    // }

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

fn Global* get_current_function(Module* module)
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

    return parent_function_global;
}

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

    auto original_block = LLVMGetInsertBlock(module->llvm.builder);
    auto function = get_current_function(module);
    auto debug_location = LLVMGetCurrentDebugLocation2(module->llvm.builder);
    LLVMPositionBuilderBefore(module->llvm.builder, function->variable.storage->function.llvm.alloca_insertion_point);
    LLVMSetCurrentDebugLocation2(module->llvm.builder, 0);

    auto alloca = llvm_builder_create_alloca(module->llvm.builder, abi_type->llvm.memory, alignment, options.name);
    LLVMPositionBuilderAtEnd(module->llvm.builder, original_block);
    LLVMSetCurrentDebugLocation2(module->llvm.builder, debug_location);
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

fn LLVMValueRef memory_to_abi(Module* module, LLVMValueRef value, Type* type)
{
    LLVMValueRef result = value;
    if (type->llvm.memory != type->llvm.abi)
    {
        result = LLVMBuildIntCast2(module->llvm.builder, result, type->llvm.abi, type_is_signed(type), "");
    }
    return result;
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
            result = memory_to_abi(module, result, options.type);
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

using EnumCallback = void (LLVMValueRef, LLVMAttributeIndex, LLVMAttributeRef);

fn LLVMAttributeRef create_enum_attribute(Module* module, AttributeIndex attribute_index, u64 value)
{
    return LLVMCreateEnumAttribute(module->llvm.context, module->llvm.attribute_table[(u64)attribute_index].n, value);
}

fn LLVMAttributeRef create_type_attribute(Module* module, AttributeIndex attribute_index, LLVMTypeRef type)
{
    return LLVMCreateTypeAttribute(module->llvm.context, module->llvm.attribute_table[(u64)attribute_index].n, type);
}

fn LLVMAttributeRef create_string_attribute(Module* module, String key, String value)
{
    return LLVMCreateStringAttribute(module->llvm.context, (char*)key.pointer, key.length, (char*)value.pointer, value.length);
}

fn void create_and_add_enum_attribute(Module* module, AttributeIndex attribute_name, u64 attribute_value, EnumCallback* add_callback, LLVMValueRef value, u32 attribute_index)
{
    auto attribute = create_enum_attribute(module, attribute_name, attribute_value);
    add_callback(value, attribute_index, attribute);
}

fn void create_and_add_type_attribute(Module* module, AttributeIndex attribute_name, LLVMTypeRef type, EnumCallback* add_callback, LLVMValueRef value, u32 attribute_index)
{
    auto attribute = create_type_attribute(module, attribute_name, type);
    add_callback(value, attribute_index, attribute);
}

fn void create_and_add_string_attribute(Module* module, String attribute_key, String attribute_value, EnumCallback* add_callback, LLVMValueRef value, u32 attribute_index)
{
    auto attribute = create_string_attribute(module, attribute_key, attribute_value);
    add_callback(value, attribute_index, attribute);
}

struct ValueAttribute
{
    u32 alignment;
    u32 sign_extend:1;
    u32 zero_extend:1;
    u32 no_alias:1;
    u32 in_reg:1;
    u32 sret:1;
    u32 writable:1;
    u32 dead_on_unwind:1;
    u32 by_value:1;
};

fn void add_value_attribute(Module* module, LLVMValueRef value, u32 index, EnumCallback* add_callback, LLVMTypeRef semantic_type, LLVMTypeRef abi_type, ValueAttribute attributes)
{
    assert(value);
    assert(semantic_type);
    assert(abi_type);

    if (attributes.alignment)
    {
        create_and_add_enum_attribute(module, AttributeIndex::align, attributes.alignment, add_callback, value, index);
    }

    if (attributes.sign_extend)
    {
        create_and_add_enum_attribute(module, AttributeIndex::signext, 0, add_callback, value, index);
    }

    if (attributes.zero_extend)
    {
        create_and_add_enum_attribute(module, AttributeIndex::zeroext, 0, add_callback, value, index);
    }

    if (attributes.no_alias)
    {
        create_and_add_enum_attribute(module, AttributeIndex::noalias, 0, add_callback, value, index);
    }

    if (attributes.in_reg)
    {
        create_and_add_enum_attribute(module, AttributeIndex::inreg, 0, add_callback, value, index);
    }

    if (attributes.sret)
    {
        create_and_add_type_attribute(module, AttributeIndex::sret, semantic_type, add_callback, value, index);
    }

    if (attributes.writable)
    {
        create_and_add_enum_attribute(module, AttributeIndex::writable, 0, add_callback, value, index);
    }

    if (attributes.dead_on_unwind)
    {
        create_and_add_enum_attribute(module, AttributeIndex::dead_on_unwind, 0, add_callback, value, index);
    }

    if (attributes.by_value)
    {
        create_and_add_type_attribute(module, AttributeIndex::byval, semantic_type, add_callback, value, index);
    }
}

fn void emit_attributes(Module* module, LLVMValueRef value, EnumCallback* add_callback, AttributeBuildOptions options)
{
    resolve_type_in_place(module, options.return_abi.semantic_type);
    add_value_attribute(module, value, 0, add_callback, options.return_abi.semantic_type->llvm.memory, options.abi_return_type->llvm.abi, {
        .alignment = 0,
        .sign_extend = options.return_abi.flags.kind == AbiKind::extend && options.return_abi.flags.sign_extension,
        .zero_extend = options.return_abi.flags.kind == AbiKind::extend && !options.return_abi.flags.sign_extension,
        .no_alias = false,
        .in_reg = false,
        .sret = false,
        .writable = false,
        .dead_on_unwind = false,
        .by_value = false,
    });

    u64 total_abi_count = 0;
    if (options.return_abi.flags.kind == AbiKind::indirect)
    {
        const auto& abi = options.return_abi;
        auto abi_index = abi.flags.sret_after_this;

        auto abi_type = options.abi_argument_types[abi_index];
        resolve_type_in_place(module, abi_type);
        add_value_attribute(module, value, abi_index + 1, add_callback, abi.semantic_type->llvm.memory, abi_type->llvm.abi, {
            .alignment = get_byte_alignment(abi.semantic_type),
            .sign_extend = false,
            .zero_extend = false,
            .no_alias = true,
            .in_reg = abi.flags.in_reg,
            .sret = true,
            .writable = true,
            .dead_on_unwind = true,
            .by_value = false,
        });

        total_abi_count += 1;
    }

    for (const auto& abi: options.argument_abis)
    {
        resolve_type_in_place(module, abi.semantic_type);

        for (auto abi_index = abi.abi_start; abi_index < abi.abi_start + abi.abi_count; abi_index += 1)
        {
            auto abi_type = options.abi_argument_types[abi_index];
            resolve_type_in_place(module, abi_type);

            add_value_attribute(module, value, abi_index + 1, add_callback, abi.semantic_type->llvm.memory, abi_type->llvm.abi, {
                .alignment = u32(abi.flags.kind == AbiKind::indirect ? 8 : 0),
                .sign_extend = abi.flags.kind == AbiKind::extend && abi.flags.sign_extension,
                .zero_extend = abi.flags.kind == AbiKind::extend && !abi.flags.sign_extension,
                .no_alias = false,
                .in_reg = abi.flags.in_reg,
                .sret = false,
                .writable = false,
                .dead_on_unwind = false,
                .by_value = abi.flags.indirect_by_value,
            });
            total_abi_count += 1;
        }
    }

    assert(total_abi_count == options.abi_argument_types.length);

    auto index = ~(u32)0;
    {
        auto is_noreturn = options.return_abi.semantic_type == noreturn_type(module);
        if (is_noreturn)
        {
            create_and_add_enum_attribute(module, AttributeIndex::noreturn, 0, add_callback, value, index);
        }

        auto nounwind = true;
        if (nounwind)
        {
            create_and_add_enum_attribute(module, AttributeIndex::nounwind, 0, add_callback, value, index);
        }

        auto no_inline = options.attributes.inline_behavior == InlineBehavior::no_inline;
        if (no_inline)
        {
            create_and_add_enum_attribute(module, AttributeIndex::noinline, 0, add_callback, value, index);
        }

        auto always_inline = options.attributes.inline_behavior == InlineBehavior::always_inline;
        if (always_inline)
        {
            create_and_add_enum_attribute(module, AttributeIndex::alwaysinline, 0, add_callback, value, index);
        }

        if (module->has_debug_info)
        {
            create_and_add_string_attribute(module, string_literal("frame-pointer"), string_literal("all"), add_callback, value, index);
        }

        if (!options.call_site)
        {
            if (options.attributes.naked)
            {
                create_and_add_enum_attribute(module, AttributeIndex::naked, 0, add_callback, value, index);
            }

            if (options.attributes.inline_behavior == InlineBehavior::inline_hint)
            {
                create_and_add_enum_attribute(module, AttributeIndex::inlinehint, 0, add_callback, value, index);
            }
        }
    }
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
        case UnaryId::enum_from_int:
        case UnaryId::leading_zeroes:
        case UnaryId::trailing_zeroes:
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
        case BinaryId::max:
        case BinaryId::min:
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

enum class IndexType
{
    none,
    array,
    enum_array,
};

struct TypeAnalysis
{
    Type* indexing_type;
    bool must_be_constant;
};

fn void analyze_type(Module* module, Value* value, Type* expected_type, TypeAnalysis analysis);

fn void analyze_binary_type(Module* module, Value* left, Value* right, bool is_boolean, Type* expected_type, bool must_be_constant, bool is_sub)
{
    auto left_constant = left->is_constant();
    auto right_constant = right->is_constant();
    auto left_receives_type = receives_type(left);
    auto right_receives_type = receives_type(right);

    if (!expected_type && left_receives_type && right_receives_type)
    {
        if (left->id == right->id)
        {
            switch (left->id)
            {
                case ValueId::string_literal:
                    {
                        expected_type = get_slice_type(module, uint8(module));
                    } break;
                default:
                    report_error();
            }
        }
        else
        {
            report_error();
        }
    }

    if (!left_receives_type && !right_receives_type)
    {
        analyze_type(module, left, 0, { .must_be_constant = must_be_constant });
        analyze_type(module, right, 0, { .must_be_constant = must_be_constant });
    }
    else if (left_receives_type && !right_receives_type)
    {
        analyze_type(module, right, 0, { .must_be_constant = must_be_constant });
        analyze_type(module, left, right->type, { .must_be_constant = must_be_constant });
    }
    else if (!left_receives_type && right_receives_type)
    {
        analyze_type(module, left, 0, { .must_be_constant = must_be_constant });
        analyze_type(module, right, left->type, { .must_be_constant = must_be_constant });
    }
    else if (left_receives_type && right_receives_type)
    {
        assert(expected_type);
        if (is_boolean)
        {
            report_error();
        }

        analyze_type(module, left, expected_type, { .must_be_constant = must_be_constant });
        analyze_type(module, right, expected_type, { .must_be_constant = must_be_constant });
    }
    else
    {
        unreachable();
    }

    assert(left->type);
    assert(right->type);

    if (expected_type)
    {
        if (expected_type->id == TypeId::integer && left->type->id == TypeId::pointer && right->type->id == TypeId::pointer && is_sub)
        {
            check_types(module, left->type, right->type);
        }
        else if (!is_boolean)
        {
            typecheck(module, expected_type, left->type);
            typecheck(module, expected_type, right->type);
        }
    }
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
            .scope = &module->scope,
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
            auto initial_value = LLVMConstStringInContext2(module->llvm.context, (char*)field.name.pointer, field.name.length, false);
            u32 alignment = 1;
            auto name_global = llvm_create_global_variable(module->llvm.module, LLVMArrayType2(u8_type->llvm.abi, field.name.length + null_terminate), is_constant, LLVMInternalLinkage, initial_value, arena_join_string(module->arena, array_to_slice(name_parts)), LLVMNotThreadLocal, false, alignment, LLVMGlobalUnnamedAddr);
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
        auto name_array_variable = llvm_create_global_variable(module->llvm.module, name_array_type, is_constant, LLVMInternalLinkage, name_array, string_literal("name.array.enum"), LLVMNotThreadLocal, false, get_byte_alignment(slice_type), LLVMGlobalUnnamedAddr);

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

fn Type* get_build_mode_enum(Module* module)
{
    auto result = module->build_mode_enum;

    if (!result)
    {
        String enum_names[] = {
            string_literal("debug_none"),
            string_literal("debug"),
            string_literal("soft_optimize"),
            string_literal("optimize_for_speed"),
            string_literal("optimize_for_size"),
            string_literal("aggressively_optimize_for_speed"),
            string_literal("aggressively_optimize_for_size"),
        };

        auto enum_fields = arena_allocate<EnumField>(module->arena, array_length(enum_names));

        u64 field_value = 0;
        for (String enum_name : enum_names)
        {
            enum_fields[field_value] = {
                .name = enum_name,
                .value = field_value,
            };

            field_value += 1;
        }

        auto backing_type = integer_type(module, { .bit_count = array_length(enum_names) - 1, .is_signed = false });

        result = type_allocate_init(module, {
            .enumerator = {
                .fields = enum_fields,
                .backing_type = backing_type,
            },
            .id = TypeId::enumerator,
            .name = string_literal("BuildMode"),
            .scope = &module->scope,
        });
    }

    assert(result);
    return result;
}

fn void analyze_type(Module* module, Value* value, Type* expected_type, TypeAnalysis analysis)
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
                    if (analysis.indexing_type)
                    {
                        expected_type = uint64(module);
                    }
                }

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
                            analyze_type(module, extended_value, 0, { .must_be_constant = analysis.must_be_constant });
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

                            analyze_type(module, unary_value, 0, { .must_be_constant = analysis.must_be_constant });
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
                            analyze_type(module, unary_value, 0, { .must_be_constant = analysis.must_be_constant });
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
                            analyze_type(module, unary_value, 0, { .must_be_constant = analysis.must_be_constant });

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
                            analyze_type(module, unary_value, 0, { .must_be_constant = analysis.must_be_constant });

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

                            analyze_type(module, unary_value, 0, { .must_be_constant = analysis.must_be_constant });
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
                            analyze_type(module, unary_value, 0, { .must_be_constant = analysis.must_be_constant });
                            auto enum_type = unary_value->type;
                            resolve_type_in_place(module, enum_type);
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
                                auto llvm_function = llvm_module_create_function(module->arena, module->llvm.module, llvm_function_type, LLVMInternalLinkage, function_name);
                                LLVMSetFunctionCallConv(llvm_function, LLVMFastCallConv);

                                LLVMValueRef llvm_argument;
                                LLVMGetParams(llvm_function, &llvm_argument);

                                auto* entry_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "entry");
                                LLVMPositionBuilderAtEnd(module->llvm.builder, entry_block);

                                auto u32_type = uint32(module);
                                resolve_type_in_place(module, u32_type);
                                auto current_function = get_current_function(module);
                                auto old_alloca_insertion_point = current_function->variable.storage->function.llvm.alloca_insertion_point;
                                current_function->variable.storage->function.llvm.alloca_insertion_point = LLVMBuildAlloca(module->llvm.builder, u32_type->llvm.abi, "alloca_insert_point");

                                auto alloca = create_alloca(module, {
                                    .type = string_type,
                                    .name = string_literal("retval"),
                                });

                                auto* return_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "return_block");
                                auto* else_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "else_block");

                                auto enum_fields = enum_type->enumerator.fields;

                                auto switch_instruction = LLVMBuildSwitch(module->llvm.builder, llvm_argument, else_block, enum_fields.length);
                                auto backing_type = enum_type->llvm.abi;
                                assert(backing_type);
                                auto u64_type = uint64(module)->llvm.abi;

                                for (u64 i = 0; i < enum_fields.length; i += 1)
                                {
                                    auto& field = enum_fields[i];
                                    auto* case_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "case_block");
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

                                current_function->variable.storage->function.llvm.alloca_insertion_point = old_alloca_insertion_point;
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

                            analyze_type(module, unary_value, 0, { .must_be_constant = analysis.must_be_constant });
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
                    case UnaryId::enum_from_int:
                        {
                            if (!expected_type)
                            {
                                report_error();
                            }

                            if (expected_type->id != TypeId::enumerator)
                            {
                                report_error();
                            }

                            analyze_type(module, unary_value, expected_type->enumerator.backing_type, { .must_be_constant = analysis.must_be_constant });
                            auto unary_value_type = unary_value->type;
                            if (unary_value_type->id != TypeId::integer)
                            {
                                report_error();
                            }

                            if (get_bit_size(unary_value_type) != get_bit_size(expected_type))
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
                                analyze_type(module, unary_value, 0, { .must_be_constant = analysis.must_be_constant });
                                value_type = uint1(module);
                            }
                            else
                            {
                                analyze_type(module, unary_value, expected_type, { .must_be_constant = analysis.must_be_constant });
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

                if (unary_type_id == UnaryTypeId::enum_values)
                {
                    auto element_type = unary_type;

                    if (element_type->id != TypeId::enumerator)
                    {
                        report_error();
                    }

                    auto fields = unary_type->enumerator.fields;
                    auto element_count = fields.length;
                    if (element_count == 0)
                    {
                        report_error();
                    }

                    auto array_type = get_array_type(module, element_type, element_count);
                    switch (value->kind)
                    {
                        case ValueKind::right:
                            {
                                value_type = array_type;
                            } break;
                        case ValueKind::left:
                            {
                                value_type = get_pointer_type(module, array_type);
                            } break;
                    }
                }
                else
                {
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
                        case UnaryTypeId::enum_values:
                            {
                                unreachable();
                            } break;
                    }

                    if (value > max_value)
                    {
                        report_error();
                    }
                }

                typecheck(module, expected_type, value_type);
            } break;
        case ValueId::binary:
            {
                auto id = value->binary.id;
                auto is_boolean = binary_is_boolean(id);
                auto left = value->binary.left;
                auto right = value->binary.right;
                auto is_sub = id == BinaryId::sub;
                analyze_binary_type(module, left, right, is_boolean, expected_type, analysis.must_be_constant, is_sub);
                check_types(module, left->type, right->type);

                if (is_sub && left->type->id == TypeId::pointer && right->type->id == TypeId::pointer)
                {
                    assert(left->type == right->type);

                    auto u64_type = uint64(module);
                    auto s64_type = sint64(module);
                    auto left_int_from_pointer = new_value(module);
                    *left_int_from_pointer = {
                        .unary = {
                            .value = left,
                            .id = UnaryId::int_from_pointer,
                        },
                        .type = u64_type,
                        .id = ValueId::unary,
                    };
                    auto right_int_from_pointer = new_value(module);
                    *right_int_from_pointer = {
                        .unary = {
                            .value = right,
                            .id = UnaryId::int_from_pointer,
                        },
                        .type = u64_type,
                        .id = ValueId::unary,
                    };

                    value->type = s64_type;
                    value->binary.left = left_int_from_pointer;
                    value->binary.right = right_int_from_pointer;

                    auto sub = new_value(module);
                    *sub = *value;

                    auto size_constant = new_value(module);

                    assert(left->type->id == TypeId::pointer);
                    auto element_type = left->type->pointer.element_type;
                    *size_constant = {
                        .unary_type = {
                            .type = element_type,
                            .id = UnaryTypeId::byte_size,
                        },
                        .id = ValueId::unary_type,
                    };

                    analyze_type(module, size_constant, s64_type, { .must_be_constant = 1 });

                    *value = {
                        .binary = {
                            .left = sub,
                            .right = size_constant,
                            .id = BinaryId::div,
                        },
                        .id = ValueId::binary,
                    };
                    
                    if (expected_type)
                    {
                        trap();
                    }
                    else
                    {
                        value_type = s64_type;
                    }
                }
                else if (is_boolean)
                {
                    value_type = uint1(module);
                }
                else
                {
                    value_type = left->type;
                }
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
                analyze_type(module, callable, 0, { .must_be_constant = analysis.must_be_constant });
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
                                        auto* element_type = resolve_alias(module, variable_type->pointer.element_type);
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

                auto semantic_argument_types = function_type->function.base.semantic_argument_types;
                auto call_arguments = call->arguments;
                if (function_type->function.base.is_variable_arguments)
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
                    analyze_type(module, call_argument, argument_type, { .must_be_constant = analysis.must_be_constant });
                    check_types(module, argument_type, call_argument->type);
                }

                for (u64 i = semantic_argument_types.length; i < call_arguments.length; i += 1)
                {
                    auto* call_argument = call_arguments[i];
                    analyze_type(module, call_argument, 0, { .must_be_constant = analysis.must_be_constant });
                }

                auto semantic_return_type = function_type->function.base.semantic_return_type;
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
                        // TODO: use existing types?
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
                        analyze_type(module, value, element_type, { .must_be_constant = analysis.must_be_constant });
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
                        analyze_type(module, value, expected_type, { .must_be_constant = analysis.must_be_constant });

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
                auto array_like = value->array_expression.array_like;
                array_like->kind = ValueKind::left;
                analyze_type(module, array_like, 0, { .must_be_constant = analysis.must_be_constant });
                assert(array_like->kind == ValueKind::left);
                auto array_like_type = array_like->type;
                if (array_like_type->id != TypeId::pointer)
                {
                    report_error();
                }
                auto pointer_element_type = array_like_type->pointer.element_type;

                auto indexing_type = pointer_element_type->id == TypeId::enum_array ? pointer_element_type->enum_array.enum_type : uint64(module);

                analyze_type(module, value->array_expression.index, 0, { .indexing_type = indexing_type, .must_be_constant = analysis.must_be_constant });

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
                    case TypeId::enum_array:
                        {
                            element_type = pointer_element_type->enum_array.element_type;
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
                    expected_type = analysis.indexing_type;
                }

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
                analyze_type(module, aggregate, 0, { .must_be_constant = analysis.must_be_constant });

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
                                // Field not found
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
                    case TypeId::enum_array:
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
                                if (resolved_aggregate_type->id == TypeId::enum_array)
                                {
                                    auto enum_type = resolved_aggregate_type->enum_array.enum_type;
                                    auto backing_type = enum_type->enumerator.backing_type;
                                    value_type = backing_type;
                                }
                                else if (resolved_aggregate_type->id == TypeId::array)
                                {
                                    value_type = uint64(module);
                                }
                                else
                                {
                                    report_error();
                                }
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

                analyze_type(module, array_like, 0, { .must_be_constant = analysis.must_be_constant });

                auto pointer_type = array_like->type;
                if (pointer_type->id != TypeId::pointer)
                {
                    report_error();
                }

                Type* sliceable_type = resolve_alias(module, pointer_type->pointer.element_type);

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
                        analyze_type(module, index, index_type, { .must_be_constant = analysis.must_be_constant });

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
                auto u8_type = uint8(module);
                auto pointer_type = get_pointer_type(module, u8_type);
                auto slice_type = get_slice_type(module, u8_type);

                if (pointer_type == expected_type)
                {
                    value_type = expected_type;
                }
                else if (slice_type == expected_type)
                {
                    value_type = expected_type;
                }
                else
                {
                    typecheck(module, expected_type, slice_type);
                    value_type = slice_type;
                }
            } break;
        case ValueId::va_start:
            {
                auto va_list_type = get_va_list_type(module);
                typecheck(module, expected_type, va_list_type);
                value_type = va_list_type;
            } break;
        case ValueId::va_arg:
            {
                analyze_type(module, value->va_arg.va_list, get_pointer_type(module, get_va_list_type(module)), { .must_be_constant = analysis.must_be_constant });
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
                auto elements = value->aggregate_initialization.elements;
                auto zero = value->aggregate_initialization.zero;
                u64 field_mask = 0;

                // TODO: make consecutive initialization with `zero` constant
                // ie:
                // Right now 0, 1, 2, 3 => constant values, rest zeroed is constant because `declaration_index == initialization_index`
                // With constant initialization values 2, 3, 4 and rest zeroed, the aggregate initialization because `declaration_index != initialization_index`, that is, the first initialization index (0) does not match the declaration index (2). The same case can be applied for cases (1, 3) and (2, 4)

                Type* aggregate_type = 0;
                switch (value->kind)
                {
                    case ValueKind::left:
                        {
                            if (resolved_type->id != TypeId::pointer)
                            {
                                report_error();
                            }

                            aggregate_type = resolved_type->pointer.element_type;
                        } break;
                    case ValueKind::right:
                        {
                            aggregate_type = resolved_type;
                        } break;
                    default:
                }

                switch (aggregate_type->id)
                {
                    case TypeId::structure:
                        {
                            bool is_ordered = true;
                            auto fields = aggregate_type->structure.fields;
                            assert(fields.length <= 64);

                            auto same_values_as_field = fields.length == elements.length;
                            auto is_properly_initialized = same_values_as_field || zero;

                            if (zero && same_values_as_field)
                            {
                                report_error();
                            }

                            if (!is_properly_initialized)
                            {
                                report_error();
                            }

                            assert(elements.length <= fields.length);

                            for (u32 initialization_index = 0; initialization_index < elements.length; initialization_index += 1)
                            {
                                auto value = elements[initialization_index].value;
                                auto name = elements[initialization_index].name;

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

                                auto mask = (u64)1 << (u64)declaration_index;
                                auto current_mask = field_mask;
                                if (current_mask & mask)
                                {
                                    // Repeated field
                                    report_error();
                                }
                                field_mask = current_mask | mask;

                                is_ordered = is_ordered && declaration_index == initialization_index;

                                auto field = fields[declaration_index];
                                auto declaration_type = field.type;
                                analyze_type(module, value, declaration_type, { .must_be_constant = analysis.must_be_constant });
                                is_constant = is_constant && value->is_constant();
                            }

                            value->aggregate_initialization.is_constant = is_constant && is_ordered;
                        } break;
                    case TypeId::bits:
                        {
                            auto fields = aggregate_type->bits.fields;
                            assert(fields.length <= 64);

                            auto same_values_as_field = fields.length == elements.length;
                            auto is_properly_initialized = same_values_as_field || zero;

                            if (zero && same_values_as_field)
                            {
                                report_error();
                            }

                            if (!is_properly_initialized)
                            {
                                report_error();
                            }

                            assert(elements.length <= fields.length);

                            for (u32 initialization_index = 0; initialization_index < elements.length; initialization_index += 1)
                            {
                                auto value = elements[initialization_index].value;
                                auto name = elements[initialization_index].name;

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

                                auto mask = 1 << declaration_index;
                                auto current_mask = field_mask;
                                if (current_mask & mask)
                                {
                                    // Repeated field
                                    report_error();
                                }
                                field_mask = current_mask | mask;

                                auto field = fields[declaration_index];
                                auto declaration_type = field.type;
                                analyze_type(module, value, declaration_type, { .must_be_constant = analysis.must_be_constant });
                                is_constant = is_constant && value->is_constant();
                            }

                            value->aggregate_initialization.is_constant = is_constant;
                        } break;
                    case TypeId::union_type:
                        {
                            if (elements.length != 1)
                            {
                                report_error();
                            }

                            auto initialization_value = elements[0].value;
                            auto initialization_name = elements[0].name;

                            u64 i;
                            auto fields = aggregate_type->union_type.fields;
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
                            analyze_type(module, initialization_value, field->type, { .must_be_constant = analysis.must_be_constant });
                        } break;
                    case TypeId::enum_array:
                        {
                            bool is_ordered = true;
                            auto enum_type = aggregate_type->enum_array.enum_type;
                            auto element_type = aggregate_type->enum_array.element_type;
                            assert(enum_type->id == TypeId::enumerator);
                            auto fields = enum_type->enumerator.fields;

                            assert(fields.length <= 64);

                            auto same_values_as_field = fields.length == elements.length;
                            auto is_properly_initialized = same_values_as_field || zero;

                            if (zero && same_values_as_field)
                            {
                                report_error();
                            }

                            if (!is_properly_initialized)
                            {
                                report_error();
                            }

                            assert(elements.length <= fields.length);

                            for (u32 initialization_index = 0; initialization_index < elements.length; initialization_index += 1)
                            {
                                auto value = elements[initialization_index].value;
                                auto name = elements[initialization_index].name;

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

                                auto mask = 1 << declaration_index;
                                auto current_mask = field_mask;
                                if (current_mask & mask)
                                {
                                    // Repeated field
                                    report_error();
                                }
                                field_mask = current_mask | mask;

                                is_ordered = is_ordered && declaration_index == initialization_index;

                                analyze_type(module, value, element_type, { .must_be_constant = analysis.must_be_constant });
                                is_constant = is_constant && value->is_constant();
                            }

                            value->aggregate_initialization.is_constant = is_constant && is_ordered;
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
                analyze_type(module, condition, 0, { .must_be_constant = analysis.must_be_constant });
                auto is_boolean = false;
                analyze_binary_type(module, true_value, false_value, is_boolean, expected_type, analysis.must_be_constant, false);

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
                        .scope = enum_type->scope,
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
                    auto llvm_function = llvm_module_create_function(module->arena, module->llvm.module, llvm_function_type, LLVMInternalLinkage, function_name);
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
                    LLVMThreadLocalMode thread_local_mode = LLVMNotThreadLocal;
                    auto externally_initialized = false;
                    auto value_array_variable = llvm_create_global_variable(module->llvm.module, value_array_variable_type, is_constant, LLVMInternalLinkage, value_array, string_literal("value.array.enum"), thread_local_mode, externally_initialized, enum_alignment, LLVMGlobalUnnamedAddr);

                    auto* entry_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "entry");
                    auto* return_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "return_block");
                    auto* loop_entry_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "loop.entry");
                    auto* loop_body_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "loop.body");
                    auto* loop_exit_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "loop.exit");

                    LLVMPositionBuilderAtEnd(module->llvm.builder, entry_block);

                    auto current_function = get_current_function(module);
                    auto old_alloca_insertion_point = current_function->variable.storage->function.llvm.alloca_insertion_point;
                    auto u32_type = uint32(module);
                    resolve_type_in_place(module, u32_type);
                    current_function->variable.storage->function.llvm.alloca_insertion_point = LLVMBuildAlloca(module->llvm.builder, u32_type->llvm.abi, "alloca_insert_point");

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

                    auto* length_match_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "length.match");
                    auto* length_mismatch_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "length.mismatch");
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
                            auto llvm_function = llvm_module_create_function(module->arena, module->llvm.module, llvm_function_type, LLVMExternalLinkage, string_literal("memcmp"));
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
                    auto* content_match_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "content.match");
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

                    current_function->variable.storage->function.llvm.alloca_insertion_point = old_alloca_insertion_point;
                }

                auto struct_type = enum_type->enumerator.string_to_enum_struct_type;
                assert(struct_type);

                typecheck(module, expected_type, struct_type);

                auto string_type = get_slice_type(module, uint8(module));

                analyze_type(module, enum_string_value, string_type, { .must_be_constant = analysis.must_be_constant });
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
                                    .scope = &macro_instantiation->scope,
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
                        analyze_type(module, instantiation_argument, argument_type, { .must_be_constant = analysis.must_be_constant });
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
                        analyze_type(module, instantiation_argument, argument_type, { .must_be_constant = analysis.must_be_constant });
                    }
                }

                // END of scope
                module->current_macro_instantiation = current_macro_instantiation;
                module->current_function = current_function;
            } break;
        case ValueId::build_mode:
            {
                value_type = get_build_mode_enum(module);
                if (expected_type)
                {
                    // typecheck(module, expected_type);
                    trap();
                }

                typecheck(module, expected_type, value_type);
            } break;
        case ValueId::has_debug_info:
            {
                value_type = uint1(module);
                typecheck(module, expected_type, value_type);
            } break;
        case ValueId::field_parent_pointer:
            {
                auto field_pointer = value->field_parent_pointer.pointer;
                auto field_name = value->field_parent_pointer.name;

                if (!expected_type)
                {
                    report_error();
                }

                value_type = expected_type;

                if (value_type->id != TypeId::pointer)
                {
                    report_error();
                }

                auto aggregate_type = value_type->pointer.element_type;

                Type* field_type = 0;
                switch (aggregate_type->id)
                {
                    case TypeId::structure:
                        {
                            auto fields = aggregate_type->structure.fields;
                            for (auto& field : fields)
                            {
                                if (field_name.equal(field.name))
                                {
                                    field_type = field.type;
                                    break;
                                }
                            }
                        } break;
                    default: report_error();
                }

                if (!field_type)
                {
                    report_error();
                }

                auto pointer_to_field = get_pointer_type(module, field_type);
                analyze_type(module, field_pointer, pointer_to_field, {});
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
        auto gep = LLVMBuildStructGEP2(module->llvm.builder, source_type->llvm.abi, source_value, 0, "coerce.dive");
        if (first_field_type->id == TypeId::structure)
        {
            trap();
        }
        else
        {
            return { gep, first_field_type };
        }
    }
    else
    {
        return { source_value, source_type };
    }
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
            auto load = create_load(module, {
                .type = source_type,
                .pointer = source,
            });
            auto result = coerce_integer_or_pointer_to_integer_or_pointer(module, load, source_type, destination_type);
            return result;
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
                auto scalable_vector_type = false;
                if (scalable_vector_type)
                {
                    trap();
                }
                else
                {
                    // Coercion through memory
                    auto original_destination_alignment = get_byte_alignment(destination_type);
                    auto source_alignment = get_byte_alignment(source_type);
                    auto destination_alignment = MAX(original_destination_alignment, source_alignment);
                    auto destination_alloca = create_alloca(module, {
                        .type = destination_type,
                        .name = string_literal("coerce"),
                        .alignment = destination_alignment,
                    });
                    auto u64_type = uint64(module);
                    resolve_type_in_place(module, u64_type);
                    LLVMBuildMemCpy(module->llvm.builder, destination_alloca, destination_alignment, source, source_alignment, LLVMConstInt(u64_type->llvm.abi, source_size, false));
                    auto load = create_load(module, {
                        .type = destination_type,
                        .pointer = destination_alloca,
                        .alignment = destination_alignment,
                    });
                    result = load;
                }
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

    // TODO: this smells badly
    //destination_type != uint1(module)
    if (!type_is_abi_equal(module, source_type, destination_type) && destination_type->id == TypeId::structure)
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
        // Coercion through memory

        auto original_destination_alignment = get_byte_alignment(destination_type);
        auto source_alloca_alignment = MAX(original_destination_alignment, get_byte_alignment(source_type));
        auto source_alloca = create_alloca(module, {
            .type = source_type,
            .name = string_literal("coerce"),
            .alignment = source_alloca_alignment,
        });
        create_store(module, {
            .source = source_value,
            .destination = source_alloca,
            .type = source_type,
            .alignment = source_alloca_alignment,
        });

        auto u64_type = uint64(module);
        resolve_type_in_place(module, u64_type);
        LLVMBuildMemCpy(module->llvm.builder, destination_value, original_destination_alignment, source_alloca, source_alloca_alignment, LLVMConstInt(u64_type->llvm.abi, destination_size, false));
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
                emit_value(module, array_like, TypeKind::memory, false);

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
                    emit_value(module, start, TypeKind::memory, false);
                }

                if (end)
                {
                    emit_value(module, end, TypeKind::memory, false);
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
                LLVMThreadLocalMode tlm = LLVMNotThreadLocal;
                bool externally_initialized = false;
                u32 alignment = 1;
                auto global = llvm_create_global_variable(module->llvm.module, string_type, is_constant, LLVMInternalLinkage, constant_string, string_literal("const.string"), tlm, externally_initialized, alignment, LLVMGlobalUnnamedAddr);

                return { global, LLVMConstInt(uint64(module)->llvm.abi, length, false) };
            } break;
        default: unreachable();
    }
}

fn void invalidate_analysis(Module* module, Value* value)
{
    switch (value->id)
    {
        case ValueId::variable_reference:
        case ValueId::constant_integer:
        case ValueId::unary_type:
            break;
        case ValueId::aggregate_initialization:
            {
                auto elements = value->aggregate_initialization.elements;
                for (auto& element : elements)
                {
                    invalidate_analysis(module, element.value);
                }
            } break;
        case ValueId::field_access:
            {
                invalidate_analysis(module, value->field_access.aggregate);
            } break;
        case ValueId::binary:
            {
                invalidate_analysis(module, value->binary.left);
                invalidate_analysis(module, value->binary.right);
            } break;
        case ValueId::unary:
            {
                invalidate_analysis(module, value->unary.value);
            } break;
        case ValueId::slice_expression:
            {
                invalidate_analysis(module, value->slice_expression.array_like);
                auto start = value->slice_expression.start;
                auto end = value->slice_expression.end;

                if (start)
                {
                    invalidate_analysis(module, start);
                }

                if (end)
                {
                    invalidate_analysis(module, end);
                }
            } break;
        default: trap();
    }

    value->type = 0;
}

fn void reanalyze_type_as_left_value(Module* module, Value* value)
{
    assert(value->type);
    assert(value->kind == ValueKind::right);
    auto original_type = value->type;
    invalidate_analysis(module, value);
    value->kind = ValueKind::left;
    auto expected_type = value->id == ValueId::aggregate_initialization ? get_pointer_type(module, original_type) : 0;
    analyze_type(module, value, expected_type, {});
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
                            auto llvm_value = variable->storage->llvm;

                            switch (variable_type->id)
                            {
                                case TypeId::pointer:
                                    {
                                        auto element_type = resolve_alias(module, variable_type->pointer.element_type);
                                        switch (element_type->id)
                                        {
                                            case TypeId::function:
                                                {
                                                    llvm_callable = create_load(module, LoadOptions{
                                                        .type = get_pointer_type(module, raw_function_type),
                                                        .pointer = llvm_value,
                                                    });
                                                } break;
                                            default: report_error();
                                        }
                                    } break;
                                case TypeId::function: llvm_callable = llvm_value; break;
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

                auto& return_abi = raw_function_type->function.abi.return_abi;
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

                auto available_registers = raw_function_type->function.abi.available_registers;

                auto declaration_semantic_argument_count = raw_function_type->function.base.semantic_argument_types.length;
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
                        argument_abi = raw_function_type->function.abi.argument_abis[call_argument_index];
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

                    resolve_type_in_place(module, semantic_argument_type);

                    if (is_named_argument)
                    {
                        auto llvm_abi_argument_types = llvm_abi_argument_type_buffer_slice(argument_abi.abi_start)(0, argument_abi.abi_count);
                        auto destination_abi_argument_types = abi_argument_type_buffer_slice(argument_abi.abi_start)(0, argument_abi.abi_count);
                        auto source_abi_argument_types = raw_function_type->function.abi.abi_argument_types(argument_abi.abi_start)(0, argument_abi.abi_count);
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
                                    emit_value(module, semantic_call_argument_value, TypeKind::abi, false);

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

                                    // TODO: fix this hack and collapse it into the generic path
                                    if (coerce_to_type == uint8(module) && semantic_argument_type == uint1(module))
                                    {
                                        emit_value(module, semantic_call_argument_value, TypeKind::memory, false);
                                        llvm_abi_argument_value_buffer[abi_argument_count] = semantic_call_argument_value->llvm;
                                        abi_argument_count += 1;
                                    }
                                    else
                                    {
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
                                                if (src->kind == ValueKind::right && !src->is_constant())
                                                {
                                                    if (!type_is_slice(src->type))
                                                    {
                                                        switch (src->id)
                                                        {
                                                            case ValueId::aggregate_initialization:
                                                            case ValueId::variable_reference:
                                                            case ValueId::field_access:
                                                                {
                                                                    reanalyze_type_as_left_value(module, src);
                                                                } break;
                                                            default:
                                                                {
                                                                    trap();
                                                                } break;
                                                        }
                                                    }
                                                }

                                                emit_value(module, src, TypeKind::memory, false);
                                                auto destination_size = get_byte_size(coerce_to_type);
                                                auto source_size = get_byte_size(argument_abi.semantic_type);
                                                auto alignment = get_byte_alignment(argument_abi.semantic_type);

                                                LLVMValueRef source = src->llvm;
                                                if (source_size < destination_size)
                                                {
                                                    auto alloca = create_alloca(module, {
                                                            .type = argument_abi.semantic_type,
                                                            .name = string_literal("coerce"),
                                                            .alignment = alignment,
                                                            });
                                                    auto u64_type = uint64(module);
                                                    resolve_type_in_place(module, u64_type);
                                                    LLVMBuildMemCpy(module->llvm.builder, alloca, alignment, source, alignment, LLVMConstInt(u64_type->llvm.abi, source_size, false));
                                                    source = alloca;
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
                                                                                LLVMThreadLocalMode thread_local_mode = {};
                                                                                bool externally_initialized = false;
                                                                                auto alignment = get_byte_alignment(semantic_argument_type);

                                                                                auto global = llvm_create_global_variable(module->llvm.module, semantic_argument_type->llvm.memory, is_constant, linkage_type, semantic_call_argument_value->llvm, string_literal("const.struct"), thread_local_mode, externally_initialized, alignment, LLVMGlobalUnnamedAddr);

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
                                                                    case ValueId::zero:
                                                                        {
                                                                            for (u32 i = 0; i < coerce_fields.length; i += 1)
                                                                            {
                                                                                auto& field = coerce_fields[i];
                                                                                auto field_type = field.type;
                                                                                llvm_abi_argument_value_buffer[abi_argument_count] = LLVMConstNull(field_type->llvm.abi);
                                                                                abi_argument_count += 1;
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
                                                        v = LLVMConstNull(coerce_to_type->llvm.abi);
                                                    } break;
                                                default:
                                                    {
                                                        LLVMValueRef pointer = 0;
                                                        Type* pointer_type = 0;
                                                        if (src->type->id != TypeId::pointer)
                                                        {
                                                            auto type = src->type;
                                                            pointer_type = get_pointer_type(module, type);
                                                            if (src->id != ValueId::variable_reference)
                                                            {
                                                                pointer = create_alloca(module, {
                                                                        .type = type,
                                                                        .name = string_literal("my.coerce"),
                                                                        });
                                                                emit_assignment(module, pointer, pointer_type, src);
                                                            }
                                                            else
                                                            {
                                                                assert(src->id == ValueId::variable_reference);
                                                                assert(src->kind == ValueKind::right);
                                                                reanalyze_type_as_left_value(module, src);
                                                            }
                                                        }
                                                        else
                                                        {
                                                            trap();
                                                        }

                                                        assert(pointer_type);
                                                        assert(pointer_type->id == TypeId::pointer);
                                                        auto element_type = pointer_type->pointer.element_type;

                                                        if (!pointer)
                                                        {
                                                            assert(src->type->id == TypeId::pointer);
                                                            assert(src->type->llvm.abi == module->llvm.pointer_type);
                                                            emit_value(module, src, TypeKind::memory, false);
                                                            pointer = src->llvm;
                                                        }

                                                        auto source_type = element_type;
                                                        assert(source_type == argument_abi.semantic_type);
                                                        auto load = create_coerced_load(module, pointer, source_type, destination_type);

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
                                    assert(argument_abi.abi_start >= raw_function_type->function.abi.abi_argument_types.length || same_address_space);

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
                                            emit_value(module, semantic_call_argument_value, TypeKind::memory, true);

                                            bool is_constant = true;
                                            LLVMLinkage linkage_type = LLVMInternalLinkage;
                                            LLVMThreadLocalMode thread_local_mode = {};
                                            bool externally_initialized = false;
                                            auto alignment = get_byte_alignment(semantic_argument_type);

                                            auto global = llvm_create_global_variable(module->llvm.module, semantic_argument_type->llvm.memory, is_constant, linkage_type, semantic_call_argument_value->llvm, string_literal("indirect.const.aggregate"), thread_local_mode, externally_initialized, alignment, LLVMGlobalUnnamedAddr);

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
                                                        reanalyze_type_as_left_value(module, semantic_call_argument_value);
                                                        emit_value(module, semantic_call_argument_value, TypeKind::memory, false);
                                                        llvm_abi_argument_value_buffer[abi_argument_count] = semantic_call_argument_value->llvm;
                                                        abi_argument_count += 1;
                                                    } break;
                                                default:
                                                    {
                                                        assert(abi_argument_type->id == TypeId::pointer);
                                                        assert(abi_argument_type->pointer.element_type == semantic_call_argument_value->type);
                                                        auto alloca = create_alloca(module, {
                                                            .type = semantic_call_argument_value->type,
                                                            .name = string_literal("indirect.struct.passing"),
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

                auto declaration_abi_argument_count = raw_function_type->function.abi.abi_argument_types.length;

                if (raw_function_type->function.base.is_variable_arguments)
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

                LLVMSetInstructionCallConv(llvm_call, llvm_calling_convention(raw_function_type->function.base.calling_convention));

                emit_attributes(module, llvm_call, &LLVMAddCallSiteAttribute, {
                    .return_abi = return_abi,
                    .argument_abis = argument_abis,
                    .abi_argument_types = { .pointer = abi_argument_type_buffer, .length = abi_argument_count },
                    .abi_return_type = raw_function_type->function.abi.abi_return_type,
                    .attributes = {},
                    .call_site = true,
                });

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

                            auto source_value = llvm_call;
                            auto source_type = raw_function_type->function.abi.abi_return_type;
                            auto destination_size = get_byte_size(destination_type);
                            auto left_destination_size = destination_size - return_abi.attributes.direct.offset;
                            auto is_destination_volatile = false;

                            switch (return_abi.semantic_type->id)
                            {
                                case TypeId::structure:
                                    {
                                        if (return_abi.semantic_type->structure.fields.length > 0)
                                        {
                                            create_coerced_store(module, source_value, source_type, destination_pointer, destination_type, left_destination_size, is_destination_volatile);
                                        }
                                        else
                                        {
                                            trap();
                                        }
                                    } break;
                                case TypeId::array:
                                    {
                                        if (get_byte_size(return_abi.semantic_type) <= 8)
                                        {
                                            create_store(module, {
                                                .source = source_value,
                                                .destination = destination_pointer,
                                                .type = source_type,
                                            });
                                        }
                                        else
                                        {
                                            create_coerced_store(module, source_value, source_type, destination_pointer, destination_type, left_destination_size, is_destination_volatile);
                                        }
                                    } break;
                                default: unreachable();
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


fn LLVMValueRef emit_va_arg(Module* module, Value* value, LLVMValueRef left_llvm, Type* left_type, LLVMValueRef llvm_function)
{
    switch (value->id)
    {
        case ValueId::va_arg:
            {
                auto raw_va_list_type = get_va_list_type(module);

                auto va_list_value = value->va_arg.va_list;
                emit_value(module, va_list_value, TypeKind::memory, false);
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

                    auto* in_reg_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "va_arg.in_reg");
                    auto* in_mem_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "va_arg.in_mem");
                    auto* end_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "va_arg.end");
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
    switch (value->id)
    {
        case ValueId::field_access:
            {
                auto aggregate = value->field_access.aggregate;
                auto field_name = value->field_access.field_name;

                emit_value(module, aggregate, TypeKind::memory, false);

                assert(aggregate->kind == ValueKind::left);
                auto aggregate_type = aggregate->type;
                assert(aggregate_type->id == TypeId::pointer);
                auto aggregate_element_type = aggregate_type->pointer.element_type;

                Type* real_aggregate_type = aggregate_element_type->id == TypeId::pointer ? aggregate_element_type->pointer.element_type : aggregate_element_type;
                auto resolved_aggregate_type = resolve_alias(module, real_aggregate_type);
                resolve_type_in_place(module, resolved_aggregate_type);
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
                                        resolve_type_in_place(module, field_type);
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
                                                .kind = type_kind,
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
                    case TypeId::enum_array:
                    case TypeId::array:
                        {
                            assert(value->field_access.field_name.equal(string_literal("length")));
                            auto array_length_type = get_llvm_type(value->type, type_kind);
                            u64 array_element_count = 0;

                            switch (resolved_aggregate_type->id)
                            {
                                case TypeId::enum_array:
                                    {
                                        auto enum_type = resolved_aggregate_type->enum_array.enum_type;
                                        assert(enum_type->id == TypeId::enumerator);
                                        array_element_count = enum_type->enumerator.fields.length;
                                    } break;
                                case TypeId::array:
                                    {
                                        array_element_count = resolved_aggregate_type->array.element_count;
                                    } break;
                                default: unreachable();
                            }

                            assert(array_element_count);

                            auto result = LLVMConstInt(array_length_type, array_element_count, false);
                            return result;
                        } break;
                    default: unreachable();
                }
            } break;
        default: unreachable();
    }
}

fn void emit_assignment(Module* module, LLVMValueRef left_llvm, Type* left_type, Value* right)
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
                emit_value(module, right, type_kind, false);
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
                            auto element_type = resolved_value_type->array.element_type;
                            auto element_count = resolved_value_type->array.element_count;
                            auto uint64_type = uint64(module);
                            assert(values.length == element_count);
                            resolve_type_in_place(module, uint64_type);

                            if (right->array_initialization.is_constant)
                            {
                                emit_value(module, right, TypeKind::memory, false);

                                bool is_constant = true;
                                LLVMLinkage linkage_type = LLVMInternalLinkage;
                                LLVMThreadLocalMode thread_local_mode = {};
                                bool externally_initialized = false;
                                auto alignment = get_byte_alignment(resolved_value_type);

                                auto global = llvm_create_global_variable(module->llvm.module, value_type->llvm.memory, is_constant, linkage_type, right->llvm, string_literal("array.init"), thread_local_mode, externally_initialized, alignment, LLVMGlobalUnnamedAddr);

                                u64 memcpy_size = get_byte_size(resolved_value_type);
                                LLVMBuildMemCpy(module->llvm.builder, left_llvm, alignment, global, alignment, LLVMConstInt(uint64_type->llvm.abi, memcpy_size, false));
                            }
                            else
                            {
                                auto u64_zero = LLVMConstNull(uint64_type->llvm.abi);
                                auto pointer_to_element_type = get_pointer_type(module, element_type);

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
                            auto elements = right->aggregate_initialization.elements;
                            auto scope = right->aggregate_initialization.scope;
                            auto is_constant = right->aggregate_initialization.is_constant;
                            auto zero = right->aggregate_initialization.zero;
                            auto u64_type = uint64(module);
                            resolve_type_in_place(module, u64_type);
                            u64 byte_size = get_byte_size(value_type);
                            auto byte_size_value = LLVMConstInt(u64_type->llvm.abi, byte_size, false);
                            auto alignment = get_byte_alignment(value_type);

                            if (is_constant)
                            {
                                emit_value(module, right, TypeKind::memory, true);

                                LLVMLinkage linkage_type = LLVMInternalLinkage;
                                LLVMThreadLocalMode thread_local_mode = LLVMNotThreadLocal;
                                bool externally_initialized = false;
                                auto global = llvm_create_global_variable(module->llvm.module, value_type->llvm.memory, is_constant, linkage_type, right->llvm, string_literal("const.aggregate"), thread_local_mode, externally_initialized, alignment, LLVMGlobalUnnamedAddr);
                                LLVMBuildMemCpy(module->llvm.builder, left_llvm, alignment, global, alignment, byte_size_value);
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

                                            if (zero)
                                            {
                                                auto u8_type = uint8(module);
                                                resolve_type_in_place(module, u8_type);
                                                LLVMBuildMemSet(module->llvm.builder, left_llvm, LLVMConstNull(u8_type->llvm.memory), byte_size_value, alignment);
                                            }

                                            for (const auto& element : elements)
                                            {
                                                auto name = element.name;
                                                auto value = element.value;

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

                                                if (module->has_debug_info)
                                                {
                                                    auto debug_location = LLVMDIBuilderCreateDebugLocation(module->llvm.context, element.line, element.column, scope->llvm, module->llvm.inlined_at);
                                                    LLVMSetCurrentDebugLocation2(module->llvm.builder, debug_location);
                                                }

                                                field_mask |= 1 << declaration_index;
                                                max_field_index = MAX(max_field_index, declaration_index);
                                                auto& field = fields[declaration_index];
                                                auto destination_pointer = LLVMBuildStructGEP2(module->llvm.builder, resolved_value_type->llvm.memory, left_llvm, declaration_index, "");
                                                emit_assignment(module, destination_pointer, get_pointer_type(module, field.type), value);
                                            }
                                        } break;
                                    case TypeId::union_type:
                                        {
                                            assert(elements.length == 1);
                                            auto fields = resolved_value_type->union_type.fields;
                                            auto biggest_field_index = resolved_value_type->union_type.biggest_field;
                                            auto& biggest_field = fields[biggest_field_index];
                                            auto biggest_field_type = fields[biggest_field_index].type;
                                            auto value = elements[0].value;
                                            auto field_value_type = value->type;
                                            auto field_type_size = get_byte_size(field_value_type);

                                            LLVMTypeRef struct_type;
                                            auto union_size = resolved_value_type->union_type.byte_size;

                                            if (field_type_size < union_size)
                                            {
                                                auto u8_type = uint8(module);
                                                resolve_type_in_place(module, u8_type);
                                                LLVMBuildMemSet(module->llvm.builder, left_llvm, LLVMConstNull(u8_type->llvm.memory), LLVMConstInt(u64_type->llvm.memory, union_size, false), alignment);
                                            }
                                            else if (field_type_size > union_size)
                                            {
                                                unreachable();
                                            }

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
                            auto result = emit_va_arg(module, right, left_llvm, left_type, llvm_function);
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
                            emit_value(module, right, TypeKind::memory, false);

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
                    case ValueId::array_expression:
                        {
                            emit_value(module, right, TypeKind::memory, false);
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
                    case BinaryId::max:
                    case BinaryId::min:
                        {
                            IntrinsicIndex intrinsic;
                            switch (resolved_value_type->id)
                            {
                                case TypeId::integer:
                                    {
                                        auto is_signed = resolved_value_type->integer.is_signed; 
                                        switch (id)
                                        {
                                            case BinaryId::max:
                                                {
                                                    intrinsic = is_signed ? IntrinsicIndex::smax : IntrinsicIndex::umax;
                                                } break;
                                            case BinaryId::min:
                                                {
                                                    intrinsic = is_signed ? IntrinsicIndex::smin : IntrinsicIndex::umin;
                                                } break;
                                            default: unreachable();
                                        }
                                    } break;
                                default: report_error();
                            }
                            LLVMTypeRef argument_types[] = { resolved_value_type->llvm.abi };
                            LLVMValueRef argument_values[] = { left, right };
                            auto llvm_value = emit_intrinsic_call(module, intrinsic, array_to_slice(argument_types), array_to_slice(argument_values));
                            return llvm_value;
                        } break;
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

                LLVMMetadataRef caller_debug_location = 0;
                if (module->has_debug_info)
                {
                    assert(!module->llvm.inlined_at);
                    caller_debug_location = LLVMDIBuilderCreateDebugLocation(module->llvm.context, macro_instantiation->line, macro_instantiation->column, macro_instantiation->scope.parent->llvm, 0);
                    LLVMSetCurrentDebugLocation2(module->llvm.builder, caller_debug_location);
                }

                for (Value* instantiation_argument: macro_instantiation->instantiation_arguments)
                {
                    emit_value(module, instantiation_argument, TypeKind::abi, false);
                }

                auto older_inlined_at = module->llvm.inlined_at;
                assert(!older_inlined_at);
                module->llvm.inlined_at = caller_debug_location;

                auto llvm_function = current_function->variable.storage->llvm;
                auto* entry_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "macro.entry");

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

                auto* return_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "macro.return_block");
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

fn LLVMValueRef emit_constant_array(Module* module, Slice<Value*> elements, Type* element_type)
{
    LLVMValueRef value_buffer[128];
    assert(elements.length <= array_length(value_buffer));

    resolve_type_in_place(module, element_type);

    for (u64 i = 0; i < elements.length; i += 1)
    {
        auto* v = elements[i];
        emit_value(module, v, TypeKind::memory, true);
        value_buffer[i] = v->llvm;
    }

    auto constant_array = LLVMConstArray2(element_type->llvm.memory, value_buffer, elements.length);
    return constant_array;
}

fn void emit_value(Module* module, Value* value, TypeKind type_kind, bool expect_constant)
{
    auto must_be_constant = expect_constant || (!module->current_function && !module->current_macro_instantiation);
    Global* parent_function_global = 0;
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
        assert(must_be_constant);
    }

    LLVMValueRef llvm_function = 0;
    if (parent_function_global)
    {
        llvm_function = parent_function_global->variable.storage->llvm;
        assert(llvm_function);
    }

    assert(value->type);
    assert(!value->llvm);
    auto resolved_value_type = resolve_alias(module, value->type);
    resolve_type_in_place(module, resolved_value_type);


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
                if (unary_id == UnaryId::truncate || unary_id == UnaryId::enum_name)
                {
                    type_kind = TypeKind::abi;
                }
                emit_value(module, unary_value, type_kind, must_be_constant);
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
                    case UnaryId::enum_from_int:
                        {
                            llvm_value = llvm_unary_value;
                        } break;
                    case UnaryId::leading_zeroes:
                    case UnaryId::trailing_zeroes:
                        {
                            auto intrinsic = unary_id == UnaryId::leading_zeroes ? IntrinsicIndex::clz : IntrinsicIndex::ctz;
                            auto u1_type = uint1(module);
                            resolve_type_in_place(module, u1_type);
                            auto zero_is_poison = LLVMConstNull(u1_type->llvm.abi);
                            LLVMValueRef values[] = { llvm_unary_value, zero_is_poison };
                            LLVMTypeRef types[] = { destination_type };
                            llvm_value = emit_intrinsic_call(module, intrinsic, array_to_slice(types), array_to_slice(values));
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
                    case UnaryTypeId::enum_values:
                        {
                            LLVMValueRef buffer[64];
                            assert(type_kind == TypeKind::memory);
                            assert(unary_type->id == TypeId::enumerator);
                            auto fields = unary_type->enumerator.fields;
                            auto llvm_enum_type = unary_type->llvm.memory;
                            u64 i = 0;
                            for (auto& field : fields)
                            {
                                auto v = field.value;
                                buffer[i] = LLVMConstInt(llvm_enum_type, v, false);
                                i += 1;
                            }
                            auto array_value = LLVMConstArray2(llvm_enum_type, buffer, i);

                            switch (value->kind)
                            {
                                case ValueKind::right:
                                    {
                                        llvm_value = array_value;
                                    } break;
                                case ValueKind::left:
                                    {
                                        auto is_constant = true;
                                        assert(resolved_value_type->id == TypeId::pointer);
                                        auto array_type = resolved_value_type->pointer.element_type;
                                        assert(array_type->id == TypeId::array);
                                        resolve_type_in_place(module, array_type);
                                        auto alignment = get_byte_alignment(resolved_value_type);
                                        auto value_array_variable = llvm_create_global_variable(module->llvm.module, array_type->llvm.memory, is_constant, LLVMInternalLinkage, array_value, string_literal("enum.values"), LLVMNotThreadLocal, 0, alignment, LLVMGlobalUnnamedAddr);
                                        llvm_value = value_array_variable;
                                    } break;
                            }
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

                    auto* right_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "shortcircuit.right");
                    auto* end_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "shortcircuit.end");

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

                    emit_value(module, left, TypeKind::abi, must_be_constant);
                    auto llvm_condition = emit_condition(module, left);
                    auto current_basic_block = LLVMGetInsertBlock(module->llvm.builder);

                    LLVMBuildCondBr(module->llvm.builder, llvm_condition, true_block, false_block);

                    LLVMPositionBuilderAtEnd(module->llvm.builder, right_block);

                    auto* right = value->binary.right;
                    if (right->llvm)
                    {
                        assert(false); // TODO: check if this if is really necessary
                    }
                    else
                    {
                        emit_value(module, right, TypeKind::abi, must_be_constant);
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
                            llvm_value = memory_to_abi(module, llvm_value, boolean_type);
                            break;
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
                            emit_value(module, binary_value, TypeKind::abi, must_be_constant);
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
                                            .kind = type_kind,
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

                if (value->array_initialization.is_constant)
                {
                    assert(value->kind == ValueKind::right);
                    auto element_type = resolved_value_type->array.element_type;
                    llvm_value = emit_constant_array(module, values, element_type);
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
                                    .name = string_literal("array.init"),
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
                            emit_value(module, array_like, TypeKind::memory, must_be_constant);
                            emit_value(module, index, TypeKind::memory, must_be_constant);

                            auto array_like_type = array_like->type;
                            assert(array_like_type->id == TypeId::pointer);
                            auto pointer_element_type = array_like_type->pointer.element_type;

                            switch (pointer_element_type->id) 
                            {
                                case TypeId::enum_array:
                                case TypeId::array:
                                    {
                                        auto array_type = pointer_element_type;

                                        auto uint64_type = uint64(module);
                                        resolve_type_in_place(module, uint64_type);
                                        auto u64_llvm = uint64_type->llvm.abi;
                                        auto zero_index = LLVMConstNull(u64_llvm);

                                        Type* element_type = 0;
                                        LLVMValueRef llvm_index = index->llvm;

                                        switch (pointer_element_type->id)
                                        {
                                            case TypeId::array:
                                                {
                                                    element_type = array_type->array.element_type;
                                                } break;
                                            case TypeId::enum_array:
                                                {
                                                    auto enum_type = array_type->enum_array.enum_type;
                                                    assert(enum_type->id == TypeId::enumerator);
                                                    auto enumerator_size = get_bit_size(enum_type->enumerator.backing_type);
                                                    if (enumerator_size != 64)
                                                    {
                                                        llvm_index = LLVMBuildIntCast2(module->llvm.builder, llvm_index, u64_llvm, false, "");
                                                    }
                                                    element_type = array_type->enum_array.element_type;
                                                } break;
                                            default: unreachable();
                                        }

                                        assert(element_type);
                                        assert(llvm_index);

                                        LLVMValueRef indices[] = { zero_index, llvm_index };
                                        auto gep = create_gep(module, {
                                            .type = array_type->llvm.memory,
                                            .pointer = array_like->llvm,
                                            .indices = array_to_slice(indices),
                                        });

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
                llvm_value = emit_va_arg(module, value, 0, 0, llvm_function);
            } break;
        case ValueId::aggregate_initialization:
            {
                auto elements = value->aggregate_initialization.elements;
                auto is_constant = value->aggregate_initialization.is_constant;
                auto zero = value->aggregate_initialization.zero;

                switch (value->kind)
                {
                    case ValueKind::left:
                        {
                            if (resolved_value_type->id != TypeId::pointer)
                            {
                                report_error();
                            }

                            auto aggregate_type = resolved_value_type->pointer.element_type;
                            
                            auto alloca = create_alloca(module, {
                                .type = aggregate_type,
                            });
                            auto resolved_pointer_type = resolved_value_type;
                            auto old_type = value->type;
                            // Overwrite type so asserts are not triggered
                            value->type = aggregate_type;
                            emit_assignment(module, alloca, resolved_pointer_type, value);
                            value->type = old_type;
                            llvm_value = alloca;
                        } break;
                    case ValueKind::right:
                        {
                            switch (resolved_value_type->id)
                            {
                                case TypeId::structure:
                                    {
                                        auto fields = resolved_value_type->structure.fields;

                                        if (is_constant)
                                        {
                                            LLVMValueRef constant_buffer[64];
                                            u32 constant_count = (u32)elements.length;

                                            for (u64 i = 0; i < elements.length; i += 1)
                                            {
                                                auto* value = elements[i].value;
                                                emit_value(module, value, TypeKind::memory, must_be_constant);
                                                auto llvm_value = value->llvm;
                                                assert(llvm_value);
                                                assert(LLVMIsAConstant(llvm_value));
                                                constant_buffer[i] = llvm_value;
                                            }

                                            if (zero)
                                            {
                                                if (elements.length == fields.length)
                                                {
                                                    unreachable();
                                                }

                                                for (u64 i = elements.length; i < fields.length; i += 1)
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
                                            // TODO: shouldn't this be a left value?
                                            unreachable();
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

                                            for (u32 initialization_index = 0; initialization_index < elements.length; initialization_index += 1)
                                            {
                                                auto value = elements[initialization_index].value;
                                                auto name = elements[initialization_index].name;

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
                                                    case ValueId::enum_literal:
                                                        {
                                                            auto enum_name = value->enum_literal;
                                                            auto value_type = value->type;
                                                            assert(value_type->id == TypeId::enumerator);
                                                            
                                                            for (auto& field: value_type->enumerator.fields)
                                                            {
                                                                if (enum_name.equal(field.name))
                                                                {
                                                                    field_value = field.value;
                                                                    break;
                                                                }
                                                            }
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

                                            for (u32 initialization_index = 0; initialization_index < elements.length; initialization_index += 1)
                                            {
                                                auto value = elements[initialization_index].value;
                                                auto name = elements[initialization_index].name;

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

                                                emit_value(module, value, TypeKind::memory, must_be_constant);

                                                auto extended = LLVMBuildZExt(module->llvm.builder, value->llvm, abi_type, "");
                                                auto shl = LLVMBuildShl(module->llvm.builder, extended, LLVMConstInt(abi_type, field.offset, false), "");
                                                auto or_value = LLVMBuildOr(module->llvm.builder, llvm_value, shl, "");
                                                llvm_value = or_value;
                                            }
                                        }
                                    } break;
                                case TypeId::enum_array:
                                    {
                                        assert(is_constant);
                                        assert(elements.length <= 64);
                                        Value* value_buffer[64];
                                        for (u64 i = 0; i < elements.length; i += 1)
                                        {
                                            value_buffer[i] = elements[i].value;
                                        }
                                        Slice<Value*> values = { value_buffer, elements.length };
                                        auto element_type = resolved_value_type->enum_array.element_type;
                                        llvm_value = emit_constant_array(module, values, element_type);
                                    } break;
                                default: unreachable();
                            }
                        } break;
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

                emit_value(module, condition, TypeKind::abi, must_be_constant);
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

                emit_value(module, true_value, type_kind, must_be_constant);
                emit_value(module, false_value, type_kind, must_be_constant);

                llvm_value = LLVMBuildSelect(module->llvm.builder, llvm_condition, true_value->llvm, false_value->llvm, "");
            } break;
        case ValueId::unreachable:
            {
                if (module->has_debug_info && !build_mode_is_optimized(module->build_mode))
                {
                    emit_intrinsic_call(module, IntrinsicIndex::trap, {}, {});
                }
                llvm_value = LLVMBuildUnreachable(module->llvm.builder);
                LLVMClearInsertionPosition(module->llvm.builder);
            } break;
        case ValueId::string_to_enum:
            {
                auto enum_type = value->string_to_enum.type;
                auto string_value = value->string_to_enum.string;
                emit_value(module, string_value, TypeKind::memory, must_be_constant);
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
                auto string_literal = emit_string_literal(module, value);
                switch (resolved_value_type->id)
                {
                    case TypeId::structure:
                        {
                            llvm_value = emit_slice_result(module, string_literal, resolved_value_type->llvm.abi);
                        } break;
                    case TypeId::pointer:
                        {
                            llvm_value = string_literal.values[0];
                        } break;
                    default:
                        report_error();
                }
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
        case ValueId::build_mode:
            {
                llvm_value = LLVMConstInt(get_llvm_type(resolved_value_type->enumerator.backing_type, type_kind), (u64)module->build_mode, false);
            } break;
        case ValueId::has_debug_info:
            {
                llvm_value = LLVMConstInt(get_llvm_type(resolved_value_type, type_kind), module->has_debug_info, false);
            } break;
        case ValueId::field_parent_pointer:
            {
                auto field_pointer = value->field_parent_pointer.pointer;
                auto field_name = value->field_parent_pointer.name;

                emit_value(module, field_pointer, TypeKind::memory, false);
                auto llvm_field_pointer = field_pointer->llvm;
                assert(llvm_field_pointer);

                assert(resolved_value_type->id == TypeId::pointer);
                auto aggregate_type = resolved_value_type->pointer.element_type;

                switch (aggregate_type->id)
                {
                    case TypeId::structure:
                        {
                            auto fields = aggregate_type->structure.fields;
                            Field* result_field = 0;
                            for (auto& field: fields)
                            {
                                if (field_name.equal(field.name))
                                {
                                    result_field = &field;
                                    break;
                                }
                            }

                            assert(result_field);
                            auto offset = result_field->offset;
                            auto u64_type = uint64(module);
                            resolve_type_in_place(module, u64_type);
                            auto llvm_u64 = u64_type->llvm.abi;
                            auto address_int = LLVMBuildPtrToInt(module->llvm.builder, llvm_field_pointer, llvm_u64, "");

                            address_int = LLVMBuildSub(module->llvm.builder, address_int, LLVMConstInt(llvm_u64, offset, false), "");

                            auto address_pointer = LLVMBuildIntToPtr(module->llvm.builder, address_int, resolved_value_type->llvm.abi, "");
                            llvm_value = address_pointer;
                        } break;
                    default:
                        report_error();
                }
            } break;
        default: unreachable();
    }

    assert(llvm_value);
    value->llvm = llvm_value;
}

fn void analyze_value(Module* module, Value* value, Type* expected_type, TypeKind type_kind, bool must_be_constant)
{
    analyze_type(module, value, expected_type, { .must_be_constant = must_be_constant });
    emit_value(module, value, type_kind, must_be_constant);
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
                    auto& return_abi = function_type.abi.return_abi;

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

                                analyze_type(module, return_value, return_abi.semantic_type, {});
                                auto pointer_type = get_pointer_type(module, return_abi.semantic_type);
                                emit_assignment(module, return_alloca, pointer_type, return_value);
                            } break;
                    }

                    auto return_block = parent_function_global->variable.storage->function.llvm.return_block;
                    LLVMBuildBr(module->llvm.builder, return_block);
                    LLVMClearInsertionPosition(module->llvm.builder);
                }
                else if (module->current_macro_instantiation)
                {
                    auto macro_instantiation = module->current_macro_instantiation;
                    auto return_type = macro_instantiation->return_type;
                    assert(return_type);
                    analyze_type(module, return_value, return_type, {});
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
                analyze_type(module, local->variable.initial_value, expected_type, {});
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
                auto* taken_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "if.taken");
                auto* not_taken_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "if.not_taken");
                auto* exit_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "if.exit");

                auto condition = statement->if_st.condition;
                analyze_value(module, condition, 0, TypeKind::abi, false);
                auto llvm_condition = emit_condition(module, condition);

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
                analyze_value(module, statement->expression, 0, TypeKind::memory, false);
            } break;
        case StatementId::while_st:
            {
                auto* entry_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "while.entry");
                LLVMBuildBr(module->llvm.builder, entry_block);
                LLVMPositionBuilderAtEnd(module->llvm.builder, entry_block);

                auto body_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "while.body");
                auto continue_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "while.continue");
                auto exit_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "while.exit");

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
                    analyze_value(module, condition, 0, TypeKind::abi, false);
                    auto llvm_condition = emit_condition(module, condition);

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

                if (!LLVMGetFirstUse((LLVMValueRef)body_block))
                {
                    trap();
                }

                if (!LLVMGetFirstUse((LLVMValueRef)exit_block))
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
                analyze_value(module, left, 0, TypeKind::memory, false);

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
                            analyze_type(module, right, element_type, {});
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
                            analyze_value(module, right, element_type, TypeKind::abi, false);
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
                auto* exit_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "switch.exit");

                auto discriminant = statement->switch_st.discriminant;
                auto clauses = statement->switch_st.clauses;
                analyze_value(module, discriminant, 0, TypeKind::abi, false);
                
                auto discriminant_type = discriminant->type;

                u32 invalid_clause_index = ~(u32)0;
                u32 else_clause_index = invalid_clause_index;
                u32 discriminant_case_count = 0;

                // TODO: more analysis
                switch (discriminant_type->id)
                {
                    case TypeId::enumerator:
                        {
                        } break;
                    case TypeId::integer:
                        {
                        } break;
                    default: report_error();
                }

                for (u64 i = 0; i < clauses.length; i += 1)
                {
                    auto& clause = clauses[i];
                    clause.basic_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, clause.values.length == 0 ? "switch.else_case_block" : "switch.case_block");
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
                        for (auto& value: clause.values)
                        {
                            switch (value.id)
                            {
                                case ClauseDiscriminantId::single:
                                    {
                                        assert(value.single);
                                        analyze_value(module, value.single, discriminant_type, TypeKind::abi, true);
                                    } break;
                                case ClauseDiscriminantId::range:
                                    {
                                        auto start = value.range[0];
                                        auto end = value.range[1];
                                        for (auto v : value.range)
                                        {
                                            analyze_value(module, v, discriminant_type, TypeKind::abi, true);
                                        }

                                        if (start->id != end->id)
                                        {
                                            report_error();
                                        }

                                        switch (start->id)
                                        {
                                            case ValueId::constant_integer:
                                                {
                                                    if (start->constant_integer.value >= end->constant_integer.value)
                                                    {
                                                        report_error();
                                                    }
                                                } break;
                                            default: report_error();
                                        }
                                    } break;
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
                    else_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "switch.else_case_block");
                }

                auto switch_instruction = LLVMBuildSwitch(module->llvm.builder, discriminant->llvm, else_block, discriminant_case_count);
                bool all_blocks_terminated = true;

                for (auto& clause : clauses)
                {
                    for (const auto& value : clause.values)
                    {
                        switch (value.id)
                        {
                            case ClauseDiscriminantId::single:
                                {
                                    LLVMAddCase(switch_instruction, value.single->llvm, clause.basic_block);
                                } break;
                            case ClauseDiscriminantId::range:
                                {
                                    auto start = value.range[0];
                                    auto end = value.range[1];

                                    LLVMAddCase(switch_instruction, start->llvm, clause.basic_block);

                                    switch (start->id)
                                    {
                                        case ValueId::constant_integer:
                                            {
                                                auto start_value = start->constant_integer.value;
                                                auto end_value = end->constant_integer.value;

                                                for (u64 i = start_value + 1; i < end_value; i += 1)
                                                {
                                                    LLVMAddCase(switch_instruction, LLVMConstInt(start->type->llvm.abi, i, false), clause.basic_block);
                                                }

                                            } break;
                                        default: unreachable();
                                    }

                                    LLVMAddCase(switch_instruction, end->llvm, clause.basic_block);
                                } break;
                        }
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
                    if (module->has_debug_info && !build_mode_is_optimized(module->build_mode))
                    {
                        emit_intrinsic_call(module, IntrinsicIndex::trap, {}, {});
                    }
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

                auto* entry_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "for_each.entry");
                auto* body_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "for_each.body");
                auto* continue_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "for_each.continue");
                auto* exit_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "for_each.exit");

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

                                analyze_type(module, right, 0, {});

                                if (right->kind == ValueKind::right)
                                {
                                    if (!is_slice(right->type))
                                    {
                                        reanalyze_type_as_left_value(module, right);
                                    }
                                }

                                Type* aggregate_type = 0;

                                if (right->kind == ValueKind::left && right->type->id != TypeId::pointer)
                                {
                                    if (!type_is_slice(right->type))
                                    {
                                        report_error();
                                    }

                                    right->kind = ValueKind::right;
                                }

                                switch (right->kind)
                                {
                                    case ValueKind::right:
                                        {
                                            aggregate_type = right->type;
                                            assert(is_slice(aggregate_type));
                                        } break;
                                    case ValueKind::left:
                                        {
                                            auto pointer_type = right->type;
                                            if (pointer_type->id != TypeId::pointer)
                                            {
                                                report_error();
                                            }

                                            aggregate_type = pointer_type->pointer.element_type;
                                        } break;
                                }

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
                                emit_value(module, right, TypeKind::memory, false);
                            }

                            assert(!local);

                            LLVMValueRef length_value = 0;

                            for (auto value : right_values)
                            {
                                Type* aggregate_type = 0;
                                auto value_type = value->type;

                                switch (value->kind)
                                {
                                    case ValueKind::right:
                                        {
                                            aggregate_type = value_type;
                                        } break;
                                    case ValueKind::left:
                                        {
                                            if (value_type->id != TypeId::pointer)
                                            {
                                                report_error();
                                            }

                                            aggregate_type = value_type->pointer.element_type;
                                        } break;
                                }

                                assert(aggregate_type);

                                auto llvm_value = value->llvm;

                                switch (aggregate_type->id)
                                {
                                    case TypeId::array:
                                        {
                                            assert(value->kind == ValueKind::left);
                                            length_value = LLVMConstInt(index_type->llvm.abi, aggregate_type->array.element_count, false);
                                        } break;
                                    case TypeId::structure:
                                        {
                                            assert(aggregate_type->structure.is_slice);

                                            switch (value->kind)
                                            {
                                                case ValueKind::right:
                                                    {
                                                        length_value = LLVMBuildExtractValue(module->llvm.builder, llvm_value, 1, "slice.length");
                                                    } break;
                                                case ValueKind::left:
                                                    {
                                                        auto gep = LLVMBuildStructGEP2(module->llvm.builder, aggregate_type->llvm.abi, llvm_value, 1, "slice.length.pointer");
                                                        auto load = create_load(module, {
                                                            .type = index_type,
                                                            .pointer = gep,
                                                        });
                                                        length_value = load;
                                                    } break;
                                            }

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
                                auto variable_kind = left_values[i];
                                auto right = right_values[i];

                                auto right_type = right->type;
                                auto right_kind = right->kind;
                                auto right_llvm = right->llvm;

                                Type* aggregate_type = 0;
                                switch (right_kind)
                                {
                                    case ValueKind::right:
                                        {
                                            aggregate_type = right_type;
                                        } break;
                                    case ValueKind::left:
                                        {
                                            assert(right_type->id == TypeId::pointer);
                                            aggregate_type = right_type->pointer.element_type;
                                        } break;
                                }

                                assert(aggregate_type);

                                LLVMValueRef element_pointer_value = 0;

                                switch (aggregate_type->id)
                                {
                                    case TypeId::array:
                                        {
                                            assert(right_kind == ValueKind::left);
                                            LLVMValueRef indices[] = {
                                                index_zero,
                                                body_index_load,
                                            };
                                            element_pointer_value = create_gep(module, {
                                                .type = aggregate_type->llvm.memory,
                                                .pointer = right_llvm,
                                                .indices = array_to_slice(indices),
                                            });
                                        } break;
                                    case TypeId::structure:
                                        {
                                            assert(aggregate_type->structure.is_slice);

                                            if (right_kind == ValueKind::left)
                                            {
                                                right_llvm = create_load(module, {
                                                    .type = aggregate_type,
                                                    .pointer = right_llvm,
                                                });
                                            }

                                            auto extract_pointer = LLVMBuildExtractValue(module->llvm.builder, right_llvm, 0, "");

                                            LLVMValueRef indices[] = {
                                                body_index_load,
                                            };
                                            auto gep_type = aggregate_type->structure.fields[0].type->pointer.element_type;
                                            resolve_type_in_place(module, gep_type);
                                            auto gep = create_gep(module, {
                                                .type = gep_type->llvm.memory,
                                                .pointer = extract_pointer,
                                                .indices = array_to_slice(indices),
                                            });
                                            element_pointer_value = gep;
                                        } break;
                                    default: unreachable();
                                }

                                assert(element_pointer_value);

                                auto local_type = local->variable.type;

                                switch (variable_kind)
                                {
                                    case ValueKind::right:
                                        {
                                            auto evaluation_kind = get_evaluation_kind(local_type);
                                            if (evaluation_kind == EvaluationKind::scalar || (aggregate_type->id == TypeId::structure && aggregate_type->structure.is_slice) || (local_type->id == TypeId::structure && local_type->structure.is_slice))
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

                            assert(!local);

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

                                if (start->is_constant())
                                {
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
                                                            analyze_type(module, end, 0, {});
                                                            auto end_type = end->type;
                                                            assert(end_type);
                                                            start->type = end_type;
                                                            local_type = end_type;
                                                        } break;
                                                }
                                            } break;
                                        default: trap();
                                    }
                                }
                                else
                                {
                                    analyze_binary_type(module, start, end, false, 0, false, false);
                                    assert(start->type == end->type);
                                    local_type = start->type;
                                }

                                assert(local_type);

                                for (auto right: right_values)
                                {
                                    if (!right->type)
                                    {
                                        analyze_type(module, right, local_type, {});
                                    }
                                }

                                local->variable.type = local_type;
                                emit_local_variable(module, local);
                                emit_value(module, start, TypeKind::memory, false);

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
                                emit_value(module, end, TypeKind::abi, false);
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
        .file_type = BBLLVMCodeGenerationFileType::object_file,
        .optimize_when_possible = options.optimization_level > BBLLVMOptimizationLevel::O0,
        .verify_module = true,
    };
    auto result = llvm_module_run_code_generation_pipeline(module, target_machine, &code_generation_options);
    return result;
}

fn void link(Module* module)
{
    Arena* arena = module->arena;
    ArgBuilder builder;
    builder.add("ld.lld");
    builder.add("--error-limit=0");
    builder.add("-o");
    assert(module->executable.pointer[module->executable.length] == 0);
    builder.add((char*)module->executable.pointer);

    for (String library_directory: module->library_directories)
    {
        String parts[] = {
            string_literal("-L"),
            library_directory,
        };
        builder.add(arena, arena_join_string(arena, array_to_slice(parts)));
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

    builder.add("-L/usr/lib/gcc/x86_64-pc-linux-gnu/15.1.1");
    builder.add("-L/usr/lib/gcc/x86_64-linux-gnu/13");

    for (String object: module->objects)
    {
        builder.add(arena, object);
    }

    for (String library_path: module->library_paths)
    {
        builder.add(arena, library_path);
    }

    for (String library_name: module->library_names)
    {
        String parts[] = {
            string_literal("-l"),
            library_name,
        };
        builder.add(arena, arena_join_string(arena, array_to_slice(parts)));
    }

    if (module->link_libcpp)
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
            case ValueId::forward_declared_function:
                {
                    if (global->variable.storage->id == ValueId::forward_declared_function && global->linkage != Linkage::external)
                    {
                        report_error();
                    }

                    auto function_type = &global->variable.storage->type->pointer.element_type->function;
                    auto semantic_argument_count = function_type->base.semantic_argument_types.length;
                    function_type->abi.argument_abis = arena_allocate<AbiInformation>(module->arena, semantic_argument_count);
                    auto resolved_calling_convention = resolve_calling_convention(function_type->base.calling_convention);
                    auto is_reg_call = resolved_calling_convention == ResolvedCallingConvention::system_v && false; // TODO: regcall calling convention

                    LLVMTypeRef llvm_abi_argument_type_buffer[64];

                    switch (resolved_calling_convention)
                    {
                        case ResolvedCallingConvention::system_v:
                            {
                                function_type->abi.available_registers = {
                                    .system_v = {
                                        .gpr = (u32)(is_reg_call ? 11 : 6),
                                        .sse = (u32)(is_reg_call ? 16 : 8),
                                    },
                                };
                                auto semantic_return_type = function_type->base.semantic_return_type;
                                function_type->abi.return_abi = abi_system_v_classify_return_type(module, resolve_alias(module, semantic_return_type));
                                auto return_abi_kind = function_type->abi.return_abi.flags.kind;

                                Type* abi_argument_type_buffer[64];
                                u16 abi_argument_type_count = 0;

                                Type* abi_return_type;
                                switch (return_abi_kind)
                                {
                                    case AbiKind::direct:
                                    case AbiKind::extend:
                                        {
                                            abi_return_type = function_type->abi.return_abi.coerce_to_type;
                                        } break;
                                    case AbiKind::ignore:
                                    case AbiKind::indirect:
                                        {
                                            abi_return_type = void_type(module);
                                        } break;
                                    default: unreachable(); // TODO
                                }
                                assert(abi_return_type);
                                function_type->abi.abi_return_type = abi_return_type;
                                resolve_type_in_place(module, abi_return_type);

                                if (function_type->abi.return_abi.flags.kind == AbiKind::indirect)
                                {
                                    assert(!function_type->abi.return_abi.flags.sret_after_this);
                                    function_type->abi.available_registers.system_v.gpr -= 1;
                                    auto indirect_type = get_pointer_type(module, function_type->abi.return_abi.semantic_type);
                                    resolve_type_in_place(module, indirect_type);

                                    auto abi_index = abi_argument_type_count;
                                    abi_argument_type_buffer[abi_index] = indirect_type;
                                    llvm_abi_argument_type_buffer[abi_index] = indirect_type->llvm.abi;
                                    abi_argument_type_count += 1;
                                }

                                for (u64 i = 0; i < semantic_argument_count; i += 1)
                                {
                                    auto& abi = function_type->abi.argument_abis[i];
                                    auto semantic_argument_type = resolve_alias(module, function_type->base.semantic_argument_types[i]);
                                    auto is_named_argument = i < semantic_argument_count;
                                    assert(is_named_argument);

                                    abi = abi_system_v_classify_argument(module, &function_type->abi.available_registers.system_v, array_to_slice(llvm_abi_argument_type_buffer), array_to_slice(abi_argument_type_buffer), {
                                        .type = semantic_argument_type,
                                        .abi_start = abi_argument_type_count,
                                        .is_named_argument = is_named_argument,
                                    });

                                    abi_argument_type_count += abi.abi_count;
                                }

                                auto abi_argument_types = new_type_array(module, abi_argument_type_count);
                                memcpy(abi_argument_types.pointer, abi_argument_type_buffer, sizeof(abi_argument_type_buffer[0]) * abi_argument_type_count);
                                function_type->abi.abi_argument_types = abi_argument_types;
                            } break;
                        case ResolvedCallingConvention::win64:
                            {
                                report_error();
                            } break;
                        case ResolvedCallingConvention::count: unreachable();
                    }

                    auto llvm_function_type = LLVMFunctionType(function_type->abi.abi_return_type->llvm.abi, llvm_abi_argument_type_buffer, (u32)function_type->abi.abi_argument_types.length, function_type->base.is_variable_arguments);

                    LLVMMetadataRef subroutine_type = 0;
                    if (module->has_debug_info)
                    {
                        LLVMMetadataRef debug_argument_type_buffer[64];
                        Slice<LLVMMetadataRef> debug_argument_types = { .pointer = debug_argument_type_buffer, .length = function_type->abi.argument_abis.length + 1 + function_type->base.is_variable_arguments };
                        debug_argument_types[0] = function_type->abi.return_abi.semantic_type->llvm.debug;
                        assert(debug_argument_types[0]);

                        auto debug_argument_type_slice = debug_argument_types(1)(0, function_type->abi.argument_abis.length);

                        for (u64 i = 0; i < function_type->abi.argument_abis.length; i += 1)
                        {
                            auto& argument_abi = function_type->abi.argument_abis[i];
                            auto* debug_argument_type = &debug_argument_type_slice[i];
                            *debug_argument_type = argument_abi.semantic_type->llvm.debug;
                            assert(*debug_argument_type);
                        }

                        if (function_type->base.is_variable_arguments)
                        {
                            auto void_ty = void_type(module);
                            assert(void_ty->llvm.debug);
                            debug_argument_types[function_type->abi.argument_abis.length + 1] = void_ty->llvm.debug;
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
                    auto llvm_function = llvm_module_create_function(module->arena, module->llvm.module, llvm_function_type, llvm_linkage_type, global->variable.name);
                    global->variable.storage->llvm = llvm_function;

                    LLVMCallConv cc;
                    switch (function_type->base.calling_convention)
                    {
                        case CallingConvention::c: cc = LLVMCCallConv; break;
                        case CallingConvention::count: unreachable();
                    }

                    LLVMSetFunctionCallConv(llvm_function, cc);

                    emit_attributes(module, llvm_function, &LLVMAddAttributeAtIndex, {
                        .return_abi = function_type->abi.return_abi,
                        .argument_abis = function_type->abi.argument_abis,
                        .abi_argument_types = function_type->abi.abi_argument_types,
                        .abi_return_type = function_type->abi.abi_return_type,
                        .attributes = global->variable.storage->function.attributes,
                        .call_site = false,
                    });

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

                    switch (global->variable.storage->id)
                    {
                        case ValueId::function:
                            {
                                global->variable.storage->function.scope.llvm = subprogram;
                            } break;
                        case ValueId::forward_declared_function:
                            {
                                assert(global->linkage == Linkage::external);
                                if (module->has_debug_info)
                                {
                                    LLVMDIBuilderFinalizeSubprogram(module->llvm.di_builder, subprogram);
                                }
                            } break;
                        default: unreachable();
                    }
                } break;
            case ValueId::global:
                {
                    assert(!module->current_function);
                    analyze_value(module, global->variable.initial_value, global->variable.type, TypeKind::memory, true);

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

                    LLVMThreadLocalMode thread_local_mode = LLVMNotThreadLocal;
                    bool externally_initialized = false;

                    auto alignment = get_byte_alignment(global_type);
                    auto global_llvm = llvm_create_global_variable(module->llvm.module, global_type->llvm.memory, is_constant, linkage, global->variable.initial_value->llvm, global->variable.name, thread_local_mode, externally_initialized, alignment, LLVMNoUnnamedAddr);
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

    for (auto* global = module->first_global; global; global = global->next)
    {
        assert(!module->current_function);
        assert(!module->current_macro_instantiation);
        assert(!module->current_macro_declaration);

        if (global->variable.storage->id == ValueId::function)
        {
            module->current_function = global;

            auto function_type = &global->variable.storage->type->pointer.element_type->function;
            auto semantic_argument_types = function_type->base.semantic_argument_types;
            auto llvm_function = global->variable.storage->llvm;
            assert(llvm_function);

            LLVMValueRef llvm_abi_argument_buffer[64];
            Slice<LLVMValueRef> llvm_abi_arguments = { .pointer = llvm_abi_argument_buffer, .length = function_type->abi.abi_argument_types.length };
            LLVMGetParams(llvm_function, llvm_abi_argument_buffer);

            auto* entry_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "entry");
            auto return_block = LLVMAppendBasicBlockInContext(module->llvm.context, llvm_function, "return_block");
            global->variable.storage->function.llvm.return_block = return_block;

            LLVMPositionBuilderAtEnd(module->llvm.builder, entry_block);
            LLVMSetCurrentDebugLocation2(module->llvm.builder, 0);

            auto u32_type = uint32(module);
            resolve_type_in_place(module, u32_type);
            global->variable.storage->function.llvm.alloca_insertion_point = LLVMBuildAlloca(module->llvm.builder, u32_type->llvm.abi, "alloca_insert_point");

            auto return_abi_kind = function_type->abi.return_abi.flags.kind;
            switch (return_abi_kind)
            {
                case AbiKind::indirect:
                    {
                        auto indirect_argument_index = function_type->abi.return_abi.flags.sret_after_this;
                        if (function_type->abi.return_abi.flags.sret_after_this)
                        {
                            trap();
                        }

                        global->variable.storage->function.llvm.return_alloca = llvm_abi_arguments[indirect_argument_index];

                        if (!function_type->abi.return_abi.flags.indirect_by_value)
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
                                .type = function_type->abi.return_abi.semantic_type,
                                .name = string_literal("retval"),
                                });
                        global->variable.storage->function.llvm.return_alloca = alloca;
                    } break;
                case AbiKind::ignore: break;
            }

            auto arguments = global->variable.storage->function.arguments;
            auto argument_abis = function_type->abi.argument_abis;
            assert(arguments.length == argument_abis.length);
            for (u64 i = 0; i < semantic_argument_types.length; i += 1)
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
                                            auto u64_type = uint64(module);
                                            LLVMBuildMemCpy(module->llvm.builder, pointer, address_alignment, address, address_alignment, LLVMConstInt(u64_type->llvm.abi, destination_size, false));
                                        }
                                    }
                                }
                                else
                                {
                                    assert(argument_abi.abi_count == 1);
                                    auto abi_argument_type = function_type->abi.abi_argument_types[argument_abi.abi_start];
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

                if (!LLVMGetFirstInstruction(current_basic_block) || !LLVMGetFirstUse((LLVMValueRef)current_basic_block))
                {
                    LLVMReplaceAllUsesWith((LLVMValueRef)return_block, (LLVMValueRef)current_basic_block);
                    LLVMDeleteBasicBlock(return_block);
                }
                else
                {
                    emit_block(module, return_block);
                }
            }
            else
            {
                bool has_single_jump_to_return_block = false;

                auto first_use = LLVMGetFirstUse((LLVMValueRef)return_block);
                LLVMValueRef user = 0;
                if (first_use)
                {
                    auto second_use = LLVMGetNextUse(first_use);
                    auto has_one_use = first_use && !second_use;
                    if (has_one_use)
                    {
                        user = LLVMGetUser(first_use);
                        has_single_jump_to_return_block = LLVMIsABranchInst(user) && !LLVMIsConditional(user) && LLVMGetSuccessor(user, 0) == return_block;
                    }
                }

                if (has_single_jump_to_return_block)
                {
                    assert(LLVMGetBasicBlockParent(return_block));
                    auto new_return_block = LLVMGetInstructionParent(user);
                    // Remove unconditional branch instruction to the return block
                    LLVMInstructionEraseFromParent(user);
                    assert(!LLVMGetFirstUse((LLVMValueRef)return_block));
                    assert(!LLVMGetBasicBlockTerminator(return_block));
                    assert(LLVMGetBasicBlockParent(return_block));
                    LLVMPositionBuilderAtEnd(module->llvm.builder, new_return_block);
                    LLVMDeleteBasicBlock(return_block);
                }
                else
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

            if (function_type->abi.return_abi.semantic_type == noreturn_type(module) || global->variable.storage->function.attributes.naked)
            {
                LLVMBuildUnreachable(module->llvm.builder);
            }
            else if (function_type->abi.return_abi.semantic_type == void_type(module))
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
                            auto coerce_to_type = function_type->abi.return_abi.get_coerce_to_type();
                            auto return_semantic_type = function_type->abi.return_abi.semantic_type;
                            if (type_is_abi_equal(module, coerce_to_type, return_semantic_type) && function_type->abi.return_abi.attributes.direct.offset == 0)
                            {
                                auto store = llvm_find_return_value_dominating_store(module->llvm.builder, return_alloca, return_semantic_type->llvm.abi);
                                if (store)
                                {
                                    return_value = LLVMGetOperand(store, 0);
                                    auto alloca = LLVMGetOperand(store, 1);
                                    assert(alloca == return_alloca);
                                    LLVMInstructionEraseFromParent(store);
                                    assert(!LLVMGetFirstUse(alloca));
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
                                if (function_type->abi.return_abi.attributes.direct.offset == 0)
                                {
                                    source = return_alloca;
                                }
                                else
                                {
                                    trap();
                                }
                                assert(source);

                                auto source_type = function_type->abi.return_abi.semantic_type;
                                auto destination_type = coerce_to_type;
                                auto result = create_coerced_load(module, source, source_type, destination_type);
                                return_value = result;
                            }
                        } break;
                    case AbiKind::indirect:
                        {
                            auto evaluation_kind = get_evaluation_kind(function_type->abi.return_abi.semantic_type);
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

            LLVMInstructionEraseFromParent(global->variable.storage->function.llvm.alloca_insertion_point);

            // END OF SCOPE
            module->current_function = 0;
        }
    }

    if (module->has_debug_info)
    {
        LLVMDIBuilderFinalize(module->llvm.di_builder);
    }

    char* verification_error_message = 0;
    auto result = LLVMVerifyModule(module->llvm.module, LLVMReturnStatusAction, &verification_error_message) == 0;
    if (!result)
    {
        dump_module(module);
        print(string_literal("\n==========================\nLLVM VERIFICATION ERROR\n==========================\n"));
        print(c_string_to_slice(verification_error_message));
        bb_fail();
    }

    if (!module->silent)
    {
        dump_module(module);
    }

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
    auto object_generation_result = generate_object(module->llvm.module, module->llvm.target_machine, {
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
