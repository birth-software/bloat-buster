#pragma once

#include <llvm_generate.h>
#include <llvm-c/Core.h>
#include <llvm-c/DebugInfo.h>
#include <llvm-c/Target.h>
#include <llvm-c/Analysis.h>
#include <llvm_common.h>

#define llvm_error() todo()

LOCAL void llvm_module_set_flag(LLVMContextRef context, LLVMModuleRef module, LLVMModuleFlagBehavior behavior, str flag, u32 value)
{
    let value_constant = LLVMConstInt(LLVMIntTypeInContext(context, 32), value, 0);
    let value_metadata = LLVMValueAsMetadata(value_constant);
    LLVMAddModuleFlag(module, behavior, flag.pointer, flag.length, value_metadata);
}

LOCAL bool type_is_abi_equal(CompileUnit* restrict unit, TypeReference a, TypeReference b)
{
    check(is_ref_valid(a));
    check(is_ref_valid(b));

    let result = ref_eq(a, b);

    if (!result)
    {
        let type_a = type_pointer_from_reference(unit, a);
        let type_b = type_pointer_from_reference(unit, b);
        todo();
    }

    return result;
}

STRUCT(LLVMAttributeId)
{
    u32 v;
};

typedef enum LLVMAttributeIndexReference : u32
{
    LLVM_ATTRIBUTE_ALIGN,
    LLVM_ATTRIBUTE_ALWAYSINLINE,
    LLVM_ATTRIBUTE_BYVAL,
    LLVM_ATTRIBUTE_DEAD_ON_UNWIND,
    LLVM_ATTRIBUTE_INLINEHINT,
    LLVM_ATTRIBUTE_INREG,
    LLVM_ATTRIBUTE_NAKED,
    LLVM_ATTRIBUTE_NOALIAS,
    LLVM_ATTRIBUTE_NOINLINE,
    LLVM_ATTRIBUTE_NORETURN,
    LLVM_ATTRIBUTE_NOUNWIND,
    LLVM_ATTRIBUTE_SIGNEXT,
    LLVM_ATTRIBUTE_SRET,
    LLVM_ATTRIBUTE_WRITABLE,
    LLVM_ATTRIBUTE_ZEROEXT,

    LLVM_ATTRIBUTE_COUNT,
} LLVMAttributeIndexReference;

LOCAL str llvm_attribute_names[] =
{
    S("align"),
    S("alwaysinline"),
    S("byval"),
    S("dead_on_unwind"),
    S("inlinehint"),
    S("inreg"),
    S("naked"),
    S("noalias"),
    S("noinline"),
    S("noreturn"),
    S("nounwind"),
    S("signext"),
    S("sret"),
    S("writable"),
    S("zeroext"),
};

static_assert(array_length(llvm_attribute_names) == LLVM_ATTRIBUTE_COUNT);

STRUCT(LLVMIntrinsicId)
{
    u32 v;
};

typedef enum LLVMIntrinsicIndexReference : u32
{
    LLVM_INTRINSIC_LEADING_ZEROES,
    LLVM_INTRINSIC_TRAILING_ZEROES,
    LLVM_INTRINSIC_DEBUG_TRAP,
    LLVM_INTRINSIC_SMAX,
    LLVM_INTRINSIC_SMIN,
    LLVM_INTRINSIC_TRAP,
    LLVM_INTRINSIC_UMAX,
    LLVM_INTRINSIC_UMIN,
    LLVM_INTRINSIC_VA_START,
    LLVM_INTRINSIC_VA_END,
    LLVM_INTRINSIC_VA_COPY,
    LLVM_INTRINSIC_VECTOR_REDUCE_ADD,
    LLVM_INTRINSIC_VECTOR_REDUCE_FADD,
    LLVM_INTRINSIC_VECTOR_REDUCE_MUL,
    LLVM_INTRINSIC_VECTOR_REDUCE_FMUL,
    LLVM_INTRINSIC_VECTOR_REDUCE_AND,
    LLVM_INTRINSIC_VECTOR_REDUCE_OR,
    LLVM_INTRINSIC_VECTOR_REDUCE_XOR,
    LLVM_INTRINSIC_VECTOR_REDUCE_SMAX,
    LLVM_INTRINSIC_VECTOR_REDUCE_SMIN,
    LLVM_INTRINSIC_VECTOR_REDUCE_UMAX,
    LLVM_INTRINSIC_VECTOR_REDUCE_UMIN,
    LLVM_INTRINSIC_VECTOR_REDUCE_FMAX,
    LLVM_INTRINSIC_VECTOR_REDUCE_FMIN,
    LLVM_INTRINSIC_COUNT,
} LLVMIntrinsicIndexReference;

LOCAL str llvm_intrinsic_names[] =
{
    S("llvm.ctlz"),
    S("llvm.cttz"),
    S("llvm.debugtrap"),
    S("llvm.smax"),
    S("llvm.smin"),
    S("llvm.trap"),
    S("llvm.umax"),
    S("llvm.umin"),
    S("llvm.va_start"),
    S("llvm.va_end"),
    S("llvm.va_copy"),
    S("llvm.vector.reduce.add"),
    S("llvm.vector.reduce.fadd"),
    S("llvm.vector.reduce.mul"),
    S("llvm.vector.reduce.fmul"),
    S("llvm.vector.reduce.and"),
    S("llvm.vector.reduce.or"),
    S("llvm.vector.reduce.xor"),
    S("llvm.vector.reduce.smax"),
    S("llvm.vector.reduce.smin"),
    S("llvm.vector.reduce.umax"),
    S("llvm.vector.reduce.umin"),
    S("llvm.vector.reduce.fmax"),
    S("llvm.vector.reduce.fmin"),
};
static_assert(array_length(llvm_intrinsic_names) == LLVM_INTRINSIC_COUNT);

LOCAL u32 llvm_default_address_space = 0;

STRUCT(GenerateCurrentFunction)
{
    Address return_address;
    LLVMValueRef alloca_insertion_point;
    LLVMBasicBlockRef return_block;
    LLVMMetadataRef inlined_at;
};

STRUCT(Generate)
{
    LLVMContextRef context;
    LLVMModuleRef module;
    LLVMBuilderRef builder;
    LLVMDIBuilderRef di_builder;
    LLVMTypeRef void_type;
    LLVMTypeRef pointer_type;
    GenerateCurrentFunction current_function;
    LLVMIntrinsicId intrinsic_table[LLVM_INTRINSIC_COUNT];
    LLVMAttributeId attribute_table[LLVM_ATTRIBUTE_COUNT];
};

LOCAL LLVMValueRef emit_known_intrinsic_call(Generate* restrict generate, LLVMIntrinsicIndexReference index, LLVMTypeRef* argument_type_pointer, u64 argument_type_count, LLVMValueRef* argument_value_pointer, u32 argument_value_count)
{
    check(index < LLVM_INTRINSIC_COUNT);
    let intrinsic_id = generate->intrinsic_table[index];
    let intrinsic_function = LLVMGetIntrinsicDeclaration(generate->module, intrinsic_id.v, argument_type_pointer, argument_type_count);
    let intrinsic_function_type = LLVMIntrinsicGetType(generate->context, intrinsic_id.v, argument_type_pointer, argument_type_count);
    let call = LLVMBuildCall2(generate->builder, intrinsic_function_type, intrinsic_function, argument_value_pointer, argument_value_count, "");
    return call;
}

LOCAL void generate_type_abi(CompileUnit* restrict unit, Generate* restrict generate, Type* type);
LOCAL void generate_type_memory(CompileUnit* restrict unit, Generate* restrict generate, Type* type);
LOCAL void generate_type_debug(CompileUnit* restrict unit, Generate* restrict generate, Type* type);

LOCAL void generate_type(CompileUnit* restrict unit, Generate* restrict generate, Type* restrict type)
{
    generate_type_abi(unit, generate, type);
    generate_type_memory(unit, generate, type);
    generate_type_debug(unit, generate, type);
}

LOCAL void generate_type_abi(CompileUnit* restrict unit, Generate* restrict generate, Type* type)
{
    check(type->analyzed);
    if (!type->llvm.abi)
    {
        LLVMTypeRef result = {};

        let default_arena = get_default_arena(unit);
        let context = generate->context;

        let type_id = type->id;
        switch (type_id)
        {
            break;
            case TYPE_ID_VOID:
            case TYPE_ID_NORETURN:
            {
                result = generate->void_type;
            }
            break; case TYPE_ID_POINTER:
            {
                result = generate->pointer_type;
            }
            break; case TYPE_ID_INTEGER:
            {
                let bit_count = type->integer.bit_count;
                result = LLVMIntTypeInContext(context, bit_count);
            }
            break; case TYPE_ID_FUNCTION:
            {
                let abi_return_type = type_pointer_from_reference(unit, get_abi_return_type(&type->function));
                generate_type(unit, generate, abi_return_type);

                let abi_argument_count = type->function.abi_argument_count;
                let abi_argument_types = arena_allocate(default_arena, LLVMTypeRef, abi_argument_count);

                for (u16 i = 0; i < abi_argument_count; i += 1)
                {
                    let abi_argument_type = type_pointer_from_reference(unit, get_abi_argument_type(&type->function, i));
                    generate_type(unit, generate, abi_argument_type);
                    abi_argument_types[i] = abi_argument_type->llvm.abi;
                }

                let semantic_argument_count = type->function.semantic_argument_count;
                let semantic_types = type->function.semantic_types;
                let semantic_type_count = semantic_argument_count + 1;

                for (u16 i = 0; i < semantic_type_count; i += 1)
                {
                    let semantic_type = type_pointer_from_reference(unit, semantic_types[i]);
                    generate_type(unit, generate, semantic_type);
                }

                let function_type = LLVMFunctionType(abi_return_type->llvm.abi, abi_argument_types, abi_argument_count, type->function.is_variable_argument);
                result = function_type;
            }
            break; case TYPE_ID_FLOAT:
            {
                let fp = type->fp;
                switch (fp)
                {
                    break; case TYPE_FLOAT_F16: result = LLVMHalfTypeInContext(context);
                    break; case TYPE_FLOAT_BF16: result = LLVMBFloatTypeInContext(context);
                    break; case TYPE_FLOAT_F32: result = LLVMFloatTypeInContext(context);
                    break; case TYPE_FLOAT_F64: result = LLVMDoubleTypeInContext(context);
                    break; case TYPE_FLOAT_F128: result = LLVMFP128TypeInContext(context);
                    break; case TYPE_FLOAT_COUNT: default: UNREACHABLE();
                }
            }
            break; default: todo();
        }

        check(result);
        type->llvm.abi = result;
    }
}

LOCAL void generate_type_memory(CompileUnit* restrict unit, Generate* restrict generate, Type* type)
{
    check(type->analyzed);

    if (!type->llvm.memory)
    {
        LLVMTypeRef result = {};

        switch (type->id)
        {
            break;
            case TYPE_ID_VOID:
            case TYPE_ID_NORETURN:
            case TYPE_ID_POINTER:
            case TYPE_ID_FLOAT:
            case TYPE_ID_FUNCTION:
            {
                generate_type_abi(unit, generate, type);
                result = type->llvm.abi;
            }
            break; case TYPE_ID_INTEGER:
            {
                let byte_size = get_byte_size(unit, type);
                let bit_count = byte_size * 8;
                result = LLVMIntTypeInContext(generate->context, bit_count);
            }
            break; default: todo();
        }

        check(result);
        type->llvm.memory = result;
    }
}

typedef enum LLVMDwarfTypeEncoding : unsigned
{
    void_type = 0x0,
    address = 0x1,
    boolean = 0x2,
    complex_float = 0x3,
    float_type = 0x4,
    signed_type = 0x5,
    signed_char = 0x6,
    unsigned_type = 0x7,
    unsigned_char = 0x8,

    // DWARF 3.
    imaginary_float = 0x9,
    packed_decimal = 0xa,
    numeric_string = 0xb,
    edited = 0xc,
    signed_fixed = 0xd,
    unsigned_fixed = 0xe,
    decimal_float = 0xf,

    // DWARF 4.
    UTF = 0x10,

    // DWARF 5.
    UCS = 0x11,
    ASCII = 0x12,

    // HP extensions.
    HP_float80 = 0x80, // Floating-point (80 bit).
    HP_complex_float80 = 0x81, // Complex floating-point (80 bit).
    HP_float128 = 0x82, // Floating-point (128 bit).
    HP_complex_float128 = 0x83, // Complex fp (128 bit).
    HP_floathpintel = 0x84, // Floating-point (82 bit IA64).
    HP_imaginary_float80 = 0x85,
    HP_imaginary_float128 = 0x86,
    HP_VAX_float = 0x88, // F or G floating.
    HP_VAX_float_d = 0x89, // D floating.
    HP_packed_decimal = 0x8a, // Cobol.
    HP_zoned_decimal = 0x8b, // Cobol.
    HP_edited = 0x8c, // Cobol.
    HP_signed_fixed = 0x8d, // Cobol.
    HP_unsigned_fixed = 0x8e, // Cobol.
    HP_VAX_complex_float = 0x8f, // F or G floating complex.
    HP_VAX_complex_float_d = 0x90, // D floating complex.
} LLVMDwarfTypeEncoding;

LOCAL void generate_type_debug(CompileUnit* restrict unit, Generate* restrict generate, Type* type)
{
    check(type->analyzed);
    if (unit->has_debug_info & !type->llvm.debug)
    {
        LLVMMetadataRef result = {};

        let arena = get_default_arena(unit);
        let di_builder = generate->di_builder;
        let type_name = is_ref_valid(type->name) ? string_from_reference(unit, type->name) : S("");

        let type_id = type->id;
        switch (type_id)
        {
            break;
            case TYPE_ID_VOID:
            case TYPE_ID_NORETURN:
            {
                LLVMDIFlags flags = {};
                if (type_id == TYPE_ID_NORETURN) flags |= LLVMDIFlagNoReturn;
                result = LLVMDIBuilderCreateBasicType(di_builder, type_name.pointer, type_name.length, 0, void_type, flags);
            }
            break; case TYPE_ID_INTEGER:
            {
                let bit_count = type->integer.bit_count;

                LLVMDwarfTypeEncoding encoding;

                if (bit_count == 1)
                {
                    encoding = boolean;
                    bit_count = 8;
                }
                else
                {
                    encoding = type->integer.is_signed ? signed_type : unsigned_type;
                }

                LLVMDIFlags flags = {};
                result = LLVMDIBuilderCreateBasicType(di_builder, type_name.pointer, type_name.length, bit_count, encoding, flags);
            }
            break; case TYPE_ID_FLOAT:
            {
                LLVMDwarfTypeEncoding encoding = float_type;

                u64 bit_count;
                switch (type->fp)
                {
                    break; case TYPE_FLOAT_F16: bit_count = 16;
                    break; case TYPE_FLOAT_BF16: bit_count = 16;
                    break; case TYPE_FLOAT_F32: bit_count = 32;
                    break; case TYPE_FLOAT_F64: bit_count = 64;
                    break; case TYPE_FLOAT_F128: bit_count = 128;
                    break; case TYPE_FLOAT_COUNT: default: UNREACHABLE();
                }

                LLVMDIFlags flags = {};
                result = LLVMDIBuilderCreateBasicType(di_builder, type_name.pointer, type_name.length, bit_count, encoding, flags);
            }
            break; case TYPE_ID_POINTER:
            {
                let element_type = type_pointer_from_reference(unit, type->pointer.element_type);
                generate_type_debug(unit, generate, element_type);

                result = type->llvm.debug;
                let pointer_size = 8;
                let pointer_alignment = 8;
                if (!result)
                {
                    result = LLVMDIBuilderCreatePointerType(di_builder, element_type->llvm.debug, pointer_size * 8, pointer_alignment * 8, llvm_default_address_space, type_name.pointer, type_name.length);
                }
            }
            break; case TYPE_ID_FUNCTION:
            {
                let semantic_argument_count = type->function.semantic_argument_count;
                let is_variable_argument = type->function.is_variable_argument;
                let type_array_count = semantic_argument_count + is_variable_argument + 1;
                let type_array = arena_allocate(arena, LLVMMetadataRef, type_array_count);

                let semantic_return_type = type_pointer_from_reference(unit, get_semantic_return_type(&type->function));
                generate_type_debug(unit, generate, semantic_return_type);
                type_array[0] = semantic_return_type->llvm.debug; 

                let argument_types = type_array + 1;
                for (u16 i = 0; i < semantic_argument_count; i += 1)
                {
                    let argument_type_ref = get_semantic_argument_type(&type->function, i);
                    let argument_type = type_pointer_from_reference(unit, argument_type_ref);
                    generate_type_debug(unit, generate, argument_type);
                    check(argument_type->llvm.debug);
                    argument_types[i] = argument_type->llvm.debug; 
                }

                if (is_variable_argument)
                {
                    let void_type = type_pointer_from_reference(unit, get_void_type(unit));
                    check(void_type->llvm.debug);
                    type_array[semantic_argument_count] = void_type->llvm.debug;
                }

                let file = file_pointer_from_reference(unit, type->function.file);
                LLVMDIFlags flags = {};
                result = LLVMDIBuilderCreateSubroutineType(di_builder, file->handle, type_array, type_array_count, flags);
            }
            break; default: todo();
        }

        check(result);
        type->llvm.debug = result;
    }
}

LOCAL LLVMValueRef llvm_create_function(LLVMModuleRef module, LLVMTypeRef function_type, LLVMLinkage linkage, str name)
{
    check(str_is_zero_terminated(name));
    let function = LLVMAddFunction(module, name.pointer, function_type);
    LLVMSetLinkage(function, linkage);
    return function;
}

LOCAL LLVMValueRef llvm_create_alloca(LLVMBuilderRef builder, LLVMTypeRef base_type, u32 alignment, str name)
{
    if (name.pointer)
    {
        check(str_is_zero_terminated(name));
    }
    else
    {
        name = S("");
    }
    let alloca = LLVMBuildAlloca(builder, base_type, name.pointer);
    LLVMSetAlignment(alloca, alignment);
    return alloca;
}

LOCAL LLVMValueRef llvm_create_store(LLVMBuilderRef builder, LLVMValueRef source, LLVMValueRef destination, u32 alignment, bool is_volatile, LLVMAtomicOrdering ordering)
{
    let store = LLVMBuildStore(builder, source, destination);

    LLVMSetAlignment(store, alignment);
    LLVMSetVolatile(store, is_volatile);
    LLVMSetOrdering(store, ordering);
    
    return store;
}

LOCAL LLVMValueRef llvm_create_load(LLVMBuilderRef builder, LLVMTypeRef type, LLVMValueRef pointer, u32 alignment, str name, bool is_volatile, LLVMAtomicOrdering ordering)
{
    if (name.pointer)
    {
        check(str_is_zero_terminated(name));
    }
    else
    {
        name = S("");
    }

    let result = LLVMBuildLoad2(builder, type, pointer, name.pointer);

    LLVMSetAlignment(result, alignment);
    LLVMSetVolatile(result, is_volatile);
    LLVMSetOrdering(result, ordering);

    return result;
}

LOCAL bool type_is_vector_bool(CompileUnit* restrict unit, Type* type)
{
    return (type->id == TYPE_ID_VECTOR) & ref_eq(type->vector.element_type, get_u1(unit));
}

LOCAL Type* convert_type_for_memory(CompileUnit* restrict unit, Type* type)
{
    let result = type;
    if (type_is_vector_bool(unit, type))
    {
        todo();
    }

    return result;
}

LOCAL LLVMTypeRef get_llvm_type(Type* type, TypeKind kind)
{
    LLVMTypeRef result = {};
    switch (kind)
    {
        break; case TYPE_KIND_ABI: result = type->llvm.abi;
        break; case TYPE_KIND_MEMORY: result = type->llvm.memory;
    }
    check(result);
    return result;
}

STRUCT(AllocaOptions)
{
    Type* type;
    str name;
    u32 alignment;
    bool use_abi;
};

LOCAL LLVMValueRef create_alloca(CompileUnit* restrict unit, Generate* restrict generate, AllocaOptions options)
{
    let alignment = options.alignment;
    let abi_type = options.type;
    if (alignment == 0)
    {
        alignment = get_alignment(unit, abi_type);
    }

    abi_type = convert_type_for_memory(unit, abi_type);

    let original_block = LLVMGetInsertBlock(generate->builder);
    let original_debug_location = LLVMGetCurrentDebugLocation2(generate->builder);
    let alloca_insertion_point = generate->current_function.alloca_insertion_point;

    LLVMPositionBuilderBefore(generate->builder, alloca_insertion_point);
    LLVMSetCurrentDebugLocation2(generate->builder, 0);

    let alloca_type = get_llvm_type(abi_type, options.use_abi ? TYPE_KIND_ABI : TYPE_KIND_MEMORY);
    let alloca = llvm_create_alloca(generate->builder, alloca_type, alignment, options.name);

    LLVMPositionBuilderAtEnd(generate->builder, original_block);
    LLVMSetCurrentDebugLocation2(generate->builder, original_debug_location);

    return alloca;
}

STRUCT(StoreOptions)
{
    LLVMValueRef source;
    LLVMValueRef destination;
    Type* type;
    u32 alignment;
    LLVMAtomicOrdering ordering;
    bool is_volatile;
};

LOCAL LLVMValueRef create_store(CompileUnit* restrict unit, Generate* restrict generate, StoreOptions options)
{
    check(options.source);
    check(options.destination);
    check(options.type);

    let store_type = options.type;
    generate_type(unit, generate, store_type);
    let memory_type = store_type->llvm.memory;

    let source_value = options.source;

    if (store_type->llvm.abi != memory_type)
    {
        source_value = LLVMBuildIntCast2(generate->builder, source_value, memory_type, type_is_signed(unit, store_type), "");
    }

    let alignment = options.alignment;
    if (alignment == 0)
    {
        alignment = get_alignment(unit, store_type);
    }

    let store = llvm_create_store(generate->builder, source_value, options.destination, alignment, options.is_volatile, options.ordering);
    return store;
}

LOCAL LLVMValueRef memory_to_abi(CompileUnit* restrict unit, LLVMBuilderRef builder, LLVMValueRef value, Type* type)
{
    let result = value;

    if (type->llvm.abi != type->llvm.memory)
    {
        result = LLVMBuildIntCast2(builder, result, type->llvm.abi, type_is_signed(unit, type), "");
    }

    return result;
}

STRUCT(LoadOptions)
{
    Type* type;
    LLVMValueRef pointer;
    str name;
    u32 alignment;
    LLVMAtomicOrdering ordering;
    TypeKind kind;
    bool use_abi;
    bool is_volatile;
};

LOCAL LLVMValueRef create_load(CompileUnit* restrict unit, Generate* restrict generate, LoadOptions options)
{
    let alignment = options.alignment;
    if (alignment == 0)
    {
        alignment = get_alignment(unit, options.type);
    }

    let type = get_llvm_type(options.type, options.use_abi ? TYPE_KIND_ABI : TYPE_KIND_MEMORY);
    let result = llvm_create_load(generate->builder, type, options.pointer, alignment, options.name, options.is_volatile, options.ordering);

    if (!options.use_abi)
    {
        if (options.kind == TYPE_KIND_ABI)
        {
            result = memory_to_abi(unit, generate->builder, result, options.type);
        }
    }

    return result;
}

typedef void LLVMAttributeCallback(LLVMValueRef, u32, LLVMAttributeRef);

LOCAL void add_enum_attribute(Generate* restrict generate, LLVMAttributeIndexReference attribute_index, u64 attribute_value, LLVMAttributeCallback* callback, LLVMValueRef value, u32 index)
{
    let attribute = LLVMCreateEnumAttribute(generate->context, generate->attribute_table[attribute_index].v, attribute_value);
    callback(value, index, attribute);
}

LOCAL void add_type_attribute(Generate* restrict generate, LLVMAttributeIndexReference attribute_index, LLVMTypeRef type, LLVMAttributeCallback* callback, LLVMValueRef value, u32 index)
{
    let attribute = LLVMCreateTypeAttribute(generate->context, generate->attribute_table[attribute_index].v, type);
    callback(value, index, attribute);
}

LOCAL void add_string_attribute(Generate* restrict generate, str attribute_key, str attribute_value, LLVMAttributeCallback* callback, LLVMValueRef value, u32 index)
{
    let attribute = LLVMCreateStringAttribute(generate->context, attribute_key.pointer, (unsigned)attribute_key.length, attribute_value.pointer, (unsigned)attribute_value.length);
    callback(value, index, attribute);
}

STRUCT(LLVMAttributes)
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

LOCAL void add_value_attribute(Generate* restrict generate, LLVMValueRef value, u32 index, LLVMAttributeCallback* callback, LLVMTypeRef semantic_type, LLVMAttributes attributes)
{
    check(value);
    check(semantic_type);

    if (attributes.alignment)
    {
        add_enum_attribute(generate, LLVM_ATTRIBUTE_ALIGN, attributes.alignment, callback, value, index);
    }

    if (attributes.sign_extend)
    {
        add_enum_attribute(generate, LLVM_ATTRIBUTE_SIGNEXT, 0, callback, value, index);
    }

    if (attributes.zero_extend)
    {
        add_enum_attribute(generate, LLVM_ATTRIBUTE_ZEROEXT, 0, callback, value, index);
    }

    if (attributes.no_alias)
    {
        add_enum_attribute(generate, LLVM_ATTRIBUTE_NOALIAS, 0, callback, value, index);
    }

    if (attributes.in_reg)
    {
        add_enum_attribute(generate, LLVM_ATTRIBUTE_INREG, 0, callback, value, index);
    }

    if (attributes.sret)
    {
        add_type_attribute(generate, LLVM_ATTRIBUTE_SRET, semantic_type, callback, value, index);
    }

    if (attributes.writable)
    {
        add_enum_attribute(generate, LLVM_ATTRIBUTE_WRITABLE, 0, callback, value, index);
    }

    if (attributes.dead_on_unwind)
    {
        add_enum_attribute(generate, LLVM_ATTRIBUTE_DEAD_ON_UNWIND, 0, callback, value, index);
    }

    if (attributes.sret)
    {
        add_type_attribute(generate, LLVM_ATTRIBUTE_BYVAL, semantic_type, callback, value, index);
    }
}

STRUCT(FunctionAttributeBuildOptions)
{
    AbiInformation* abis;
    TypeReference* abi_types;
    u16 semantic_argument_count;
    u16 abi_argument_count;
    FunctionAttributes attributes;
};

LOCAL void generate_function_attributes(CompileUnit* unit, Generate* restrict generate, LLVMValueRef value, LLVMAttributeCallback* callback, FunctionAttributeBuildOptions options)
{
    let return_abi = &options.abis[0];
    let semantic_return_type_ref = return_abi->semantic_type;
    let semantic_return_type = type_pointer_from_reference(unit, semantic_return_type_ref);
    let abi_return_type = options.abi_types[0];
    let semantic_argument_count = options.semantic_argument_count;
    let abi_argument_count = options.abi_argument_count;

    add_value_attribute(generate, value, 0, callback, semantic_return_type->llvm.memory, (LLVMAttributes) {
        .alignment = 0,
        .sign_extend = (return_abi->flags.kind == ABI_KIND_EXTEND) & return_abi->flags.sign_extension,
        .zero_extend = (return_abi->flags.kind == ABI_KIND_EXTEND) & !return_abi->flags.sign_extension,
        .no_alias = 0,
        .in_reg = 0,
        .sret = 0,
        .writable = 0,
        .dead_on_unwind = 0,
        .by_value = 0,
    });

    u16 total_abi_count = 0;

    if (return_abi->flags.kind == ABI_KIND_INDIRECT)
    {
        let abi = return_abi;
        u16 abi_index = abi->flags.sret_after_this;

        let abi_type = options.abi_types[abi_index + 1];

        add_value_attribute(generate, value, abi_index, callback, semantic_return_type->llvm.memory, (LLVMAttributes) {
            .alignment = get_alignment(unit, semantic_return_type),
            .sign_extend = 0,
            .zero_extend = 0,
            .no_alias = 1,
            .in_reg = abi->flags.in_reg,
            .sret = 1,
            .writable = 1,
            .dead_on_unwind = 1,
            .by_value = 0,
        });

        total_abi_count += 1;
    }

    let argument_abis = return_abi + 1;

    for (u16 i = 0; i < abi_argument_count; i += 1)
    {
        let abi = &argument_abis[i];
        let abi_start = abi->abi_start;
        let abi_count = abi->abi_count;

        for (u16 abi_index = abi_start; abi_index < abi_start + abi_count; abi_index += 1)
        {
            check(abi_index >= 1);
            let abi_type = type_pointer_from_reference(unit, options.abi_types[abi_index]);
            let semantic_type = type_pointer_from_reference(unit, abi->semantic_type);
            u32 alignment = abi->flags.kind == ABI_KIND_INDIRECT ? MAX(get_alignment(unit, semantic_type), 8) : 0;
            check(alignment == 0 || alignment >= 8);
            check(semantic_type->llvm.memory);
            add_value_attribute(generate, value, abi_index, callback, semantic_type->llvm.memory, (LLVMAttributes) {
                .alignment = alignment,
                .sign_extend = (abi->flags.kind == ABI_KIND_EXTEND) & abi->flags.sign_extension,
                .zero_extend = (abi->flags.kind == ABI_KIND_EXTEND) & !abi->flags.sign_extension,
                .no_alias = 0,
                .in_reg = abi->flags.in_reg,
                .sret = 0,
                .writable = 0,
                .dead_on_unwind = 0,
                .by_value = abi->flags.indirect_by_value,
            });

            total_abi_count += 1;
        }
    }

    check(total_abi_count == abi_argument_count);

    const let index = ~(u32)0;

    let is_noreturn = ref_eq(semantic_return_type_ref, get_noreturn_type(unit));
    if (is_noreturn)
    {
        add_enum_attribute(generate, LLVM_ATTRIBUTE_NORETURN, 0, callback, value, index);
    }

    let no_unwind = 1;
    if (no_unwind)
    {
        add_enum_attribute(generate, LLVM_ATTRIBUTE_NOUNWIND, 0, callback, value, index);
    }

    let is_noinline = options.attributes.inline_behavior == INLINE_NO;
    if (is_noreturn)
    {
        add_enum_attribute(generate, LLVM_ATTRIBUTE_NOINLINE, 0, callback, value, index);
    }

    let always_inline = options.attributes.inline_behavior == INLINE_ALWAYS;
    if (always_inline)
    {
        add_enum_attribute(generate, LLVM_ATTRIBUTE_ALWAYSINLINE, 0, callback, value, index);
    }

    if (unit->has_debug_info)
    {
        add_string_attribute(generate, S("frame-pointer"), S("all"), callback, value, index);
    }

    let is_definition = callback == &LLVMAddAttributeAtIndex;
    if (is_definition)
    {
        if (options.attributes.is_naked)
        {
            add_enum_attribute(generate, LLVM_ATTRIBUTE_NAKED, 0, callback, value, index);
        }

        if (options.attributes.inline_behavior == INLINE_HINT)
        {
            add_enum_attribute(generate, LLVM_ATTRIBUTE_INLINEHINT, 0, callback, value, index);
        }
    }
}

LOCAL void generate_value(CompileUnit* restrict unit, Generate* restrict generate, Value* restrict value, TypeKind type_kind, bool expect_constant);

LOCAL LLVMValueRef generate_call(CompileUnit* restrict unit, Generate* restrict generate, Value* value, Address address)
{
    let is_valid_address_argument = address.pointer != 0;

    check(value->id == VALUE_ID_CALL);

    let function_type_ref = value->call.function_type;
    let function_type = type_pointer_from_reference(unit, function_type_ref);
    check(function_type->id == TYPE_ID_FUNCTION);
    let callable = value_pointer_from_reference(unit, value->call.callable);
    let call_arguments = value->call.arguments;
    check(call_arguments.count < UINT16_MAX);

    // TODO: load function pointer
    generate_value(unit, generate, callable, TYPE_KIND_ABI, 0);
    check(callable->kind == VALUE_KIND_LEFT);
    let callable_type = type_pointer_from_reference(unit, callable->type);
    check(callable_type->id == TYPE_ID_POINTER);

    LLVMValueRef llvm_callable = callable->llvm;
    let is_direct_function_call = ref_eq(callable_type->pointer.element_type, function_type_ref);
    if (!is_direct_function_call)
    {
        todo();
    }

    let available_registers = function_type->function.available_registers;
    let declaration_semantic_argument_types = function_type->function.semantic_types + 1;
    let declaration_semantic_argument_count = function_type->function.semantic_argument_count;
    let declaration_abi_argument_count = function_type->function.abi_argument_count;

    LLVMValueRef llvm_abi_argument_buffer[4096];
    LLVMTypeRef llvm_abi_argument_type_buffer[array_length(llvm_abi_argument_buffer)];
    TypeReference abi_type_buffer[array_length(llvm_abi_argument_buffer)];
    AbiInformation abi_buffer[512];
    u16 abi_count = 1;

    let source_abi_types = function_type->function.abi_types;

    check(declaration_semantic_argument_count <= array_length(abi_buffer));
    check(declaration_abi_argument_count <= array_length(llvm_abi_argument_buffer));
    memcpy(abi_buffer, get_abis(&function_type->function), (declaration_semantic_argument_count + 1) * sizeof(AbiInformation));
    memcpy(abi_type_buffer, source_abi_types, (declaration_abi_argument_count + 1) * sizeof(TypeReference));
    let return_abi = &abi_buffer[0];
    AbiKind return_abi_kind = return_abi->flags.kind;

    switch (return_abi_kind)
    {
        break; case ABI_KIND_INDIRECT: case ABI_KIND_IN_ALLOCA: case ABI_KIND_COERCE_AND_EXPAND:
        {
            todo();
        }
        break; default: {}
    }

    let semantic_call_argument_node_ref = call_arguments.first;

    for (u16 call_argument_index = 0; call_argument_index < (u16)call_arguments.count; call_argument_index += 1)
    {
        let is_named_argument = call_argument_index < declaration_semantic_argument_count;
        let semantic_call_argument_node = value_node_pointer_from_reference(unit, semantic_call_argument_node_ref);
        let semantic_call_argument_value_ref = semantic_call_argument_node->item;
        let semantic_call_argument_value = value_pointer_from_reference(unit, semantic_call_argument_value_ref);

        AbiInformation argument_abi = {};

        if (is_named_argument)
        {
            argument_abi = *get_argument_abi(&function_type->function, call_argument_index);
        }
        else
        {
            todo();
        }

        let semantic_argument_type_ref = argument_abi.semantic_type;
        check(is_ref_valid(semantic_argument_type_ref));

        if (is_named_argument)
        {
            let abi_start = argument_abi.abi_start;
            let abi_count = argument_abi.abi_count;

            for (u16 i = abi_start; i < abi_start + abi_count; i += 1)
            {
                let abi_argument_type_ref = source_abi_types[i];
                let abi_argument_type = type_pointer_from_reference(unit, abi_argument_type_ref);
                check(abi_argument_type->llvm.abi);
                abi_type_buffer[i] = abi_argument_type_ref;
                llvm_abi_argument_type_buffer[i] = abi_argument_type->llvm.abi;
            }
        }

        abi_buffer[call_argument_index + 1] = argument_abi;

        if (is_ref_valid(argument_abi.padding.type))
        {
            todo();
        }

        check(abi_count == argument_abi.abi_start);

        switch (argument_abi.flags.kind)
        {
            break; case ABI_KIND_IGNORE:
            {
                UNREACHABLE();
            }
            break; case ABI_KIND_IN_ALLOCA:
            {
                todo();
            }
            break; case ABI_KIND_DIRECT: case ABI_KIND_EXTEND:
            {
                let call_argument_type_ref = semantic_call_argument_value->type;
                check(ref_eq(call_argument_type_ref, semantic_argument_type_ref));
                let semantic_argument_type = type_pointer_from_reference(unit, semantic_argument_type_ref);
                let type_evaluation_kind = get_type_evaluation_kind(unit, semantic_argument_type);
                let coerce_to_type_ref = abi_get_coerce_to_type(&argument_abi);
                let coerce_to_type = type_pointer_from_reference(unit, coerce_to_type_ref);

                if ((coerce_to_type->id != TYPE_ID_STRUCT) & (argument_abi.attributes.direct.offset == 0) & type_is_abi_equal(unit, coerce_to_type_ref, semantic_argument_type_ref))
                {
                    check(argument_abi.abi_count == 1);

                    generate_value(unit, generate, semantic_call_argument_value, TYPE_KIND_ABI, false);
                    LLVMValueRef value = {};

                    if (type_evaluation_kind == TYPE_EVALUATION_KIND_AGGREGATE)
                    {
                        todo();
                    }
                    else
                    {
                        value = semantic_call_argument_value->llvm;
                    }

                    check(value);

                    if (!type_is_abi_equal(unit, coerce_to_type_ref, call_argument_type_ref))
                    {
                        todo();
                    }

                    // TODO: trivial bitcast if types don't match?
                    
                    llvm_abi_argument_buffer[abi_count++ - 1] = value;
                }
                else
                {
                    todo();
                }
            }
            break; case ABI_KIND_INDIRECT: case ABI_KIND_INDIRECT_ALIASED:
            {
                todo();
            }
            break; case ABI_KIND_COERCE_AND_EXPAND:
            {
                todo();
            }
            break; case ABI_KIND_EXPAND:
            {
                todo();
            }
            break; default: todo();
        }

        check(abi_count == argument_abi.abi_start + argument_abi.abi_count);

        semantic_call_argument_node_ref = semantic_call_argument_node->next;
    }

    check(!is_ref_valid(semantic_call_argument_node_ref));

    if (function_type->function.is_variable_argument)
    {
        check(declaration_abi_argument_count <= abi_count - 1);
    }
    else
    {
        check(declaration_abi_argument_count == abi_count - 1);
    }

    for (u16 i = 0; i < abi_count - 1; i += 1)
    {
        check(llvm_abi_argument_buffer[i]);
    }
    
    let llvm_call = LLVMBuildCall2(generate->builder, function_type->llvm.abi, llvm_callable, llvm_abi_argument_buffer, abi_count - 1, "");
    LLVMCallConv calling_convention;

    switch (function_type->function.calling_convention)
    {
        break; case CALLING_CONVENTION_C: calling_convention = LLVMCCallConv;
        break; default: UNREACHABLE();
    }

    LLVMSetInstructionCallConv(llvm_call, calling_convention);

    generate_function_attributes(unit, generate, llvm_call, &LLVMAddCallSiteAttribute, (FunctionAttributeBuildOptions) {
        .abis = abi_buffer,
        .abi_types = abi_type_buffer,
        .semantic_argument_count = call_arguments.count,
        .abi_argument_count = abi_count - 1,
        .attributes = {},
    });

    switch (return_abi_kind)
    {
        break; case ABI_KIND_IGNORE:
        {
            return llvm_call;
        }
        break; case ABI_KIND_DIRECT: case ABI_KIND_EXTEND:
        {
            let coerce_to_type = abi_get_coerce_to_type(return_abi);
            if (return_abi->attributes.direct.offset == 0 && type_is_abi_equal(unit, return_abi->semantic_type, coerce_to_type))
            {
                let evaluation_kind = get_type_evaluation_kind(unit, type_pointer_from_reference(unit, coerce_to_type));

                switch (evaluation_kind)
                {
                    break; case TYPE_EVALUATION_KIND_SCALAR:
                    {
                        return llvm_call;
                    }
                    break; case TYPE_EVALUATION_KIND_AGGREGATE: {}
                    break; case TYPE_EVALUATION_KIND_COMPLEX: UNREACHABLE();
                }
            }

            todo();
        }
        break; case ABI_KIND_INDIRECT:
        {
            todo();
        }
        break; default: UNREACHABLE();
    }
}

LOCAL void generate_value(CompileUnit* restrict unit, Generate* restrict generate, Value* restrict value, TypeKind type_kind, bool expect_constant)
{
    check(unit->phase == COMPILE_PHASE_LLVM_IR_GENERATION);

    let must_be_constant = expect_constant | !is_ref_valid(unit->current_function);

    let current_function = get_current_function(unit);
    let current_function_type = get_function_type_from_storage(unit, current_function);

    let value_type_ref = value->type;
    check(is_ref_valid(value_type_ref));
    let value_type = type_pointer_from_reference(unit, value_type_ref);

    LLVMValueRef llvm_value = 0;

    let id = value->id;

    switch (id)
    {
        break; case VALUE_ID_CONSTANT_INTEGER:
        {
            let llvm_integer_type = get_llvm_type(value_type, type_kind);
            llvm_value = LLVMConstIntOfArbitraryPrecision(llvm_integer_type, 1, &value->integer);
        }
        break; case VALUE_ID_CALL:
        {
            llvm_value = generate_call(unit, generate, value, (Address){});
        }
        break; case VALUE_ID_REFERENCED_VARIABLE:
        {
            let variable = variable_pointer_from_reference(unit, value->variable);
            let storage = value_pointer_from_reference(unit, variable->storage);
            let llvm_storage = storage->llvm;

            switch (value->kind)
            {
                break; case VALUE_KIND_LEFT:
                {
                    check(ref_eq(value_type_ref, storage->type));
                    llvm_value = llvm_storage;
                }
                break; case VALUE_KIND_RIGHT:
                {
                    check(ref_eq(value_type_ref, variable->type));
                    if (must_be_constant)
                    {
                        todo();
                    }
                    else
                    {
                        // TODO: more fine-grained checkion
                        check(get_byte_size(unit, value_type) <= 16);
                        let evaluation_kind = get_type_evaluation_kind(unit, value_type);

                        llvm_value = create_load(unit, generate, (LoadOptions) {
                            .type = value_type,
                            .pointer = llvm_storage,
                            .kind = type_kind,
                        });
                    }
                }
            }
        }
        break;
        case VALUE_ID_UNARY_MINUS_INTEGER:
        case VALUE_ID_UNARY_BOOLEAN_NOT:
        case VALUE_ID_UNARY_ADDRESS_OF:
        case VALUE_ID_INTRINSIC_EXTEND:
        case VALUE_ID_INTRINSIC_TRUNCATE:
        case VALUE_ID_POINTER_DEREFERENCE:
        {
            let operand = value_pointer_from_reference(unit, value->unary);
            generate_value(unit, generate, operand, TYPE_KIND_ABI, must_be_constant);
            let llvm_operand = operand->llvm;
            let operand_type = type_pointer_from_reference(unit, operand->type);
            let llvm_type = get_llvm_type(type_pointer_from_reference(unit, value->type), type_kind);

            switch (id)
            {
                break; case VALUE_ID_UNARY_MINUS_INTEGER: llvm_value = LLVMBuildNeg(generate->builder, llvm_operand, "");
                break; case VALUE_ID_UNARY_BOOLEAN_NOT: llvm_value = LLVMBuildNot(generate->builder, llvm_operand, "");
                break; case VALUE_ID_UNARY_ADDRESS_OF: llvm_value = llvm_operand;
                break; case VALUE_ID_INTRINSIC_EXTEND:
                {
                    check(operand_type->id == TYPE_ID_INTEGER);
                    
                    if (type_is_signed(unit, operand_type))
                    {
                        llvm_value = LLVMBuildSExt(generate->builder, llvm_operand, llvm_type, "");
                    }
                    else
                    {
                        llvm_value = LLVMBuildSExt(generate->builder, llvm_operand, llvm_type, "");
                    }
                }
                break; case VALUE_ID_INTRINSIC_TRUNCATE:
                {
                    if (type_kind != TYPE_KIND_ABI)
                    {
                        check(value_type->llvm.abi == value_type->llvm.memory);
                    }

                    llvm_value = LLVMBuildTrunc(generate->builder, llvm_operand, llvm_type, "");
                }
                break; case VALUE_ID_POINTER_DEREFERENCE:
                {
                    switch (value->kind)
                    {
                        break; case VALUE_KIND_RIGHT:
                        {
                            let pointer_type_ref = operand->type;
                            let pointer_type = type_pointer_from_reference(unit, pointer_type_ref);
                            check(pointer_type->id == TYPE_ID_POINTER);
                            let element_type_ref = pointer_type->pointer.element_type;
                            check(ref_eq(value->type, element_type_ref));
                            let element_type = type_pointer_from_reference(unit, element_type_ref);

                            let load = create_load(unit, generate, (LoadOptions) {
                                .type = element_type,
                                .pointer = llvm_operand,
                                .kind = type_kind,
                            });
                            llvm_value = load;
                        }
                        break; case VALUE_KIND_LEFT:
                        {
                            todo();
                        }
                    }
                }
                break; default: UNREACHABLE();
            }
        }
        break;
        case VALUE_ID_BINARY_ADD_INTEGER:
        case VALUE_ID_BINARY_SUB_INTEGER:
        case VALUE_ID_BINARY_MULTIPLY_INTEGER:
        case VALUE_ID_BINARY_DIVIDE_INTEGER_SIGNED:
        case VALUE_ID_BINARY_REMAINDER_INTEGER_SIGNED:
        case VALUE_ID_BINARY_COMPARE_EQUAL_INTEGER:
        case VALUE_ID_BINARY_COMPARE_NOT_EQUAL_INTEGER:
        case VALUE_ID_BINARY_BITWISE_AND:
        case VALUE_ID_BINARY_BITWISE_OR:
        case VALUE_ID_BINARY_BITWISE_XOR:
        case VALUE_ID_BINARY_BITWISE_SHIFT_LEFT:
        case VALUE_ID_BINARY_BITWISE_SHIFT_RIGHT_LOGICAL:
        case VALUE_ID_BINARY_BITWISE_SHIFT_RIGHT_ARITHMETIC:
        {
            LLVMValueRef operands[2];
            for (u64 i = 0; i < array_length(operands); i += 1)
            {
                let operand = value_pointer_from_reference(unit, value->binary[i]);
                generate_value(unit, generate, operand, TYPE_KIND_ABI, must_be_constant);
                operands[i] = operand->llvm;
            }

            switch (id)
            {
                break; case VALUE_ID_BINARY_ADD_INTEGER: llvm_value = LLVMBuildAdd(generate->builder, operands[0], operands[1], "");
                break; case VALUE_ID_BINARY_SUB_INTEGER: llvm_value = LLVMBuildSub(generate->builder, operands[0], operands[1], "");
                break; case VALUE_ID_BINARY_MULTIPLY_INTEGER: llvm_value = LLVMBuildMul(generate->builder, operands[0], operands[1], "");
                break; case VALUE_ID_BINARY_DIVIDE_INTEGER_SIGNED: llvm_value = LLVMBuildSDiv(generate->builder, operands[0], operands[1], "");
                break; case VALUE_ID_BINARY_REMAINDER_INTEGER_SIGNED: llvm_value = LLVMBuildSRem(generate->builder, operands[0], operands[1], "");
                break; case VALUE_ID_BINARY_COMPARE_EQUAL_INTEGER: llvm_value = LLVMBuildICmp(generate->builder, LLVMIntEQ, operands[0], operands[1], "");
                break; case VALUE_ID_BINARY_COMPARE_NOT_EQUAL_INTEGER: llvm_value = LLVMBuildICmp(generate->builder, LLVMIntNE, operands[0], operands[1], "");
                break; case VALUE_ID_BINARY_BITWISE_AND: llvm_value = LLVMBuildAnd(generate->builder, operands[0], operands[1], "");
                break; case VALUE_ID_BINARY_BITWISE_OR: llvm_value = LLVMBuildOr(generate->builder, operands[0], operands[1], "");
                break; case VALUE_ID_BINARY_BITWISE_XOR: llvm_value = LLVMBuildXor(generate->builder, operands[0], operands[1], "");
                break; case VALUE_ID_BINARY_BITWISE_SHIFT_LEFT: llvm_value = LLVMBuildShl(generate->builder, operands[0], operands[1], "");
                break; case VALUE_ID_BINARY_BITWISE_SHIFT_RIGHT_LOGICAL: llvm_value = LLVMBuildLShr(generate->builder, operands[0], operands[1], "");
                break; case VALUE_ID_BINARY_BITWISE_SHIFT_RIGHT_ARITHMETIC: llvm_value = LLVMBuildAShr(generate->builder, operands[0], operands[1], "");
                break; default: UNREACHABLE();
            }
        }
        break; case VALUE_ID_INTRINSIC_TRAP:
        {
            let trap_call = emit_known_intrinsic_call(generate, LLVM_INTRINSIC_TRAP, 0, 0, 0, 0);
            LLVMBuildUnreachable(generate->builder);
            LLVMClearInsertionPosition(generate->builder);
            llvm_value = trap_call;
        }
        break; default: todo();
    }

    check(llvm_value);
    value->llvm = llvm_value;
}

LOCAL void generate_assignment(CompileUnit* restrict unit, Generate* restrict generate, Value* right, Address address)
{
    check(unit->phase == COMPILE_PHASE_LLVM_IR_GENERATION);

    let current_function = get_current_function(unit);
    let current_function_type = get_function_type_from_storage(unit, current_function);

    check(!right->llvm);
    let value_type = type_pointer_from_reference(unit, right->type);
    generate_type(unit, generate, value_type);

    let evaluation_kind = get_type_evaluation_kind(unit, value_type);
    let type_kind = TYPE_KIND_MEMORY;

    switch (evaluation_kind)
    {
        break; case TYPE_EVALUATION_KIND_SCALAR:
        {
            generate_value(unit, generate, right, type_kind, 0);
            create_store(unit, generate, (StoreOptions) {
                .source = right->llvm,
                .destination = address.pointer,
                .type = value_type,
            });
        }
        break; case TYPE_EVALUATION_KIND_AGGREGATE:
        {
            todo();
        }
        break; case TYPE_EVALUATION_KIND_COMPLEX:
        {
            todo();
        }
    }
}

LOCAL void generate_local_storage(CompileUnit* restrict unit, Generate* restrict generate, Variable* restrict variable)
{
    let storage = value_pointer_from_reference(unit, variable->storage);
    let pointer_type = type_pointer_from_reference(unit, storage->type);
    let alloca_type = type_pointer_from_reference(unit, variable->type);
    generate_type(unit, generate, pointer_type);
    generate_type(unit, generate, alloca_type);
    let alloca = create_alloca(unit, generate, (AllocaOptions) {
        .type = alloca_type,
        .name = string_from_reference(unit, variable->name),
    });

    storage->llvm = alloca;
}

LOCAL LLVMMetadataRef null_expression(Generate* restrict generate)
{
    return LLVMDIBuilderCreateExpression(generate->di_builder, 0, 0);
}

LOCAL void end_debug_local(CompileUnit* restrict unit, Generate* restrict generate, Variable* restrict variable, LLVMMetadataRef llvm_local)
{
    let scope = scope_pointer_from_reference(unit, variable->scope);
    let debug_location = LLVMDIBuilderCreateDebugLocation(generate->context, location_get_line(variable->location), location_get_column(variable->location), scope->llvm, generate->current_function.inlined_at);
    LLVMSetCurrentDebugLocation2(generate->builder, debug_location);
    let basic_block = LLVMGetInsertBlock(generate->builder);
    check(basic_block);
    let storage = value_pointer_from_reference(unit, variable->storage);
    LLVMDIBuilderInsertDeclareRecordAtEnd(generate->di_builder, storage->llvm, llvm_local, null_expression(generate), debug_location, basic_block);
}

LOCAL void generate_local_declaration(CompileUnit* restrict unit, Generate* restrict generate, File* file, Local* restrict local)
{
    generate_local_storage(unit, generate, &local->variable);

    if (unit->has_debug_info)
    {
        let variable_type = type_pointer_from_reference(unit, local->variable.type);
        let always_preserve = 1;
        LLVMDIFlags flags = {};
        let scope = scope_pointer_from_reference(unit, local->variable.scope);
        let bit_alignment = get_alignment(unit, variable_type) * 8;
        let name = string_from_reference(unit, local->variable.name);
        let location = local->variable.location;

        let local_variable = LLVMDIBuilderCreateAutoVariable(generate->di_builder, scope->llvm, name.pointer, name.length, file->handle, location_get_line(location), variable_type->llvm.debug, always_preserve, flags, bit_alignment);

        end_debug_local(unit, generate, &local->variable, local_variable);
    }
}

LOCAL LLVMValueRef generate_condition_out_of_value(CompileUnit* restrict unit, Generate* restrict generate, Value* value)
{
    let llvm_condition = value->llvm;
    let condition_type = type_pointer_from_reference(unit, value->type);
    check(llvm_condition);
    check((condition_type->id == TYPE_ID_INTEGER) | (condition_type->id == TYPE_ID_POINTER));

    if (!((condition_type->id == TYPE_ID_INTEGER) & (condition_type->integer.bit_count == 1)))
    {
        llvm_condition = LLVMBuildICmp(generate->builder, LLVMIntNE, llvm_condition, LLVMConstNull(condition_type->llvm.abi), "");
    }

    check(llvm_condition);

    return llvm_condition;
}

LOCAL LLVMValueRef generate_condition(CompileUnit* unit, Generate* restrict generate, Value* value)
{
    generate_value(unit, generate, value, TYPE_KIND_ABI, false);
    return generate_condition_out_of_value(unit, generate, value);
}

LOCAL void generate_block(CompileUnit* restrict unit, Generate* restrict generate, File* file, Block* restrict block);

LOCAL void generate_statement(CompileUnit* restrict unit, Generate* restrict generate, File* file, Scope* restrict scope, Statement* statement)
{
    check(unit->phase == COMPILE_PHASE_LLVM_IR_GENERATION);

    let current_function = get_current_function(unit);
    let current_function_type = get_function_type_from_storage(unit, current_function);
    let llvm_function = value_pointer_from_reference(unit, current_function->variable.storage)->llvm;

    LLVMMetadataRef statement_location = 0;
    if (unit->has_debug_info)
    {
        let location = statement->location;
        statement_location = LLVMDIBuilderCreateDebugLocation(generate->context, location_get_line(location), location_get_column(location), scope->llvm, generate->current_function.inlined_at);
        LLVMSetCurrentDebugLocation2(generate->builder, statement_location);
    }

    switch (statement->id)
    {
        break; case STATEMENT_ID_RETURN:
        {
            let return_value_ref = statement->value;
            let return_abi = get_return_abi(&current_function_type->function);

            if (is_ref_valid(return_value_ref))
            {
                if (unit->has_debug_info)
                {
                    LLVMSetCurrentDebugLocation2(generate->builder, statement_location);
                }

                let semantic_return_type = return_abi->semantic_type;

                let return_value = value_pointer_from_reference(unit, return_value_ref);
                let return_address = generate->current_function.return_address;
                generate_assignment(unit, generate, return_value, return_address);
            }

            let return_block = generate->current_function.return_block;
            LLVMBuildBr(generate->builder, return_block);
            LLVMClearInsertionPosition(generate->builder);
        }
        break; case STATEMENT_ID_LOCAL:
        {
            let local = local_pointer_from_reference(unit, statement->local);
            generate_local_declaration(unit, generate, file, local);
            let storage = value_pointer_from_reference(unit, local->variable.storage);
            let local_type = type_pointer_from_reference(unit, local->variable.type);
            Address address = {
                .pointer = storage->llvm,
                .element_type = local_type,
                .alignment = get_alignment(unit, local_type),
                .offset = 0,
            };
            let initial_value = value_pointer_from_reference(unit, local->initial_value);
            generate_assignment(unit, generate, initial_value, address);
        }
        break; case STATEMENT_ID_IF:
        {
            let branch = statement->branch;

            let condition = value_pointer_from_reference(unit, branch.condition);
            let taken_branch = statement_pointer_from_reference(unit, branch.taken_branch);
            let else_branch = is_ref_valid(branch.else_branch) ? statement_pointer_from_reference(unit, branch.else_branch) : 0;

            let taken_block = LLVMAppendBasicBlockInContext(generate->context, llvm_function, "if.if");
            let else_block = LLVMAppendBasicBlockInContext(generate->context, llvm_function, "if.else");
            let exit_block = LLVMAppendBasicBlockInContext(generate->context, llvm_function, "if.exit");

            let llvm_condition = generate_condition(unit, generate, condition);

            LLVMBuildCondBr(generate->builder, llvm_condition, taken_block, else_block);
            LLVMPositionBuilderAtEnd(generate->builder, taken_block);

            generate_statement(unit, generate, file, scope, taken_branch);

            if (LLVMGetInsertBlock(generate->builder))
            {
                LLVMBuildBr(generate->builder, exit_block);
            }

            LLVMPositionBuilderAtEnd(generate->builder, else_block);

            if (else_branch)
            {
                generate_statement(unit, generate, file, scope, else_branch);
            }

            if (LLVMGetInsertBlock(generate->builder))
            {
                LLVMBuildBr(generate->builder, exit_block);
            }

            LLVMPositionBuilderAtEnd(generate->builder, exit_block);
        }
        break; case STATEMENT_ID_BLOCK:
        {
            generate_block(unit, generate, file, block_pointer_from_reference(unit, statement->block));
        }
        break; case STATEMENT_ID_EXPRESSION:
        {
            generate_value(unit, generate, value_pointer_from_reference(unit, statement->value), TYPE_KIND_ABI, false);
        }
        break; default: todo();
    }
}

LOCAL void generate_block(CompileUnit* restrict unit, Generate* restrict generate, File* file, Block* restrict block)
{
    check(unit->phase == COMPILE_PHASE_LLVM_IR_GENERATION);
    let block_scope = scope_pointer_from_reference(unit, block->scope);

    if (unit->has_debug_info)
    {
        let parent_scope = scope_pointer_from_reference(unit, block_scope->parent);
        let location = block_scope->location;
        let lexical_block = LLVMDIBuilderCreateLexicalBlock(generate->di_builder, parent_scope->llvm, file->handle, location_get_line(location), location_get_column(location));
        block_scope->llvm = lexical_block;
    }

    let statement_ref = block->first_statement;

    while (is_ref_valid(statement_ref))
    {
        let statement = statement_pointer_from_reference(unit, statement_ref);
        generate_statement(unit, generate, file, block_scope, statement);

        statement_ref = statement->next;
    }
}

STRUCT(ParameterValue)
{
    union
    {
        Address address;
        LLVMValueRef value;
    };
    bool is_indirect;
};

// Returns single use if true, null if not
LOCAL LLVMUseRef value_has_single_use(LLVMValueRef v)
{
    LLVMUseRef result = 0;
    let first_use = LLVMGetFirstUse(v);
    if (first_use)
    {
        if (!LLVMGetNextUse(first_use))
        {
            result = first_use;
        }
    }

    return result;
}

LOCAL LLVMValueRef store_pointer_operand(LLVMValueRef store)
{
    check(LLVMIsAStoreInst(store));
    return LLVMGetOperand(store, 1);
}

LOCAL LLVMValueRef store_value_operand(LLVMValueRef store)
{
    check(LLVMIsAStoreInst(store));
    return LLVMGetOperand(store, 0);
}

LLVMValueRef llvm_get_last_user(LLVMValueRef value)
{
    LLVMValueRef result = 0;

    LLVMUseRef use = LLVMGetFirstUse(value);

    if (use)
    {
        let last_use = use;
        while ((use = LLVMGetNextUse(use)))
        {
            last_use = use;
        }

        result = LLVMGetUser(last_use);
    }

    return result;
}

LOCAL LLVMValueRef llvm_get_store_if_valid(LLVMValueRef user, LLVMValueRef return_alloca, LLVMTypeRef element_type)
{
    let is_user_store_instruction = LLVMIsAStoreInst(user);
    if (!is_user_store_instruction || store_pointer_operand(user) != return_alloca || LLVMTypeOf(store_value_operand(user)) != element_type)
    {
        return 0;
    }

    check(!LLVMIsAtomic(user) && !LLVMGetVolatile(user));
    return user;
}

LLVMBasicBlockRef llvm_get_single_predecessor(LLVMBasicBlockRef basic_block)
{
    LLVMBasicBlockRef result = 0;

    LLVMUseRef use = LLVMGetFirstUse((LLVMValueRef)basic_block);

    if (use)
    {
        u32 seen = 0;

        for (; use; use = LLVMGetNextUse(use))
        {
            LLVMValueRef user = LLVMGetUser(use);
            if (user && !LLVMIsATerminatorInst(user))
            {
                LLVMBasicBlockRef predecessor = LLVMGetInstructionParent(user);
                if (predecessor)
                {
                    seen += 1;

                    if (seen == 1)
                    {
                        result = predecessor;
                    }
                    else
                    {
                        result = 0;
                        break;
                    }
                }
            }
        }
    }

    return result;
}

LOCAL LLVMValueRef llvm_find_return_value_dominating_store(LLVMBuilderRef builder, LLVMValueRef return_alloca, LLVMTypeRef element_type)
{
    LLVMValueRef result = 0;

    if (!value_has_single_use(return_alloca))
    {
        let insert_point = LLVMGetInsertBlock(builder);

        let first_instruction = LLVMGetFirstInstruction(insert_point);

        if (first_instruction)
        {
            for (let instruction = first_instruction; instruction; instruction = LLVMGetNextInstruction(instruction))
            {
                trap();
            }
        }
    }
    else
    {
        let store = llvm_get_store_if_valid(llvm_get_last_user(return_alloca), return_alloca, element_type);

        if (store)
        {
            let store_basic_block = LLVMGetInstructionParent(store);
            let insert_block = LLVMGetInsertBlock(builder);

            LLVMBasicBlockRef block_map[64];
            u64 bit_block = 0;
            u64 element_count = 0;

            result = store;

            while (insert_block != store_basic_block)
            {
                check(element_count < 64);
                bool seen = 0;
                for (u64 i = 0; i < 64; i += 1)
                {
                    if (bit_block & (1 << i))
                    {
                        let candidate = block_map[i];
                        if (candidate == insert_block)
                        {
                            seen = 1;
                            break;
                        }
                    }
                }

                if (seen || !(insert_block = llvm_get_single_predecessor(insert_block)))
                {
                    result = 0;
                    break;
                }

                if (!seen)
                {
                    for (u64 i = 0; i < 64; i += 1)
                    {
                        trap();
                    }

                    element_count += 1;
                }
            }
        }
    }

    return result;
}

LOCAL ParameterValue parameter_direct(LLVMValueRef value)
{
    check(value);
    return (ParameterValue){ .value = value, .is_indirect = false };
}

LOCAL LLVMValueRef parameter_get_direct(ParameterValue* restrict parameter)
{
    check(!parameter->is_indirect);
    return parameter->value;
}

LOCAL Address create_memory_temporary(CompileUnit* restrict unit, Generate* restrict generate, Type* restrict type, u32 alignment, str name)
{
    let alloca_type = convert_type_for_memory(unit, type);
    let alloca = create_alloca(unit, generate, (AllocaOptions) {
        .type = alloca_type,
        .alignment = alignment,
        .name = name,
    });

    return (Address) {
        .pointer = alloca,
        .element_type = alloca_type,
        .alignment = alignment,
        .offset = 0,
    };
}

LOCAL bool type_has_boolean_representation(CompileUnit* restrict unit, Type* type)
{
    switch (type->id)
    {
        break; case TYPE_ID_INTEGER:
        {
            let bit_count = type->integer.bit_count;
            return bit_count == 1;
        }
        break;
        case TYPE_ID_POINTER:
        {
            return false;
        }
        break; default: todo();
    }
}

LOCAL bool type_is_arbitrary_bit_integer(CompileUnit* restrict unit, Type* type)
{
    switch (type->id)
    {
        break; case TYPE_ID_INTEGER:
        {
            let bit_count = type->integer.bit_count;
            let is_not_arbitrary_bit_integer = (bit_count == 1) | ((bit_count >= 8 & bit_count <= 128) & ((bit_count & (bit_count - 1)) == 0));
            return !is_not_arbitrary_bit_integer;
        }
        break;
        case TYPE_ID_POINTER:
        {
            return false;
        }
        break; default: todo();
    }
}

LOCAL Type* convert_type_for_load_store(CompileUnit* restrict unit, Type* type)
{
    if (type_is_arbitrary_bit_integer(unit, type) | (type_pointer_from_reference(unit, get_u1(unit)) == type))
    {
        return type_pointer_from_reference(unit, get_integer_type(unit, get_byte_size(unit, type) * 8, type_is_signed(unit, type)));
    }

    if (type_is_vector_bool(unit, type))
    {
        todo();
    }

    return type;
}

// CodeGenFunction::EmitToMemory
LOCAL LLVMValueRef emit_to_memory(CompileUnit* restrict unit, Generate* restrict generate, LLVMValueRef value, Type* type)
{
    if (type_has_boolean_representation(unit, type) | type_is_arbitrary_bit_integer(unit, type))
    {
        let store_type = convert_type_for_load_store(unit, type);
        let result = LLVMBuildIntCast2(generate->builder, value, store_type->llvm.abi, type_is_signed(unit, type), "storedv");
        return result;
    }

    if (type_is_vector_bool(unit, type))
    {
        todo();
    }

    return value;
}

LOCAL void address_create_store(CompileUnit* restrict unit, Generate* restrict generate, LLVMValueRef value, Address address, bool is_volatile)
{
    let ordering = LLVMAtomicOrderingNotAtomic;
    llvm_create_store(generate->builder, value, address.pointer, address.alignment, is_volatile, ordering);
}

LOCAL LLVMValueRef address_create_load(CompileUnit* restrict unit, Generate* restrict generate, Address address, str name, bool is_volatile)
{
    LLVMAtomicOrdering ordering = LLVMAtomicOrderingNotAtomic;
    let result = llvm_create_load(generate->builder, address.element_type->llvm.abi, address.pointer, address.alignment, name, is_volatile, ordering);
    return result;
}

LOCAL void emit_store_of_scalar(CompileUnit* restrict unit, Generate* restrict generate, LLVMValueRef value, Type* value_type, Address address)
{
    // TODO: constant matrix
    // TODO: if global value
    let element_type = address.element_type;

    if (element_type->id == TYPE_ID_VECTOR)
    {
        todo();
    }

    value = emit_to_memory(unit, generate, value, value_type);

    // TODO: atomic
    
    // TODO:
    bool is_volatile = false;
    address_create_store(unit, generate, value, address, is_volatile);
    // TODO: non-temporal store
    // TODO: TBAA annotations
}

LOCAL void emit_debug_argument(CompileUnit* restrict unit, Generate* restrict generate, Argument* argument, File* file, LLVMBasicBlockRef basic_block)
{
    check(unit->has_debug_info);

    bool always_preserve = 1;
    LLVMDIFlags flags = {};

    let scope = scope_pointer_from_reference(unit, argument->variable.scope);
    let llvm_scope = scope->llvm;
    check(llvm_scope);
    let name = string_from_reference(unit, argument->variable.name);
    let location = argument->variable.location;
    let line = location_get_line(location);
    let column = location_get_column(location);
    let argument_type = type_pointer_from_reference(unit, argument->variable.type);
    check(argument_type->llvm.debug);
    let argument_storage = value_pointer_from_reference(unit, argument->variable.storage);

    let parameter_variable = LLVMDIBuilderCreateParameterVariable(generate->di_builder, llvm_scope, name.pointer, name.length, argument->index, file->handle, line, argument_type->llvm.debug, always_preserve, flags);

    let inlined_at = generate->current_function.inlined_at;
    let debug_location = LLVMDIBuilderCreateDebugLocation(generate->context, line, column, llvm_scope, inlined_at);
    LLVMDIBuilderInsertDeclareRecordAtEnd(generate->di_builder, argument_storage->llvm, parameter_variable, null_expression(generate), debug_location, basic_block);
}

PUB_IMPL GenerateIRResult llvm_generate_ir(CompileUnit* restrict unit, bool verify)
{
    llvm_initialize();
    str result_error_message = {};

    let default_arena = get_default_arena(unit);
    let context = LLVMContextCreate();
    let builder = LLVMCreateBuilderInContext(context);
    
    let first_file_ref = unit->first_file;
    let file_ref = first_file_ref;
    let first_file = file_pointer_from_reference(unit, file_ref);
    let module = LLVMModuleCreateWithNameInContext(first_file->name.pointer, context);

    if (unit->has_debug_info)
    {
        llvm_module_set_flag(context, module, LLVMModuleFlagBehaviorWarning, S("Dwarf Version"), 4);
        llvm_module_set_flag(context, module, LLVMModuleFlagBehaviorWarning, S("Debug Info Version"), 3);
    }

    STRUCT(Options)
    {
        bool has_debug_info;
    };

    Options options = {
        .has_debug_info = 1,
    };

    LLVMDIBuilderRef di_builder = {};

    if (options.has_debug_info)
    {
        di_builder = LLVMCreateDIBuilder(module);

        str producer = S("bloat-buster");
        bool is_optimized = false;
        str flags = S("");
        unsigned runtime_version = 0;
        str split_name = S("");
        str sysroot = S("");
        str sdk = S("");

        while (is_ref_valid(file_ref))
        {
            let file = file_pointer_from_reference(unit, file_ref);

            let di_file = LLVMDIBuilderCreateFile(di_builder, file->file_name.pointer, file->file_name.length, file->directory.pointer, file->directory.length);
            let di_compile_unit = LLVMDIBuilderCreateCompileUnit(di_builder, LLVMDWARFSourceLanguageC17, di_file, producer.pointer, producer.length, is_optimized, flags.pointer, flags.length, runtime_version, split_name.pointer, split_name.length, LLVMDWARFEmissionFull, 0, 0, is_optimized, sysroot.pointer, sysroot.length, sdk.pointer, sdk.length);
            file->handle = di_file;
            file->compile_unit = di_compile_unit;
            let scope = scope_pointer_from_reference(unit, file->scope);
            scope->llvm = di_file;

            file_ref = file->next;
        }
    }

    let target_machine_options = LLVMCreateTargetMachineOptions();
    LLVMTargetMachineOptionsSetCPU(target_machine_options, "generic");
    LLVMTargetMachineOptionsSetFeatures(target_machine_options, "");

    LLVMCodeGenOptLevel code_generation_optimization_level;

    switch (unit->build_mode)
    {
        break; case BUILD_MODE_DEBUG: code_generation_optimization_level = LLVMCodeGenLevelNone;
        break; case BUILD_MODE_SIZE: case BUILD_MODE_SPEED: code_generation_optimization_level = LLVMCodeGenLevelAggressive;
    }

    LLVMTargetMachineOptionsSetCodeGenOptLevel(target_machine_options, code_generation_optimization_level);

    str cpu = S("");

    switch (unit->target.cpu)
    {
        break; case CPU_ARCH_UNKNOWN: UNREACHABLE();
        break; case CPU_ARCH_X86_64:
        {
            cpu = S("x86_64");
        }
        break; case CPU_ARCH_AARCH64:
        {
            cpu = S("aarch64");
        }
    }

    str os = S("");
    str vendor = S("unknown");

    switch (unit->target.os)
    {
        break; case OPERATING_SYSTEM_UNKNOWN: UNREACHABLE();
        break; case OPERATING_SYSTEM_LINUX:
        {
            os = S("linux");
            vendor = S("pc");
        }
        break; case OPERATING_SYSTEM_MACOS:
        {
            os = S("macos");
            vendor = S("apple");
        }
        break; case OPERATING_SYSTEM_WINDOWS:
        {
            os = S("windows");
            vendor = S("pc");
        }
    }

    str target_triple_parts[] = {
        cpu,
        S("-"),
        vendor,
        S("-"),
        os,
    };
    str llvm_target_triple = arena_join_string(default_arena, string_array_to_slice(target_triple_parts), true);
    unit->target_triple = llvm_target_triple;

    LLVMTargetRef target = {};
    char* error_message = {};
    let result = LLVMGetTargetFromTriple(llvm_target_triple.pointer, &target, &error_message);

    if (result)
    {
        llvm_error();
    }

    check(!error_message);

    let target_machine = LLVMCreateTargetMachineWithOptions(target, llvm_target_triple.pointer, target_machine_options);

    let target_data_layout = LLVMCreateTargetDataLayout(target_machine);
    LLVMSetModuleDataLayout(module, target_data_layout);
    LLVMSetTarget(module, llvm_target_triple.pointer);

    Generate g = {
        .context = context,
        .module = module,
        .builder = builder,
        .di_builder = di_builder,
        .void_type = LLVMVoidTypeInContext(context),
        .pointer_type = LLVMPointerTypeInContext(context, llvm_default_address_space),
    };

    Generate* restrict generate = &g;

    for (u64 i = 0; i < LLVM_INTRINSIC_COUNT; i += 1)
    {
        let name = llvm_intrinsic_names[i];
        let id = LLVMLookupIntrinsicID(name.pointer, name.length);
        check(id != 0);
        generate->intrinsic_table[i] = (LLVMIntrinsicId){
            .v = id,
        };
    }

    for (u64 i = 0; i < LLVM_ATTRIBUTE_COUNT; i += 1)
    {
        let name = llvm_attribute_names[i];
        let id = LLVMGetEnumAttributeKindForName(name.pointer, name.length);
        check(id != 0);
        generate->attribute_table[i] = (LLVMAttributeId){
            .v = id,
        };
    }

    unit->phase = COMPILE_PHASE_LLVM_IR_GENERATION;

    {
        let type_arena = unit_arena(unit, UNIT_ARENA_TYPE);
        let base_type_allocation = (Type*)(type_arena + 1);
        let base_type = base_type_allocation;

        let base_type_count = get_base_type_count();
        for (u64 i = 0; i < base_type_count; i += 1, base_type += 1)
        {
            generate_type(unit, generate, base_type);
        }
    }

    file_ref = first_file_ref;
    while (is_ref_valid(file_ref))
    {
        let file = file_pointer_from_reference(unit, file_ref);

        let global_ref = file->first_global;

        while (is_ref_valid(global_ref))
        {
            let global = global_pointer_from_reference(unit, global_ref);

            if (!global->generated)
            {
                global->generated = 1;

                let global_type_ref = global->variable.type;
                let global_storage_ref = global->variable.storage;
                let global_name = string_from_reference(unit, global->variable.name);
                let global_type = type_pointer_from_reference(unit, global_type_ref);
                let global_storage = value_pointer_from_reference(unit, global_storage_ref);
                let global_storage_type_ref = global_storage->type;
                let global_storage_type = type_pointer_from_reference(unit, global_storage_type_ref);
                check(global_storage_type->id == TYPE_ID_POINTER);
                check(ref_eq(global_storage_type->pointer.element_type, global_type_ref)); 

                print(S("===\n"));
                print(S("'"));
                print(global_name);
                print(S("':\n"));

                generate_type(unit, generate, global_type);
                generate_type(unit, generate, global_storage_type);

                LLVMLinkage linkage;
                switch (global->linkage)
                {
                    break; case LINKAGE_INTERNAL: linkage = LLVMInternalLinkage;
                    break; case LINKAGE_EXTERNAL: linkage = LLVMExternalLinkage;
                    break; default: UNREACHABLE();
                }

                let global_id = global_storage->id;
                switch (global_id)
                {
                    break; case VALUE_ID_FUNCTION:
                    {
                        let function = llvm_create_function(generate->module, global_type->llvm.abi, linkage, global_name);
                        global_storage->llvm = function;

                        for (u16 i = 0; i < global_type->function.semantic_argument_count; i += 1)
                        {
                            let abi = get_argument_abi(&global_type->function, i);
                            let arg_type_ref = get_semantic_argument_type(&global_type->function, i);
                            check(ref_eq(abi->semantic_type, arg_type_ref));
                            let arg_type = type_pointer_from_reference(unit, arg_type_ref);
                            check(arg_type->llvm.abi);
                            check(arg_type->llvm.memory);
                            if (unit->has_debug_info)
                            {
                                check(arg_type->llvm.debug);
                            }
                        }

                        LLVMCallConv calling_convention;

                        switch (global_type->function.calling_convention)
                        {
                            break; case CALLING_CONVENTION_C: calling_convention = LLVMCCallConv;
                            break; default: UNREACHABLE();
                        }

                        LLVMSetFunctionCallConv(function, calling_convention);

                        generate_function_attributes(unit, generate, function, &LLVMAddAttributeAtIndex, (FunctionAttributeBuildOptions) {
                            .abis = get_abis(&global_type->function),
                            .abi_types = global_type->function.abi_types,
                            .semantic_argument_count = global_type->function.semantic_argument_count,
                            .abi_argument_count = global_type->function.abi_argument_count,
                            .attributes = global_storage->function.attributes,
                        });

                        print(S("===\n"));

                        if (unit->has_debug_info)
                        {
                            let linkage_name = global_name;
                            let scope = scope_pointer_from_reference(unit, global->variable.scope);
                            let location = global->variable.location;
                            let is_local_to_unit = linkage == LLVMInternalLinkage;
                            let is_definition = global_id == VALUE_ID_FUNCTION;
                            let line = location_get_line(location);
                            let function_scope = scope_pointer_from_reference(unit, global_storage->function.scope);
                            let scope_line = location_get_line(function_scope->location);
                            let is_optimized = unit->build_mode != BUILD_MODE_DEBUG;
                            LLVMDIFlags flags = {};
                            let subprogram = LLVMDIBuilderCreateFunction(di_builder, scope->llvm, global_name.pointer, global_name.length, linkage_name.pointer, linkage_name.length, file->handle, line, global_type->llvm.debug, is_local_to_unit, is_definition, scope_line, flags, is_optimized);
                            LLVMSetSubprogram(function, subprogram);

                            switch (global_id)
                            {
                                break; case VALUE_ID_FUNCTION:
                                {
                                    let function_scope = scope_pointer_from_reference(unit, global_storage->function.scope);
                                    function_scope->llvm = subprogram;
                                }
                                break; default: UNREACHABLE();
                            }
                        }
                    }
                    break; default:
                    {
                        llvm_error();
                    }
                }
            }

            global_ref = global->next;
        }

        file_ref = file->next;
    }

    file_ref = first_file_ref;

    while (is_ref_valid(file_ref))
    {
        let file = file_pointer_from_reference(unit, file_ref);

        let global_ref = file->first_global;

        while (is_ref_valid(global_ref))
        {
            let global = global_pointer_from_reference(unit, global_ref);
            let global_storage = value_pointer_from_reference(unit, global->variable.storage);
            let global_name = string_from_reference(unit, global->variable.name);

            if (global_storage->id == VALUE_ID_FUNCTION)
            {
                unit->current_function = global_ref;
                let function_pointer_type = type_pointer_from_reference(unit, global_storage->type);
                check(function_pointer_type->id == TYPE_ID_POINTER);
                let function_type_ref = function_pointer_type->pointer.element_type;
                let function_type = type_pointer_from_reference(unit, function_type_ref);
                check(function_type->id == TYPE_ID_FUNCTION);

                let llvm_function = global_storage->llvm;
                LLVMValueRef llvm_abi_argument_buffer[256];
                let semantic_argument_count = function_type->function.semantic_argument_count;
                let abi_argument_count = function_type->function.abi_argument_count;
                check(abi_argument_count <= array_length(llvm_abi_argument_buffer));
                LLVMGetParams(llvm_function, llvm_abi_argument_buffer);
                let llvm_abi_arguments = llvm_abi_argument_buffer;

                let entry_block = LLVMAppendBasicBlockInContext(context, llvm_function, "entry_block");
                let return_block = LLVMAppendBasicBlockInContext(context, llvm_function, "return_block");
                generate->current_function.return_block = return_block;

                LLVMPositionBuilderAtEnd(generate->builder, entry_block);
                LLVMSetCurrentDebugLocation2(generate->builder, 0);

                let u32_type = type_pointer_from_reference(unit, get_integer_type(unit, 32, 0));
                generate->current_function.alloca_insertion_point = LLVMBuildAlloca(builder, u32_type->llvm.abi, "alloca.insertion.point");

                let return_abi = get_return_abi(&function_type->function);

                let semantic_return_type_ref = return_abi->semantic_type;
                let semantic_return_type = type_pointer_from_reference(unit, semantic_return_type_ref);
                switch (return_abi->flags.kind)
                {
                    break; default:
                    {
                        let alignment = get_alignment(unit, semantic_return_type);
                        let alloca = create_alloca(unit, generate, (AllocaOptions) {
                            .type = semantic_return_type,
                            .name = S("return_value"),
                            .alignment = alignment,
                        });
                        generate->current_function.return_address = (Address) {
                            .pointer = alloca,
                            .element_type = semantic_return_type,
                            .alignment = alignment,
                            .offset = 0,
                        };
                    }
                    break; case ABI_KIND_IGNORE: {}
                    break; case ABI_KIND_IN_ALLOCA:
                    {
                        todo();
                    }
                    break; case ABI_KIND_INDIRECT:
                    {
                        todo();
                    }
                }

                ParameterValue parameter_value_buffer[256];
                u16 parameter_value_count = 0;

                let argument_ref = global_storage->function.arguments;

                for (u16 i = 0; i < semantic_argument_count; i += 1)
                {
                    let argument = argument_pointer_from_reference(unit, argument_ref);
                    let argument_abi = get_argument_abi(&function_type->function, i);
                    let abi_start = argument_abi->abi_start;
                    let abi_count = argument_abi->abi_count;
                    let abi_end = abi_start + abi_count;

                    let llvm_abi_arguments = llvm_abi_argument_buffer + abi_start - 1;

                    LLVMValueRef semantic_argument_storage = {};
                    let semantic_argument_type = argument_abi->semantic_type;

                    switch (argument_abi->flags.kind)
                    {
                        break; case ABI_KIND_IN_ALLOCA:
                        {
                            todo();
                        }
                        break; case ABI_KIND_INDIRECT: case ABI_KIND_INDIRECT_ALIASED:
                        {
                            todo();
                        }
                        break; case ABI_KIND_DIRECT: case ABI_KIND_EXTEND:
                        {
                            let llvm_first_argument = llvm_abi_arguments[0];
                            let value = llvm_first_argument;
                            let coerce_to_type_ref = abi_get_coerce_to_type(argument_abi);
                            let coerce_to_type = type_pointer_from_reference(unit, coerce_to_type_ref);

                            if ((coerce_to_type->id != TYPE_ID_STRUCT) & (argument_abi->attributes.direct.offset == 0) & type_is_abi_equal(unit, coerce_to_type_ref, semantic_argument_type))
                            {
                                check(argument_abi->abi_count == 1);

                                if (coerce_to_type->llvm.abi != LLVMTypeOf(value))
                                {
                                    todo();
                                }

                                check(parameter_value_count < array_length(parameter_value_buffer));
                                parameter_value_buffer[parameter_value_count++] = parameter_direct(value);
                            }
                            else
                            {
                                todo();
                            }
                        }
                        break; default:
                        {
                            todo();
                        }
                    }

                    argument_ref = argument->next;
                }

                check(!is_ref_valid(argument_ref));
                check(parameter_value_count < array_length(parameter_value_buffer));

                bool use_indirect_debug_address = 0;
                argument_ref = global_storage->function.arguments;

                for (u16 i = 0; i < parameter_value_count; i += 1)
                {
                    let parameter_value = &parameter_value_buffer[i];
                    let argument = argument_pointer_from_reference(unit, argument_ref);
                    check(function_type->id == TYPE_ID_FUNCTION);
                    let argument_abi = get_argument_abi(&function_type->function, i);
                    let type_ref = argument->variable.type;
                    let type = type_pointer_from_reference(unit, type_ref);
                    let type_name = string_from_reference(unit, type->name);
                    let abi_type_name = string_from_reference(unit, type_pointer_from_reference(unit, argument_abi->semantic_type)->name);
                    check(ref_eq(type_ref, argument_abi->semantic_type));

                    Address declaration_pointer = {};
                    bool do_store = false;
                    let type_evaluation_kind = get_type_evaluation_kind(unit, type);
                    let is_scalar = type_evaluation_kind == TYPE_EVALUATION_KIND_SCALAR;

                    // CodeGenFunction::EmitParmDecl
                    if (parameter_value->is_indirect)
                    {
                        todo();
                    }
                    else
                    {
                        // TODO: argument alignment
                        declaration_pointer = create_memory_temporary(unit, generate, type, get_alignment(unit, type), string_from_reference(unit, argument->variable.name));
                        do_store = 1;
                    }

                    if (do_store)
                    {
                        let argument_value = parameter_get_direct(parameter_value);
                        emit_store_of_scalar(unit, generate, argument_value, type, declaration_pointer);
                    }

                    let argument_storage = value_pointer_from_reference(unit, argument->variable.storage);
                    argument_storage->llvm = declaration_pointer.pointer;

                    if (unit->has_debug_info)
                    {
                        emit_debug_argument(unit, generate, argument, file, entry_block);
                    }

                    argument_ref = argument->next;
                }

                check(!is_ref_valid(argument_ref));

                generate_block(unit, generate, file, block_pointer_from_reference(unit, global_storage->function.block));

                let current_basic_block = LLVMGetInsertBlock(generate->builder);
                if (current_basic_block)
                {
                    check(!LLVMGetBasicBlockTerminator(current_basic_block));
                    if (!LLVMGetFirstInstruction(current_basic_block) | !LLVMGetFirstUse((LLVMValueRef)current_basic_block))
                    {
                        LLVMReplaceAllUsesWith((LLVMValueRef)return_block, (LLVMValueRef)current_basic_block);
                        LLVMDeleteBasicBlock(return_block);
                    }
                    else
                    {
                        todo();
                    }
                }
                else
                {
                    bool has_single_jump_to_return_block = false;
                    let single_use = value_has_single_use((LLVMValueRef)return_block);
                    LLVMValueRef user = 0;

                    if (single_use)
                    {
                        user = LLVMGetUser(single_use);
                        has_single_jump_to_return_block = LLVMIsABranchInst(user) != 0 && !LLVMIsConditional(user) && LLVMGetSuccessor(user, 0) == return_block;
                    }

                    if (has_single_jump_to_return_block)
                    {
                        check(LLVMGetBasicBlockParent(return_block) != 0);
                        let new_return_block = LLVMGetInstructionParent(user);
                        // Remove unconditional branch instruction to the return block
                        LLVMInstructionEraseFromParent(user);

                        check(!LLVMGetFirstUse((LLVMValueRef)return_block));
                        check(!LLVMGetBasicBlockTerminator(return_block));
                        check(LLVMGetBasicBlockParent(return_block) != 0);

                        LLVMPositionBuilderAtEnd(generate->builder, new_return_block);
                        LLVMDeleteBasicBlock(return_block);
                    }
                    else
                    {
                        todo();
                    }
                }

                if (unit->has_debug_info)
                {
                    LLVMSetCurrentDebugLocation2(generate->builder, 0);
                }

                if ((ref_eq(semantic_return_type_ref, get_noreturn_type(unit))) | global_storage->function.attributes.is_naked)
                {
                    LLVMBuildUnreachable(generate->builder);
                }
                else if (ref_eq(semantic_return_type_ref, get_void_type(unit)))
                {
                    LLVMBuildRetVoid(generate->builder);
                }
                else
                {
                    LLVMValueRef return_value = 0;
                    Address return_address = generate->current_function.return_address;

                    switch (return_abi->flags.kind)
                    {
                        break; case ABI_KIND_DIRECT: case ABI_KIND_EXTEND:
                        {
                            let coerce_to_type = abi_get_coerce_to_type(return_abi);
                            if (return_abi->attributes.direct.offset == 0 && type_is_abi_equal(unit, coerce_to_type, semantic_return_type_ref))
                            {
                                let store = llvm_find_return_value_dominating_store(generate->builder, return_address.pointer, semantic_return_type->llvm.abi);
                                if (store)
                                {
                                    return_value = store_value_operand(store);
                                    let alloca = store_pointer_operand(store);
                                    check(alloca == return_address.pointer);

                                    if (unit->has_debug_info)
                                    {
                                        LLVMSetCurrentDebugLocation2(generate->builder, LLVMInstructionGetDebugLoc(store));
                                    }

                                    LLVMInstructionEraseFromParent(store);
                                    LLVMInstructionEraseFromParent(alloca);
                                }
                                else
                                {
                                    return_value = address_create_load(unit, generate, return_address, S("ret.load"), 0);
                                }
                            }
                            else
                            {
                                todo();
                            }
                        }
                        break; case ABI_KIND_INDIRECT:
                        {
                            todo();
                        }
                        default: UNREACHABLE();
                    }

                    LLVMBuildRet(generate->builder, return_value);
                }

                LLVMInstructionEraseFromParent(generate->current_function.alloca_insertion_point);

                if (unit->has_debug_info)
                {
                    let subprogram = LLVMGetSubprogram(llvm_function);
                    LLVMDIBuilderFinalizeSubprogram(generate->di_builder, subprogram);
                }

                generate->current_function = (GenerateCurrentFunction){};
                unit->current_function = (GlobalReference){};
            }

            global_ref = global->next;
        }

        file_ref = file->next;
    }
    
    if (unit->has_debug_info)
    {
        LLVMDIBuilderFinalize(generate->di_builder);
    }

    if (verify)
    {
        char* error_message = {};
        let verify_result = LLVMVerifyModule(generate->module, LLVMReturnStatusAction, &error_message) == 0;
        if (!verify_result)
        {
            result_error_message = (str){error_message, strlen(error_message)};
        }
    }

    return (GenerateIRResult) {
        .module = module,
        .target_machine = target_machine,
        .error_message = result_error_message,
    };
}

#if BB_INCLUDE_TESTS
PUB_IMPL bool llvm_generation_tests(TestArguments* arguments)
{
    return 1;
}
#endif
