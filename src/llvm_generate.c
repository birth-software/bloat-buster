#include <llvm_generate.h>
#include <llvm-c/Core.h>
#include <llvm-c/DebugInfo.h>
#include <llvm-c/Target.h>
#include <llvm-c/Analysis.h>
#include <llvm_common.h>

#define llvm_error() todo()

static void llvm_module_set_flag(LLVMContextRef context, LLVMModuleRef module, LLVMModuleFlagBehavior behavior, str flag, u32 value)
{
    let value_constant = LLVMConstInt(LLVMIntTypeInContext(context, 32), value, 0);
    let value_metadata = LLVMValueAsMetadata(value_constant);
    LLVMAddModuleFlag(module, behavior, flag.pointer, flag.length, value_metadata);
}

static bool type_is_abi_equal(CompileUnit* restrict unit, TypeReference a, TypeReference b)
{
    assert(is_ref_valid(a));
    assert(is_ref_valid(b));

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

static str llvm_attribute_names[] =
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

static str llvm_intrinsic_names[] =
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

static u32 llvm_default_address_space = 0;

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

static void generate_type_abi(CompileUnit* restrict unit, Generate* restrict generate, Type* type);
static void generate_type_memory(CompileUnit* restrict unit, Generate* restrict generate, Type* type);
static void generate_type_debug(CompileUnit* restrict unit, Generate* restrict generate, Type* type);

static void generate_type(CompileUnit* restrict unit, Generate* restrict generate, Type* restrict type)
{
    generate_type_abi(unit, generate, type);
    generate_type_memory(unit, generate, type);
    generate_type_debug(unit, generate, type);
}

static void generate_type_abi(CompileUnit* restrict unit, Generate* restrict generate, Type* type)
{
    assert(type->analyzed);
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
                    generate_type(unit, generate, abi_return_type);
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

        assert(result);
        type->llvm.abi = result;
    }
}

static void generate_type_memory(CompileUnit* restrict unit, Generate* restrict generate, Type* type)
{
    assert(type->analyzed);

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

        assert(result);
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

static void generate_type_debug(CompileUnit* restrict unit, Generate* restrict generate, Type* type)
{
    assert(type->analyzed);
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
                let type_array = arena_allocate(arena, LLVMMetadataRef, semantic_argument_count);

                let semantic_return_type = type_pointer_from_reference(unit, get_semantic_return_type(&type->function));
                generate_type_debug(unit, generate, semantic_return_type);
                type_array[0] = semantic_return_type->llvm.debug; 

                let argument_types = type_array + 1;
                for (u16 i = 0; i < semantic_argument_count; i += 1)
                {
                    todo();
                }

                if (is_variable_argument)
                {
                    let void_type = get_void_type(unit);
                    todo();
                }

                let file = file_pointer_from_reference(unit, type->function.file);
                LLVMDIFlags flags = {};
                result = LLVMDIBuilderCreateSubroutineType(di_builder, file->handle, type_array, type_array_count, flags);
            }
            break; default: todo();
        }

        assert(result);
        type->llvm.debug = result;
    }
}

static LLVMValueRef llvm_create_function(LLVMModuleRef module, LLVMTypeRef function_type, LLVMLinkage linkage, str name)
{
    assert(str_is_zero_terminated(name));
    let function = LLVMAddFunction(module, name.pointer, function_type);
    LLVMSetLinkage(function, linkage);
    return function;
}

static LLVMValueRef llvm_create_alloca(LLVMBuilderRef builder, LLVMTypeRef base_type, u32 alignment, str name)
{
    if (name.pointer)
    {
        assert(str_is_zero_terminated(name));
    }
    else
    {
        name = S("");
    }
    let alloca = LLVMBuildAlloca(builder, base_type, name.pointer);
    LLVMSetAlignment(alloca, alignment);
    return alloca;
}

static LLVMValueRef llvm_create_store(LLVMBuilderRef builder, LLVMValueRef source, LLVMValueRef destination, u32 alignment, bool is_volatile, LLVMAtomicOrdering ordering)
{
    let store = LLVMBuildStore(builder, source, destination);

    LLVMSetAlignment(store, alignment);
    LLVMSetVolatile(store, is_volatile);
    LLVMSetOrdering(store, ordering);
    
    return store;
}

static LLVMValueRef llvm_create_load(LLVMBuilderRef builder, LLVMTypeRef type, LLVMValueRef pointer, u32 alignment, str name, bool is_volatile, LLVMAtomicOrdering ordering)
{
    if (name.pointer)
    {
        assert(str_is_zero_terminated(name));
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

static bool type_is_vector_bool(CompileUnit* restrict unit, Type* type)
{
    return (type->id == TYPE_ID_VECTOR) & ref_eq(type->vector.element_type, get_u1(unit));
}

static Type* convert_type_for_memory(CompileUnit* restrict unit, Type* type)
{
    let result = type;
    if (type_is_vector_bool(unit, type))
    {
        todo();
    }

    return result;
}

static LLVMTypeRef get_llvm_type(Type* type, TypeKind kind)
{
    LLVMTypeRef result = {};
    switch (kind)
    {
        break; case TYPE_KIND_ABI: result = type->llvm.abi;
        break; case TYPE_KIND_MEMORY: result = type->llvm.memory;
    }
    assert(result);
    return result;
}

STRUCT(AllocaOptions)
{
    Type* type;
    str name;
    u32 alignment;
    bool use_abi;
};

static LLVMValueRef create_alloca(CompileUnit* restrict unit, Generate* restrict generate, AllocaOptions options)
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

static LLVMValueRef create_store(CompileUnit* restrict unit, Generate* restrict generate, StoreOptions options)
{
    assert(options.source);
    assert(options.destination);
    assert(options.type);

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

static LLVMValueRef create_load(CompileUnit* restrict unit, Generate* restrict generate, LoadOptions options)
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
            todo();
        }
    }

    return result;
}

typedef void LLVMAttributeCallback(LLVMValueRef, u32, LLVMAttributeRef);

static void add_enum_attribute(Generate* restrict generate, LLVMAttributeIndexReference attribute_index, u64 attribute_value, LLVMAttributeCallback* callback, LLVMValueRef value, u32 index)
{
    let attribute = LLVMCreateEnumAttribute(generate->context, generate->attribute_table[attribute_index].v, attribute_value);
    callback(value, index, attribute);
}

static void add_type_attribute(Generate* restrict generate, LLVMAttributeIndexReference attribute_index, LLVMTypeRef type, LLVMAttributeCallback* callback, LLVMValueRef value, u32 index)
{
    let attribute = LLVMCreateTypeAttribute(generate->context, generate->attribute_table[attribute_index].v, type);
    callback(value, index, attribute);
}

static void add_string_attribute(Generate* restrict generate, str attribute_key, str attribute_value, LLVMAttributeCallback* callback, LLVMValueRef value, u32 index)
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

static void add_value_attribute(Generate* restrict generate, LLVMValueRef value, u32 index, LLVMAttributeCallback* callback, LLVMTypeRef semantic_type, LLVMAttributes attributes)
{
    assert(value);
    assert(semantic_type);

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

static void generate_function_attributes(CompileUnit* unit, Generate* restrict generate, LLVMValueRef value, LLVMAttributeCallback* callback, FunctionAttributeBuildOptions options)
{
    let return_abi = &options.abis[0];
    let semantic_return_type_ref = return_abi->semantic_type;
    let semantic_return_type = type_pointer_from_reference(unit, semantic_return_type_ref);
    let abi_return_type = options.abi_types[0];
    let semantic_argument_count = options.semantic_argument_count;
    let abi_argument_count = options.abi_argument_count;
    let argument_abis = return_abi + 1;
    let abi_argument_types = options.abi_types + 1;

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

        let abi_type = abi_argument_types[abi_index];

        add_value_attribute(generate, value, abi_index + 1, callback, semantic_return_type->llvm.memory, (LLVMAttributes) {
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

    for (u16 i = 0; i < abi_argument_count; i += 1)
    {
        let abi = &argument_abis[i];
        let abi_start = abi->abi_start;
        let abi_count = abi->abi_count;

        for (u16 abi_index = abi_start; abi_index < abi_start + abi_count; abi_index += 1)
        {
            let abi_type = type_pointer_from_reference(unit, abi_argument_types[abi_index]);
            let semantic_type = type_pointer_from_reference(unit, abi->semantic_type);
            u32 alignment = abi->flags.kind == ABI_KIND_INDIRECT ? MAX(get_alignment(unit, semantic_type), 8) : 0;
            assert(alignment == 0 || alignment >= 8);
            add_value_attribute(generate, value, abi_index + 1, callback, semantic_type->llvm.memory, (LLVMAttributes) {
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

    assert(total_abi_count == abi_argument_count);

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

static void generate_value(CompileUnit* restrict unit, Generate* restrict generate, Value* restrict value, TypeKind type_kind, bool expect_constant);

static LLVMValueRef generate_call(CompileUnit* restrict unit, Generate* restrict generate, Value* value, Address address)
{
    let is_valid_address_argument = address.pointer != 0;

    assert(value->id == VALUE_ID_CALL);

    let function_type_ref = value->call.function_type;
    let function_type = type_pointer_from_reference(unit, function_type_ref);
    assert(function_type->id == TYPE_ID_FUNCTION);
    let callable = value_pointer_from_reference(unit, value->call.callable);
    let call_arguments = value->call.arguments;
    assert(call_arguments.count < UINT16_MAX);

    // TODO: load function pointer
    generate_value(unit, generate, callable, TYPE_KIND_ABI, 0);
    assert(callable->kind == VALUE_KIND_LEFT);
    let callable_type = type_pointer_from_reference(unit, callable->type);
    assert(callable_type->id == TYPE_ID_POINTER);

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
    AbiInformation abi_buffer[512];
    TypeReference abi_types[array_length(llvm_abi_argument_buffer)];

    assert(declaration_semantic_argument_count <= array_length(abi_buffer));
    assert(declaration_abi_argument_count <= array_length(llvm_abi_argument_buffer));
    memcpy(abi_buffer, get_abis(&function_type->function), (declaration_semantic_argument_count + 1) * sizeof(AbiInformation));
    memcpy(abi_types, function_type->function.abi_types, (declaration_abi_argument_count + 1) * sizeof(TypeReference));
    let return_abi = &abi_buffer[0];
    AbiKind return_abi_kind = return_abi->flags.kind;

    u16 abi_argument_count = 0;

    switch (return_abi_kind)
    {
        break; case ABI_KIND_INDIRECT: case ABI_KIND_IN_ALLOCA: case ABI_KIND_COERCE_AND_EXPAND:
        {
            todo();
        }
        break; default: {}
    }

    for (u16 call_argument_index = 0; call_argument_index < (u16)call_arguments.count; call_argument_index += 1)
    {
        todo();
    }

    if (function_type->function.is_variable_argument)
    {
        assert(declaration_abi_argument_count <= abi_argument_count);
    }
    else
    {
        assert(declaration_abi_argument_count == abi_argument_count);
    }

    for (u16 i = 0; i < abi_argument_count; i += 1)
    {
        assert(llvm_abi_argument_buffer[i]);
    }
    
    let llvm_call = LLVMBuildCall2(generate->builder, function_type->llvm.abi, llvm_callable, llvm_abi_argument_buffer, abi_argument_count, "");
    LLVMCallConv calling_convention;

    switch (function_type->function.calling_convention)
    {
        break; case CALLING_CONVENTION_C: calling_convention = LLVMCCallConv;
        break; default: UNREACHABLE();
    }

    LLVMSetInstructionCallConv(llvm_call, calling_convention);

    generate_function_attributes(unit, generate, llvm_call, &LLVMAddCallSiteAttribute, (FunctionAttributeBuildOptions) {
        .abis = abi_buffer,
        .abi_types = abi_types,
        .semantic_argument_count = call_arguments.count,
        .abi_argument_count = abi_argument_count,
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

static void generate_value(CompileUnit* restrict unit, Generate* restrict generate, Value* restrict value, TypeKind type_kind, bool expect_constant)
{
    assert(unit->phase == COMPILE_PHASE_LLVM_IR_GENERATION);

    let must_be_constant = expect_constant | !is_ref_valid(unit->current_function);

    let current_function = get_current_function(unit);
    let current_function_type = get_function_type_from_storage(unit, current_function);

    let value_type_ref = value->type;
    assert(is_ref_valid(value_type_ref));
    let value_type = type_pointer_from_reference(unit, value_type_ref);

    LLVMValueRef llvm_value = 0;

    switch (value->id)
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
                    assert(ref_eq(value_type_ref, storage->type));
                    llvm_value = llvm_storage;
                }
                break; case VALUE_KIND_RIGHT:
                {
                    assert(ref_eq(value_type_ref, variable->type));
                    if (must_be_constant)
                    {
                        todo();
                    }
                    else
                    {
                        // TODO: more fine-grained assertion
                        assert(get_byte_size(unit, value_type) <= 16);
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
        break; case VALUE_ID_UNARY_MINUS_INTEGER:
        {
            let operand = value_pointer_from_reference(unit, value->unary);
            generate_value(unit, generate, operand, TYPE_KIND_ABI, must_be_constant);
            let llvm_operand = operand->llvm;
            llvm_value = LLVMBuildNeg(generate->builder, llvm_operand, "");
        }
        break; case VALUE_ID_BINARY_ADD_INTEGER:
        {
            LLVMValueRef operands[2];
            for (u64 i = 0; i < array_length(operands); i += 1)
            {
                let operand = value_pointer_from_reference(unit, value->binary[i]);
                generate_value(unit, generate, operand, TYPE_KIND_ABI, must_be_constant);
                operands[i] = operand->llvm;
            }

            llvm_value = LLVMBuildAdd(generate->builder, operands[0], operands[1], "");
        }
        break; default: todo();
    }

    assert(llvm_value);
    value->llvm = llvm_value;
}

static void generate_assignment(CompileUnit* restrict unit, Generate* restrict generate, Value* right, Address address)
{
    assert(unit->phase == COMPILE_PHASE_LLVM_IR_GENERATION);

    let current_function = get_current_function(unit);
    let current_function_type = get_function_type_from_storage(unit, current_function);

    assert(!right->llvm);
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

static void generate_local_storage(CompileUnit* restrict unit, Generate* restrict generate, Variable* restrict variable)
{
    let storage = value_pointer_from_reference(unit, variable->storage);
    let alloca = create_alloca(unit, generate, (AllocaOptions) {
        .type = type_pointer_from_reference(unit, variable->type),
        .name = string_from_reference(unit, variable->name),
    });

    storage->llvm = alloca;
}

static LLVMMetadataRef null_expression(Generate* restrict generate)
{
    return LLVMDIBuilderCreateExpression(generate->di_builder, 0, 0);
}

static void end_debug_local(CompileUnit* restrict unit, Generate* restrict generate, Variable* restrict variable, LLVMMetadataRef llvm_local)
{
    let scope = scope_pointer_from_reference(unit, variable->scope);
    let debug_location = LLVMDIBuilderCreateDebugLocation(generate->context, location_get_line(variable->location), location_get_column(variable->location), scope->llvm, generate->current_function.inlined_at);
    LLVMSetCurrentDebugLocation2(generate->builder, debug_location);
    let basic_block = LLVMGetInsertBlock(generate->builder);
    assert(basic_block);
    let storage = value_pointer_from_reference(unit, variable->storage);
    LLVMDIBuilderInsertDeclareRecordAtEnd(generate->di_builder, storage->llvm, llvm_local, null_expression(generate), debug_location, basic_block);
}

static void generate_local_declaration(CompileUnit* restrict unit, Generate* restrict generate, File* file, Local* restrict local)
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

static void generate_statement(CompileUnit* restrict unit, Generate* restrict generate, File* file, Scope* restrict scope, Statement* statement)
{
    assert(unit->phase == COMPILE_PHASE_LLVM_IR_GENERATION);

    let current_function = get_current_function(unit);
    let current_function_type = get_function_type_from_storage(unit, current_function);

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
        break; default: todo();
    }
}

static void generate_block(CompileUnit* restrict unit, Generate* restrict generate, File* file, Block* restrict block)
{
    assert(unit->phase == COMPILE_PHASE_LLVM_IR_GENERATION);
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
static LLVMUseRef value_has_single_use(LLVMValueRef v)
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

static LLVMValueRef store_pointer_operand(LLVMValueRef store)
{
    assert(LLVMIsAStoreInst(store));
    return LLVMGetOperand(store, 1);
}

static LLVMValueRef store_value_operand(LLVMValueRef store)
{
    assert(LLVMIsAStoreInst(store));
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

static LLVMValueRef llvm_get_store_if_valid(LLVMValueRef user, LLVMValueRef return_alloca, LLVMTypeRef element_type)
{
    let is_user_store_instruction = LLVMIsAStoreInst(user);
    if (!is_user_store_instruction || store_pointer_operand(user) != return_alloca || LLVMTypeOf(store_value_operand(user)) != element_type)
    {
        return 0;
    }

    assert(!LLVMIsAtomic(user) && !LLVMGetVolatile(user));
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

static LLVMValueRef llvm_find_return_value_dominating_store(LLVMBuilderRef builder, LLVMValueRef return_alloca, LLVMTypeRef element_type)
{
    LLVMValueRef result = 0;
    if (!value_has_single_use(return_alloca))
    {
        trap();
    }

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
            assert(element_count < 64);
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

    return result;
}

GenerateIRResult llvm_generate_ir(CompileUnit* restrict unit, bool verify)
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

    assert(!error_message);

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
        assert(id != 0);
        generate->intrinsic_table[i] = (LLVMIntrinsicId){
            .v = id,
        };
    }

    for (u64 i = 0; i < LLVM_ATTRIBUTE_COUNT; i += 1)
    {
        let name = llvm_attribute_names[i];
        let id = LLVMGetEnumAttributeKindForName(name.pointer, name.length);
        assert(id != 0);
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
                assert(global_storage_type->id == TYPE_ID_POINTER);
                assert(ref_eq(global_storage_type->pointer.element_type, global_type_ref)); 

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

            if (global_storage->id == VALUE_ID_FUNCTION)
            {
                unit->current_function = global_ref;
                let function_pointer_type = type_pointer_from_reference(unit, global_storage->type);
                assert(function_pointer_type->id == TYPE_ID_POINTER);
                let function_type_ref = function_pointer_type->pointer.element_type;
                let function_type = type_pointer_from_reference(unit, function_type_ref);
                assert(function_type->id == TYPE_ID_FUNCTION);

                let llvm_function = global_storage->llvm;
                LLVMValueRef llvm_abi_argument_buffer[256];
                let semantic_argument_count = function_type->function.semantic_argument_count;
                let abi_argument_count = function_type->function.abi_argument_count;
                assert(abi_argument_count <= array_length(llvm_abi_argument_buffer));
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
                    todo();
                }

                bool use_indirect_debug_address = 0;

                for (u16 i = 0; i < parameter_value_count; i += 1)
                {
                    todo();
                }

                generate_block(unit, generate, file, block_pointer_from_reference(unit, global_storage->function.block));

                let current_basic_block = LLVMGetInsertBlock(generate->builder);
                if (current_basic_block)
                {
                    todo();
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
                        assert(LLVMGetBasicBlockParent(return_block) != 0);
                        let new_return_block = LLVMGetInstructionParent(user);
                        // Remove unconditional branch instruction to the return block
                        LLVMInstructionEraseFromParent(user);

                        assert(!LLVMGetFirstUse((LLVMValueRef)return_block));
                        assert(!LLVMGetBasicBlockTerminator(return_block));
                        assert(LLVMGetBasicBlockParent(return_block) != 0);

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
                                    assert(alloca == return_address.pointer);

                                    if (unit->has_debug_info)
                                    {
                                        LLVMSetCurrentDebugLocation2(generate->builder, LLVMInstructionGetDebugLoc(store));
                                    }

                                    LLVMInstructionEraseFromParent(store);
                                    LLVMInstructionEraseFromParent(alloca);
                                }
                                else
                                {
                                    todo();
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
bool llvm_generation_tests(TestArguments* arguments)
{
    return 1;
}
#endif
