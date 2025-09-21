#include <compiler.h>

typedef enum Aarch64VectorType
{
    AARCH64_VECTOR_GENERIC,
    AARCH64_VECTOR_ALTIVEC_VECTOR,
    AARCH64_VECTOR_ALTIVEC_PIXEL,
    AARCH64_VECTOR_NEON,
    AARCH64_VECTOR_NEON_POLY,
    AARCH64_VECTOR_SVE_FIXED_LENGTH_DATA,
    AARCH64_VECTOR_SVE_FIXED_LENGTH_PREDICATE,
    AARCH64_VECTOR_RVV_FIXED_LENGTH_DATA,
    AARCH64_VECTOR_RVV_FIXED_LENGTH_MASK,
    AARCH64_VECTOR_RVV_FIXED_LENGTH_MASK_1,
    AARCH64_VECTOR_RVV_FIXED_LENGTH_MASK_2,
    AARCH64_VECTOR_RVV_FIXED_LENGTH_MASK_4,
} Aarch64VectorType;

// TODO
static Aarch64VectorType get_vector_kind(Type* type)
{
    return AARCH64_VECTOR_GENERIC;
}

// TODO
static bool is_sve_sizeless_builtin_type(Type* type)
{
    return false;
}

static bool pass_as_aggregate_type(CompileUnit* restrict unit, Type* type, Aarch64AbiKind kind)
{
    if ((kind == AARCH64_ABI_KIND_AAPCS) & is_sve_sizeless_builtin_type(type))
    {
        todo();
    }

    return type_is_aggregate_for_abi(unit, type);
}

AbiInformation aarch64_classify_return_type(CompileUnit* restrict unit, TypeReference return_type_reference, bool is_variadic_function, Aarch64AbiKind kind)
{
    let return_type = type_pointer_from_reference(unit, return_type_reference);
    let byte_size = get_byte_size(unit, return_type);

    if ((return_type->id == TYPE_ID_VOID) | (return_type->id == TYPE_ID_NORETURN))
    {
        return abi_get_ignore(return_type_reference);
    }

    if (return_type->id == TYPE_ID_VECTOR)
    {
        let kind = get_vector_kind(return_type);
        if ((kind == AARCH64_VECTOR_SVE_FIXED_LENGTH_DATA) | (kind == AARCH64_VECTOR_SVE_FIXED_LENGTH_PREDICATE))
        {
            todo();
        }
    }

    if ((return_type->id == TYPE_ID_VECTOR) & (byte_size > 128))
    {
        todo();
    }

    if (!pass_as_aggregate_type(unit, return_type, kind))
    {
        if (return_type->id == TYPE_ID_ENUM)
        {
            todo();
        }

        if (return_type->id == TYPE_ID_INTEGER)
        {
            let bit_count = return_type->integer.bit_count;
            if ((bit_count > 128) & ((bit_count & (bit_count - 1)) != 0))
            {
                todo();
            }
        }

        let result = (type_is_promotable_integer_for_abi(unit, return_type) & (kind == AARCH64_ABI_KIND_DARWIN_PCS)) ?
            abi_get_extend(unit, (AbiExtendOptions) { .semantic_type = return_type_reference, .is_signed = type_is_signed(unit, return_type) }) :
            abi_get_direct(unit, (AbiDirectOptions) { .semantic_type = return_type_reference, .type = return_type_reference });

        return result;
    }

    todo();
}
