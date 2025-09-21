#include <compiler.h>

AbiInformation abi_get_ignore(TypeReference semantic_type)
{
    return (AbiInformation){
        .semantic_type = semantic_type,
        .flags = {
            .kind = ABI_KIND_IGNORE,
        },
    };
}

AbiInformation abi_get_direct(CompileUnit* restrict unit, AbiDirectOptions options)
{
    AbiInformation result = {
        .semantic_type = options.semantic_type,
        .flags = {
            .kind = ABI_KIND_DIRECT,
        },
    };

    abi_set_coerce_to_type(&result, options.type);
    abi_set_padding_type(&result, options.padding);
    abi_set_direct_offset(&result, options.offset);
    abi_set_direct_alignment(&result, options.alignment);
    abi_set_can_be_flattened(&result, !options.cannot_be_flattened);

    return result;
}

AbiInformation abi_get_extend(CompileUnit* restrict unit, AbiExtendOptions options)
{
    assert(type_is_integral_or_enumeration(unit, options.semantic_type));
    AbiInformation result = {
        .semantic_type = options.semantic_type,
        .flags = {
            .kind = ABI_KIND_EXTEND,
        },
    };

    abi_set_coerce_to_type(&result, is_ref_valid(options.type) ? options.type : options.semantic_type);
    abi_set_padding_type(&result, (TypeReference){});
    abi_set_direct_offset(&result, 0);
    abi_set_direct_alignment(&result, 0);
    result.flags.sign_extension = options.is_signed;

    return result;
}

