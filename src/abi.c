#pragma once

#include <compiler.h>

LOCAL bool abi_can_have_coerce_to_type(AbiInformation* restrict abi)
{
    AbiKind kind = abi->flags.kind;
    return (kind == ABI_KIND_DIRECT) | (kind == ABI_KIND_EXTEND) | (kind == ABI_KIND_COERCE_AND_EXPAND);
}

LOCAL bool abi_can_have_padding_type(AbiInformation* restrict abi)
{
    AbiKind kind = abi->flags.kind;
    return ((kind == ABI_KIND_DIRECT) | (kind == ABI_KIND_EXTEND)) | ((kind == ABI_KIND_INDIRECT) | (kind == ABI_KIND_INDIRECT_ALIASED)) | (kind == ABI_KIND_EXPAND);
}

PUB_IMPL TypeReference abi_get_padding_type(AbiInformation* restrict abi)
{
    return abi_can_have_padding_type(abi) ? abi->padding.type : (TypeReference){};
}

PUB_IMPL void abi_set_coerce_to_type(AbiInformation* restrict abi, TypeReference type_reference)
{
    check(abi_can_have_coerce_to_type(abi));
    abi->coerce_to_type = type_reference;
}

PUB_IMPL void abi_set_padding_type(AbiInformation* restrict abi, TypeReference type_reference)
{
    check(abi_can_have_padding_type(abi));
    abi->padding.type = type_reference;
}

PUB_IMPL void abi_set_direct_offset(AbiInformation* restrict abi, u32 offset)
{
    check((abi->flags.kind == ABI_KIND_DIRECT) || (abi->flags.kind == ABI_KIND_EXTEND));
    abi->attributes.direct.offset = offset;
}

PUB_IMPL void abi_set_direct_alignment(AbiInformation* restrict abi, u32 alignment)
{
    check((abi->flags.kind == ABI_KIND_DIRECT) || (abi->flags.kind == ABI_KIND_EXTEND));
    abi->attributes.direct.alignment = alignment;
}

PUB_IMPL void abi_set_can_be_flattened(AbiInformation* restrict abi, bool value)
{
    check(abi->flags.kind == ABI_KIND_DIRECT);
    abi->flags.can_be_flattened = value;
}

PUB_IMPL TypeReference abi_get_coerce_to_type(AbiInformation* restrict abi)
{
    check(abi_can_have_coerce_to_type(abi));
    return abi->coerce_to_type;
}

PUB_IMPL AbiInformation abi_get_ignore(TypeReference semantic_type)
{
    return (AbiInformation){
        .semantic_type = semantic_type,
        .flags = {
            .kind = ABI_KIND_IGNORE,
        },
    };
}

PUB_IMPL AbiInformation abi_get_direct(CompileUnit* restrict unit, AbiDirectOptions options)
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

PUB_IMPL AbiInformation abi_get_extend(CompileUnit* restrict unit, AbiExtendOptions options)
{
    check(type_is_integral_or_enumeration(unit, options.semantic_type));
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

