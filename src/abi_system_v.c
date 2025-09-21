#include <compiler.h>

typedef enum AbiSystemVClass : u8
{
    ABI_SYSTEM_V_CLASS_NONE,
    ABI_SYSTEM_V_CLASS_INTEGER,
    ABI_SYSTEM_V_CLASS_SSE,
    ABI_SYSTEM_V_CLASS_SSE_UP,
    ABI_SYSTEM_V_CLASS_X87,
    ABI_SYSTEM_V_CLASS_X87_UP,
    ABI_SYSTEM_V_CLASS_COMPLEX_X87,
    ABI_SYSTEM_V_CLASS_MEMORY,
} AbiSystemVClass;

STRUCT(Classification)
{
    AbiSystemVClass classes[2];
};

STRUCT(ClassifyOptions)
{
    u64 base_offset;
    bool is_variable_argument;
    bool is_register_call;
};

static Classification abi_system_v_classify_type(CompileUnit* restrict unit, TypeReference type_reference, ClassifyOptions options)
{
    Classification result = {};
    let is_memory = options.base_offset >= 8;
    u64 current_index = is_memory;
    u64 not_current_index = !is_memory;
    assert(current_index != not_current_index);
    result.classes[current_index] = ABI_SYSTEM_V_CLASS_MEMORY;

    let type_pointer = type_pointer_from_reference(unit, type_reference);

    switch (type_pointer->id)
    {
        break; case TYPE_ID_INTEGER:
        {
            let bit_count = type_pointer->integer.bit_count;

            if (bit_count <= 64)
            {
                result.classes[current_index] = ABI_SYSTEM_V_CLASS_INTEGER;
            }
            else if (bit_count == 128)
            {
                result.classes[0] = ABI_SYSTEM_V_CLASS_INTEGER;
                result.classes[1] = ABI_SYSTEM_V_CLASS_INTEGER;
            }
            else
            {
                UNREACHABLE();
            }
        }
        break; default:
        {
            UNREACHABLE();
        }
    }

    return result;
}

static bool contains_no_user_data(CompileUnit* restrict unit, Type* type, u64 start, u64 end)
{
    let byte_size = get_byte_size(unit, type);
    let result = byte_size <= start;

    if (!result)
    {
        todo();
    }

    return result;
}

static TypeReference abi_system_v_get_integer_type_at_offset(CompileUnit* restrict unit, TypeReference type_reference, u64 offset, TypeReference source_type_reference, u64 source_offset)
{
    let type_pointer = type_pointer_from_reference(unit, type_reference);

    switch (type_pointer->id)
    {
        break; case TYPE_ID_INTEGER:
        {
            if (offset == 0)
            {
                let bit_count = type_pointer->integer.bit_count;

                if (bit_count == 64)
                {
                    return type_reference;
                }

                if ((bit_count == 32) | (bit_count == 16) | (bit_count == 8))
                {
                    let start = source_offset + get_byte_size(unit, type_pointer);
                    let end = source_offset + 8;

                    if (contains_no_user_data(unit, type_pointer_from_reference(unit, source_type_reference), start, end))
                    {
                        return type_reference;
                    }
                }
            }
        }
        break; default:
        {
            todo();
        }
    }

    todo();
}

AbiInformation abi_system_v_classify_return_type(CompileUnit* restrict unit, TypeReference type_reference)
{
    let classify = abi_system_v_classify_type(unit, type_reference, (ClassifyOptions){});
    assert(classify.classes[1] != ABI_SYSTEM_V_CLASS_MEMORY || classify.classes[0] == ABI_SYSTEM_V_CLASS_MEMORY);
    assert(classify.classes[1] != ABI_SYSTEM_V_CLASS_SSE_UP || classify.classes[0] == ABI_SYSTEM_V_CLASS_SSE);

    TypeReference result_type = {};

    switch (classify.classes[0])
    {
        break; case ABI_SYSTEM_V_CLASS_INTEGER:
        {
            result_type = abi_system_v_get_integer_type_at_offset(unit, type_reference, 0, type_reference, 0);
            let result_type_pointer = type_pointer_from_reference(unit, result_type);

            if ((classify.classes[1] == ABI_SYSTEM_V_CLASS_NONE) & (result_type_pointer->id == TYPE_ID_INTEGER))
            {
                if (type_is_integral_or_enumeration(unit, type_reference))
                {
                    if (type_is_promotable_integer_for_abi(unit, type_pointer_from_reference(unit, type_reference)))
                    {
                        todo();
                    }
                }
            }
        }
        break; default:
        {
            todo();
        }
    }

    TypeReference high_type = {};

    switch (classify.classes[1])
    {
        break;
        case ABI_SYSTEM_V_CLASS_MEMORY:
        case ABI_SYSTEM_V_CLASS_X87:
        {
            UNREACHABLE();
        }
        break; case ABI_SYSTEM_V_CLASS_NONE: case ABI_SYSTEM_V_CLASS_COMPLEX_X87: {}
        break; default:
        {
            todo();
        }
    }

    if (is_ref_valid(high_type))
    {
        todo();
    }

    let result = abi_get_direct(unit, (AbiDirectOptions) {
        .semantic_type = type_reference,
        .type = result_type,
    });

    return result;
}

AbiSystemVClassifyArgumentTypeResult abi_system_v_classify_argument_type(CompileUnit* restrict unit, TypeReference type, AbiSystemVClassifyArgumentTypeOptions options)
{
    todo();
}

AbiInformation abi_system_v_classify_argument(CompileUnit* restrict unit, AbiRegisterCount* restrict available_registers, TypeReference* restrict abi_argument_type_buffer, AbiSystemVClassifyArgumentOptions options)
{
    todo();
}
