#pragma once

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

LOCAL Classification abi_system_v_classify_type(CompileUnit* restrict unit, TypeReference type_reference, ClassifyOptions options)
{
    Classification result = {};
    let is_memory = options.base_offset >= 8;
    u64 current_index = is_memory;
    u64 not_current_index = !is_memory;
    check(current_index != not_current_index);
    result.classes[current_index] = ABI_SYSTEM_V_CLASS_MEMORY;

    let type_pointer = type_pointer_from_reference(unit, type_reference);

    switch (type_pointer->id)
    {
        break; case TYPE_ID_VOID: case TYPE_ID_NORETURN:
        {
            result.classes[current_index] = ABI_SYSTEM_V_CLASS_NONE;
        }
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
        break; case TYPE_ID_POINTER:
        {
            result.classes[current_index] = ABI_SYSTEM_V_CLASS_INTEGER;
        }
        break; default:
        {
            UNREACHABLE();
        }
    }

    return result;
}

LOCAL bool contains_no_user_data(CompileUnit* restrict unit, Type* type, u64 start, u64 end)
{
    let byte_size = get_byte_size(unit, type);
    let result = byte_size <= start;

    if (!result)
    {
        todo();
    }

    return result;
}

LOCAL TypeReference abi_system_v_get_integer_type_at_offset(CompileUnit* restrict unit, TypeReference type_reference, u64 offset, TypeReference source_type_reference, u64 source_offset)
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
        break; case TYPE_ID_POINTER:
        {
            if (offset == 0)
            {
                return type_reference;
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

    let source_type = type_pointer_from_reference(unit, source_type_reference);
    let source_size = get_byte_size(unit, source_type);
    check(source_size != source_offset);
    let byte_count = source_size - source_offset;
    let bit_count = byte_count > 8 ? 64 : byte_count * 8;
    let result = get_integer_type(unit, bit_count, false);

    return result;
}

PUB_IMPL AbiInformation abi_system_v_classify_return_type(CompileUnit* restrict unit, TypeReference return_type_reference)
{
    let classify = abi_system_v_classify_type(unit, return_type_reference, (ClassifyOptions){});
    check(classify.classes[1] != ABI_SYSTEM_V_CLASS_MEMORY || classify.classes[0] == ABI_SYSTEM_V_CLASS_MEMORY);
    check(classify.classes[1] != ABI_SYSTEM_V_CLASS_SSE_UP || classify.classes[0] == ABI_SYSTEM_V_CLASS_SSE);

    TypeReference result_type = {};

    switch (classify.classes[0])
    {
        break; case ABI_SYSTEM_V_CLASS_NONE:
        {
            if (classify.classes[1] == ABI_SYSTEM_V_CLASS_NONE)
            {
                return abi_get_ignore(return_type_reference);
            }
            else
            {
                todo();
            }
        }
        break; case ABI_SYSTEM_V_CLASS_INTEGER:
        {
            result_type = abi_system_v_get_integer_type_at_offset(unit, return_type_reference, 0, return_type_reference, 0);
            let result_type_pointer = type_pointer_from_reference(unit, result_type);

            if ((classify.classes[1] == ABI_SYSTEM_V_CLASS_NONE) & (result_type_pointer->id == TYPE_ID_INTEGER))
            {
                if (type_is_integral_or_enumeration(unit, return_type_reference))
                {
                    if (type_is_promotable_integer_for_abi(unit, type_pointer_from_reference(unit, return_type_reference)))
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
        .semantic_type = return_type_reference,
        .type = result_type,
    });

    return result;
}

PUB_IMPL AbiSystemVClassifyArgumentTypeResult abi_system_v_classify_argument_type(CompileUnit* restrict unit, TypeReference semantic_argument_type_ref, AbiSystemVClassifyArgumentTypeOptions options)
{
    let semantic_argument_type = type_pointer_from_reference(unit, semantic_argument_type_ref);
    let classification = abi_system_v_classify_type(unit, semantic_argument_type_ref, (ClassifyOptions) {
        .base_offset = 0,
        .is_variable_argument = !options.is_named_argument,
        .is_register_call = options.is_register_call,
    });

    AbiRegisterCount needed_registers = {};

    TypeReference result_type = {};

    switch (classification.classes[0])
    {
        break; case ABI_SYSTEM_V_CLASS_NONE:
        {
            UNREACHABLE();
        }
        break; case ABI_SYSTEM_V_CLASS_INTEGER:
        {
            needed_registers.x86_64.gpr += 1;
            result_type = abi_system_v_get_integer_type_at_offset(unit, semantic_argument_type_ref, 0, semantic_argument_type_ref, 0);

            let result_type_pointer = type_pointer_from_reference(unit, result_type);

            if ((classification.classes[1] == ABI_SYSTEM_V_CLASS_NONE) & (result_type_pointer->id == TYPE_ID_INTEGER))
            {
                // TODO: if enumerator?

                if (type_is_integral_or_enumeration(unit, semantic_argument_type_ref) & type_is_promotable_integer_for_abi(unit, semantic_argument_type))
                {
                    return (AbiSystemVClassifyArgumentTypeResult) {
                        .abi = abi_get_extend(unit, (AbiExtendOptions) {
                            .semantic_type = semantic_argument_type_ref,
                            .is_signed = type_is_signed(unit, semantic_argument_type),
                        }),
                        .needed_registers = needed_registers,
                    };
                }
            }
        }
        break; default: todo();
    }
    
    TypeReference high_type = {};

    switch (classification.classes[1])
    {
        break; case ABI_SYSTEM_V_CLASS_NONE: {}
        break; default: todo();
    }

    if (is_ref_valid(high_type))
    {
        todo();
    }

    return (AbiSystemVClassifyArgumentTypeResult) {
        .abi = abi_get_direct(unit, (AbiDirectOptions){
            .semantic_type = semantic_argument_type_ref,
            .type = result_type,
        }),
        .needed_registers = needed_registers,
    };
}

PUB_IMPL AbiInformation abi_system_v_classify_argument(CompileUnit* restrict unit, AbiRegisterCount* restrict available_registers, TypeReference* restrict abi_argument_type_buffer, AbiSystemVClassifyArgumentOptions options)
{
    let semantic_argument_type_ref = options.type;

    if (options.is_register_call)
    {
        todo();
    }

    let result = abi_system_v_classify_argument_type(unit, semantic_argument_type_ref, (AbiSystemVClassifyArgumentTypeOptions) {
        .available_gpr = available_registers->x86_64.gpr,
        .is_named_argument = options.is_named_argument,
        .is_register_call = options.is_register_call,
    });

    let abi = result.abi;
    let needed_registers = result.needed_registers;

    AbiInformation argument_abi;

    if ((available_registers->x86_64.gpr >= needed_registers.x86_64.gpr) & (available_registers->x86_64.sse >= needed_registers.x86_64.sse))
    {
        available_registers->x86_64.gpr -= needed_registers.x86_64.gpr;
        available_registers->x86_64.sse -= needed_registers.x86_64.sse;

        argument_abi = abi;
    }
    else
    {
        todo();
    }

    if (is_ref_valid(abi_get_padding_type(&argument_abi)))
    {
        todo();
    }

    argument_abi.abi_start = options.abi_start;

    u16 count = 0;

    u64 abi_start = options.abi_start;

    switch (argument_abi.flags.kind)
    {
        break;
        case ABI_KIND_DIRECT:
        case ABI_KIND_EXTEND:
        {
            let coerce_to_type_ref = abi_get_coerce_to_type(&argument_abi);
            let coerce_to_type = type_pointer_from_reference(unit, coerce_to_type_ref);
            let is_flattened_struct = ((argument_abi.flags.kind == ABI_KIND_DIRECT) & argument_abi.flags.can_be_flattened) & (coerce_to_type->id == TYPE_ID_STRUCT);

            if (is_flattened_struct)
            {
                todo();
            }
            else
            {
                abi_argument_type_buffer[abi_start] = coerce_to_type_ref;
                count = 1;
            }
        }
        break; case ABI_KIND_INDIRECT:
        {
            todo();
        }
        break; default:
        {
            UNREACHABLE();
        }
    }

    check(count != 0);
    argument_abi.abi_count = count;

    return argument_abi;
}
