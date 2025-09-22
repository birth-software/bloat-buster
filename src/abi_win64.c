#pragma once

#include <compiler.h>

PUB_IMPL AbiInformation win64_classify_type(CompileUnit* restrict unit, TypeReference type_reference, Win64ClassifyOptions options)
{
    Type* restrict type = type_pointer_from_reference(unit, type_reference);

    if ((type->id == TYPE_ID_VOID) | (type->id == TYPE_ID_NORETURN))
    {
        return abi_get_ignore(type_reference);
    }
    else
    {
        let alignment = get_alignment(unit, type);
        let is_type_record = type_is_record(type);
        // TODO: flexible array member
        
        if (options.is_vector_call | options.is_register_call)
        {
            todo();
        }

        // TODO: member pointer?

        if (is_type_record)
        {
            todo();
        }

        switch (type->id)
        {
            break; case TYPE_ID_INTEGER:
            {
                let bit_count = type->integer.bit_count;
                if (bit_count == 1)
                {
                    todo();
                }
                else if (bit_count == 128)
                {
                    todo();
                }
                else if ((bit_count > 64) & ((bit_count & (bit_count - 1)) != 0))
                {
                    todo();
                }
            }
            break; case TYPE_ID_FLOAT:
            {
                todo();
            }
            break; default:{}
        }

        return abi_get_direct(unit, (AbiDirectOptions){ .semantic_type = type_reference, .type = type_reference });
    }
}
