#include <analysis.h>

#define analysis_error() trap()

static void queue_top_level_declarations(CompileUnit* restrict unit, TopLevelDeclarationReference first_tld)
{
    let tld_ref = first_tld;

    while (is_ref_valid(tld_ref))
    {
        let tld = top_level_declaration_pointer_from_reference(unit, tld_ref);

        switch (tld->id)
        {
            break; case TOP_LEVEL_DECLARATION_TYPE:
            {
                todo();
            }
            break; case TOP_LEVEL_DECLARATION_GLOBAL:
            {
                let global_ref = tld->global;
                let global = global_pointer_from_reference(unit, global_ref);

                if (is_ref_valid(unit->last_global))
                {
                    assert(is_ref_valid(unit->first_global));
                    let last_global = global_pointer_from_reference(unit, unit->last_global);
                    last_global->next = global_ref;
                }
                else
                {
                    assert(!is_ref_valid(unit->first_global));
                    unit->first_global = global_ref; 
                }

                unit->last_global = global_ref;
            }
            break; case TOP_LEVEL_DECLARATION_WHEN:
            {
                todo();
            }
        }

        tld_ref = tld->next;
    }
}

static TypeReference resolve_type(CompileUnit* restrict unit, TypeReference* restrict type_reference)
{
    let original_reference = *type_reference;
    let type_pointer = type_pointer_from_reference(unit, original_reference);

    TypeReference result = {};

    if (type_pointer->analyzed)
    {
        result = original_reference;
    }
    else
    {
        switch (type_pointer->id)
        {
            break; case TYPE_ID_FUNCTION:
            {
                let calling_convention = type_pointer->function.calling_convention;
                let resolved_calling_convention = resolve_calling_convention(calling_convention);

                let semantic_types = type_pointer->function.semantic_types;

                for (u64 i = 0; i < type_pointer->function.semantic_argument_count + 1; i += 1)
                {
                    let pointer = &semantic_types[i];
                    resolve_type(unit, &semantic_types[i]);
                }

                let semantic_return_type = get_semantic_return_type(&type_pointer->function);

                switch (resolved_calling_convention)
                {
                    break; case CALLING_CONVENTION_SYSTEM_V:
                    {
                        bool is_register_call = false;

                        type_pointer->function.available_registers = (AbiRegisterCount) {
                            .system_v = {
                                .gpr = is_register_call ? 11 : 6,
                                .sse = is_register_call ? 16 : 8,
                            },
                        };

                        let return_abi = abi_system_v_classify_return_type(unit, semantic_return_type);
                        *get_return_abi_information(&type_pointer->function) = return_abi;
                        todo();
                    }
                    break; default:
                    {
                        UNREACHABLE();
                    }
                }

                todo();
            }
            break; default:
            {
                todo();
            }
        }

        assert(is_ref_valid(result));
        *type_reference = result;
    }

    assert(is_ref_valid(result));
    return result;
}

void analyze(CompileUnit* restrict unit, TopLevelDeclarationReference first_tld)
{
    unit->phase = COMPILE_PHASE_ANALYSIS;

    queue_top_level_declarations(unit, first_tld);

    let global_ref = unit->first_global;

    while (is_ref_valid(global_ref))
    {
        assert(!is_ref_valid(unit->current_function));

        let global = global_pointer_from_reference(unit, global_ref);

        if (!global->analyzed)
        {
            let global_storage_ref = global->variable.storage;
            let global_storage = value_pointer_from_reference(unit, global_storage_ref);

            let global_storage_id = global_storage->id;
            switch (global_storage_id)
            {
                break; case VALUE_ID_FUNCTION:
                {
                    if (!is_ref_valid(global->variable.type))
                    {
                        analysis_error();
                    }

                    let global_type_ref = resolve_type(unit, &global->variable.type);
                    let global_type = type_pointer_from_reference(unit, global_type_ref);
                    if (global_type->id != TYPE_ID_FUNCTION)
                    {
                        analysis_error();
                    }


                    let global_storage_type = get_pointer_type(unit, global_type_ref);
                    global_storage->type = global_storage_type;
                }
                break; case VALUE_ID_GLOBAL:
                {
                    todo();
                }
                break; default:
                {
                    analysis_error();
                }
            }
        }

        global_ref = global->next;
    }
}
