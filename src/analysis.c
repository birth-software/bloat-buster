#include <analysis.h>

#define analysis_error() trap()

static TypeReference get_u64(CompileUnit* restrict unit)
{
    return get_integer_type(unit, 64, 0);
}

static void queue_top_level_declarations(CompileUnit* restrict unit, FileReference file_reference, TopLevelDeclarationReference first_tld)
{
    let file = file_pointer_from_reference(unit, file_reference);
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

                if (is_ref_valid(file->last_global))
                {
                    assert(is_ref_valid(file->first_global));
                    let last_global = global_pointer_from_reference(unit, file->last_global);
                    last_global->next = global_ref;
                }
                else
                {
                    assert(!is_ref_valid(file->first_global));
                    file->first_global = global_ref; 
                }

                file->last_global = global_ref;
            }
            break; case TOP_LEVEL_DECLARATION_WHEN:
            {
                todo();
            }
        }

        tld_ref = tld->next;
    }
}

static TypeReference analyze_type(CompileUnit* restrict unit, TypeReference* restrict type_reference)
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
                    analyze_type(unit, &semantic_types[i]);
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

                        let return_abi = get_return_abi_information(&type_pointer->function);
                        *return_abi = abi_system_v_classify_return_type(unit, semantic_return_type);
                        AbiKind return_abi_kind = return_abi->flags.kind;

                        TypeReference abi_return_type = {};

                        switch (return_abi_kind)
                        {
                            break;
                            case ABI_KIND_DIRECT:
                            case ABI_KIND_EXTEND:
                            {
                                abi_return_type = analyze_type(unit, &return_abi->coerce_to_type);
                            }
                            break;
                            case ABI_KIND_IGNORE:
                            case ABI_KIND_INDIRECT:
                            {
                                abi_return_type = get_void_type(unit);
                            }
                            break; default:
                            {
                                UNREACHABLE();
                            }
                        }

                        TypeReference abi_type_buffer[1024];
                        u16 abi_type_count = 0;

                        assert(is_ref_valid(abi_return_type));
                        abi_type_buffer[abi_type_count] = abi_return_type;
                        abi_type_count += 1;

                        if (return_abi_kind == ABI_KIND_INDIRECT)
                        {
                            assert(!return_abi->flags.sret_after_this);
                            todo();
                        }

                        for (u16 i = 0; i < type_pointer->function.semantic_argument_count; i += 1)
                        {
                            todo();
                        }

                        let abi_types = arena_allocate(unit_arena(unit, UNIT_ARENA_COMPILE_UNIT), TypeReference, abi_type_count);
                        memcpy(abi_types, abi_type_buffer, sizeof(abi_type_buffer[0]) * abi_type_count);
                        type_pointer->function.abi_types = abi_types;
                        type_pointer->function.abi_argument_count = abi_type_count - 1;
                    }
                    break; default:
                    {
                        UNREACHABLE();
                    }
                }

                result = original_reference;
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

static Global* get_current_function(CompileUnit* restrict unit)
{
    let current_function_ref = unit->current_function;
    if (!is_ref_valid(current_function_ref))
    {
        analysis_error();
    }

    let current_function = global_pointer_from_reference(unit, current_function_ref);
    return current_function;
}

static Type* get_function_type(CompileUnit* restrict unit, Global* function)
{
    let function_storage_ref = function->variable.storage;
    let function_storage = value_pointer_from_reference(unit, function_storage_ref);
    let function_pointer_type_ref = function_storage->type;
    assert(is_ref_valid(function_pointer_type_ref));
    let function_pointer_type = type_pointer_from_reference(unit, function_pointer_type_ref);
    assert(function_pointer_type->id == TYPE_ID_POINTER);
    let function_type_ref = function_pointer_type->pointer.element_type;
    assert(is_ref_valid(function_type_ref));
    let function_type = type_pointer_from_reference(unit, function_type_ref);
    assert(function_type->id == TYPE_ID_FUNCTION);

    return function_type;
}

static u64 integer_max_value(u64 bit_count, bool is_signed)
{
    assert(bit_count <= 64);
    let result = bit_count == 64 ? ~(u64)0 : ((u64)1 << (bit_count - is_signed)) - 1;
    return result;
}

typedef enum IdentifierSearchId : u8
{
    IDENTIFIER_SEARCH_NONE,
    IDENTIFIER_SEARCH_VALUE,
    IDENTIFIER_SEARCH_TYPE,
} IdentifierSearchId;

STRUCT(IdentifierSearch)
{
    union
    {
        TypeReference type;
        ValueReference value;
    };
    IdentifierSearchId id;
};

STRUCT(TypeAnalysis)
{
    TypeReference indexing_type;
    bool must_be_constant;
};

static IdentifierSearch reference_identifier(CompileUnit* restrict unit, ValueReference* value_ref, TypeReference expected_type, TypeAnalysis analysis)
{
    let original_reference = *value_ref;
    let value = value_pointer_from_reference(unit, original_reference);
    assert(value->id == VALUE_ID_UNRESOLVED_IDENTIFIER);
    let identifier_ref = value->unresolved_identifier.string;
    let current_scope = value->unresolved_identifier.scope;
    Variable* variable = {};
    Type* type = {};
    let scope_ref = current_scope;

    while (is_ref_valid(scope_ref) & ((variable == 0) & (type == 0)))
    {
        let scope = scope_pointer_from_reference(unit, scope_ref);
        let ty = scope->types.first;
        while (is_ref_valid(ty))
        {
            todo();
        }

        if (!type)
        {
            switch (scope->id)
            {
                break; case SCOPE_ID_NONE: UNREACHABLE();
                break; case SCOPE_ID_GLOBAL:
                {
                    todo();
                }
                break; case SCOPE_ID_FILE:
                {
                    let file = file_pointer_from_reference(unit, scope->file);
                    let global_ref = file->first_global;
                    while (is_ref_valid(global_ref))
                    {
                        let global = global_pointer_from_reference(unit, global_ref);
                        if (ref_eq(identifier_ref, global->variable.name))
                        {
                            variable = &global->variable;
                            break;
                        }

                        global_ref = global->next;
                    }
                }
                break; case SCOPE_ID_FUNCTION:
                {
                    let global = global_pointer_from_reference(unit, scope->function);
                    let storage = value_pointer_from_reference(unit, global->variable.storage);
                    assert(storage->id == VALUE_ID_FUNCTION);

                    let argument_ref = storage->function.arguments;
                    while (is_ref_valid(argument_ref))
                    {
                        todo();
                    }
                }
                break; case SCOPE_ID_BLOCK:
                {
                    let block = block_pointer_from_reference(unit, scope->block);

                    let local_ref = block->first_local;
                    while (is_ref_valid(local_ref))
                    {
                        let local = local_pointer_from_reference(unit, local_ref);
                        if (ref_eq(identifier_ref, local->variable.name))
                        {
                            variable = &local->variable;
                            break;
                        }

                        local_ref = local->next;
                    }
                }
            }

        }

        scope_ref = scope->parent;
    }
    
    IdentifierSearch result = {};

    if (variable)
    {
        if (value_ref)
        {
            let value = value_pointer_from_reference(unit, original_reference);
            let kind = value->kind;
            let storage = value_pointer_from_reference(unit, variable->storage);
            *value = (Value) {
                .variable = variable_reference_from_pointer(unit, variable),
                .type = kind == VALUE_KIND_RIGHT ? variable->type : storage->type,
                .id = VALUE_ID_REFERENCED_VARIABLE,
                .kind = kind,
                .analyzed = 0,
            };

            result = (IdentifierSearch) {
                .value = original_reference,
                .id = IDENTIFIER_SEARCH_VALUE,
            };
        }
        else
        {
            todo();
        }
    }
    else if (type)
    {
        todo();
    }

    return result;
}

static void check_types(CompileUnit* restrict unit, TypeReference expected, TypeReference source)
{
    assert(is_ref_valid(expected));
    assert(is_ref_valid(expected));

    if (!ref_eq(expected, source))
    {
        todo();
    }
}

static void typecheck(CompileUnit* restrict unit, TypeReference expected, TypeReference source)
{
    if (is_ref_valid(expected))
    {
        check_types(unit, expected, source);
    }
}

static ValueReference analyze_value(CompileUnit* restrict unit, ValueReference* restrict value_reference, TypeReference expected_type, TypeAnalysis analysis)
{
    let original_reference = *value_reference;
    let value = value_pointer_from_reference(unit, original_reference);

    assert(!value->analyzed);
    assert(!is_ref_valid(value->type));

    if (value->id == VALUE_ID_UNRESOLVED_IDENTIFIER)
    {
        let identifier = value->unresolved_identifier.string;
        let scope = value->unresolved_identifier.scope;

        let search = reference_identifier(unit, &original_reference, expected_type, analysis);

        switch (search.id)
        {
            break; case IDENTIFIER_SEARCH_NONE:
            {
                analysis_error();
            }
            break; case IDENTIFIER_SEARCH_VALUE:
            {
                assert(ref_eq(original_reference, search.value));
            }
            break; case IDENTIFIER_SEARCH_TYPE:
            {
                todo();
            }
        }
    }

    ValueReference result = {};

    switch (value->id)
    {
        break; case VALUE_ID_CONSTANT_INTEGER:
        {
            if (!is_ref_valid(expected_type))
            {
                if (is_ref_valid(analysis.indexing_type))
                {
                    expected_type = get_u64(unit);
                }
            }

            if (!is_ref_valid(expected_type))
            {
                analysis_error();
            }

            let type = type_pointer_from_reference(unit, expected_type);
            let constant_value = value->integer;

            switch (type->id)
            {
                break; case TYPE_ID_INTEGER:
                {
                    let type_bit_count = type->integer.bit_count;
                    let type_is_signed = type->integer.is_signed;

                    let max_value = integer_max_value(type_bit_count, type_is_signed);

                    if (constant_value > max_value)
                    {
                        analysis_error();
                    }

                    value->type = expected_type;
                }
                break; case TYPE_ID_POINTER:
                {
                    // TODO: should pointer be supported here?
                    analysis_error();
                }
                break; default:
                {
                    analysis_error();
                }
            }

            typecheck(unit, expected_type, value->type);
            result = original_reference;
        }
        break; case VALUE_ID_CALL:
        {
            let callable_ref = analyze_value(unit, &value->call.callable, (TypeReference){}, (TypeAnalysis){});

            assert(!is_ref_valid(value->call.function_type));
            TypeReference function_type_ref = {};

            let callable = value_pointer_from_reference(unit, callable_ref);
            switch (callable->id)
            {
                break; case VALUE_ID_REFERENCED_VARIABLE:
                {
                    let callable_type_ref = callable->type;
                    let callable_type = type_pointer_from_reference(unit, callable_type_ref);
                    switch (callable->kind)
                    {
                        break; case VALUE_KIND_RIGHT:
                        {
                            assert(callable_type->id == TYPE_ID_FUNCTION);
                            function_type_ref = callable_type_ref;
                        }
                        break; case VALUE_KIND_LEFT:
                        {
                            todo();
                        }
                    }
                }
                break; default: todo();
            }

            assert(is_ref_valid(function_type_ref));
            let function_type = type_pointer_from_reference(unit, function_type_ref);
            assert(function_type->id == TYPE_ID_FUNCTION);
            value->call.function_type = function_type_ref;

            let arguments = value->call.arguments;
            let semantic_argument_count = function_type->function.semantic_argument_count;
            let is_variable_argument = function_type->function.is_variable_argument;

            if (is_variable_argument)
            {
                if (arguments.count < semantic_argument_count)
                {
                    analysis_error();
                }
            }
            else
            {
                if (arguments.count != semantic_argument_count)
                {
                    analysis_error();
                }
            }

            let argument_node_ref = arguments.first;

            for (u16 i = 0; i < semantic_argument_count; i += 1)
            {
                let semantic_argument_type = get_semantic_argument_type(&function_type->function, i);
                let argument_node = value_node_pointer_from_reference(unit, argument_node_ref);
                let call_argument = &argument_node->item;
                analyze_value(unit, call_argument, semantic_argument_type, (TypeAnalysis){});
            }

            assert(!is_ref_valid(argument_node_ref) || is_variable_argument);

            for (u16 i = semantic_argument_count; i < arguments.count; i += 1)
            {
                todo();
            }

            let semantic_return_type = get_semantic_return_type(&function_type->function);

            typecheck(unit, expected_type, semantic_return_type);
            result = original_reference;
            value->type = semantic_return_type;
        }
        break; case VALUE_ID_REFERENCED_VARIABLE:
        {
            result = original_reference;
            typecheck(unit, expected_type, value->type);
        }
        break; case VALUE_ID_UNRESOLVED_IDENTIFIER:
        {
            UNREACHABLE();
        }
        break; default:
        {
            todo();
        }
    }

    assert(is_ref_valid(result));
    assert(is_ref_valid(value_pointer_from_reference(unit, result)->type));

    return result;
}

static void analyze_statement(CompileUnit* restrict unit, Statement* restrict statement)
{
    assert(!statement->analyzed);
    let statement_id = statement->id;

    let current_function = get_current_function(unit);
    let current_function_type = get_function_type(unit, current_function);

    switch (statement_id)
    {
        break; case STATEMENT_ID_RETURN:
        {
            let return_value = statement->value;

            let semantic_return_type_ref = get_semantic_return_type(&current_function_type->function);
            let semantic_return_type = type_pointer_from_reference(unit, semantic_return_type_ref);

            switch (semantic_return_type->id)
            {
                break; case TYPE_ID_VOID:
                {
                    todo();
                }
                break; case TYPE_ID_NORETURN:
                {
                    todo();
                }
                break; default:
                {
                    if (!is_ref_valid(statement->value))
                    {
                        analysis_error();
                    }

                    analyze_value(unit, &statement->value, semantic_return_type_ref, (TypeAnalysis){});
                }
            }
        }
        break; case STATEMENT_ID_LOCAL:
        {
            let local_ref = statement->local;
            let local = local_pointer_from_reference(unit, local_ref);
            let local_type_ref = local->variable.type;

            // TODO: array inference
            if (is_ref_valid(local_type_ref))
            {
                
            }

            let expected_type = local_type_ref;

            analyze_value(unit, &local->initial_value, expected_type, (TypeAnalysis){});

            if (!is_ref_valid(expected_type))
            {
                let initial_value = value_pointer_from_reference(unit, local->initial_value);
                local_type_ref = initial_value->type;
            }

            local->variable.type = local_type_ref;
            let storage = value_pointer_from_reference(unit, local->variable.storage);
            storage->type = get_pointer_type(unit, local_type_ref);
        }
        break; case STATEMENT_ID_EXPRESSION:
        {
            analyze_value(unit, &statement->value, (TypeReference){}, (TypeAnalysis){});
            todo();
        }
        break; default:
        {
            todo();
        }
    }

    statement->analyzed = 1;
}

static void analyze_block(CompileUnit* restrict unit, BlockReference block_ref)
{
    let block = block_pointer_from_reference(unit, block_ref);
    assert(!block->analyzed);

    let statement_ref = block->first_statement;

    while (is_ref_valid(statement_ref))
    {
        let statement_pointer = statement_pointer_from_reference(unit, statement_ref);
        analyze_statement(unit, statement_pointer);
        statement_ref = statement_pointer->next;
    }

    block->analyzed = 1;
}

void analyze(CompileUnit* restrict unit, TopLevelDeclarationReference first_tld)
{
    unit->phase = COMPILE_PHASE_ANALYSIS;

    FileReference file_ref = unit->first_file;

    while (is_ref_valid(file_ref))
    {
        queue_top_level_declarations(unit, file_ref, first_tld);
        let file = file_pointer_from_reference(unit, file_ref);
        file_ref = file->next;
    }

    file_ref = unit->first_file;

    while (is_ref_valid(file_ref))
    {
        let file = file_pointer_from_reference(unit, file_ref);

        let global_ref = file->first_global;

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

                        let global_type_ref = analyze_type(unit, &global->variable.type);
                        let global_type = type_pointer_from_reference(unit, global_type_ref);
                        if (global_type->id != TYPE_ID_FUNCTION)
                        {
                            analysis_error();
                        }

                        let global_storage_type = get_pointer_type(unit, global_type_ref);
                        global_storage->type = global_storage_type;

                        unit->current_function = global_ref;

                        analyze_block(unit, global_storage->function.block);

                        unit->current_function = (GlobalReference){};
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

        file_ref = file->next;
    }
}
