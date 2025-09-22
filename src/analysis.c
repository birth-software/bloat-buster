#pragma once

#include <analysis.h>

#define analysis_error() todo()

STRUCT(TypeAnalysis)
{
    TypeReference indexing_type;
    bool must_be_constant;
};

LOCAL ValueReference analyze_value(CompileUnit* restrict unit, ValueReference* restrict value_reference, TypeReference expected_type, TypeAnalysis analysis);

LOCAL void queue_top_level_declarations(CompileUnit* restrict unit, FileReference file_reference, TopLevelDeclarationReference first_tld)
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

LOCAL TypeReference analyze_type(CompileUnit* restrict unit, TypeReference* restrict type_reference);

LOCAL void garbage_collect_type(CompileUnit* unit, TypeReference type_ref)
{
    let type = type_pointer_from_reference(unit, type_ref);
    memset(type, 0, sizeof(Type));

    let first_free_type = unit->free_types;
    type->next = first_free_type;
    unit->free_types = type_ref;
}

LOCAL TypeReference get_function_type(CompileUnit* restrict unit, TypeReference* restrict type_reference)
{
    let original_reference = *type_reference;
    let type = type_pointer_from_reference(unit, original_reference);
    assert(type->id == TYPE_ID_FUNCTION);
    assert(!is_ref_valid(type->name));
    assert(!type->analyzed);

    let semantic_types = type->function.semantic_types;

    for (u16 i = 0; i < type->function.semantic_argument_count + 1; i += 1)
    {
        let pointer = &semantic_types[i];
        analyze_type(unit, &semantic_types[i]);
    }

    let calling_convention = type->function.calling_convention;
    let is_variable_argument = type->function.is_variable_argument;
    let semantic_argument_count = type->function.semantic_argument_count;
    let file = type->function.file;
    let has_debug_info = unit->has_debug_info;

    TypeReference result = {};
    let function_type_ref = unit->first_function_type;

    while (is_ref_valid(function_type_ref))
    {
        assert(!ref_eq(function_type_ref, original_reference));

        let function_type = type_pointer_from_reference(unit, function_type_ref);
        assert(function_type->id == TYPE_ID_FUNCTION);

        bool is_equal = (((calling_convention == function_type->function.calling_convention) & (is_variable_argument == function_type->function.is_variable_argument)) & ((semantic_argument_count == function_type->function.semantic_argument_count) & (has_debug_info ? ref_eq(file, function_type->function.file) : 1))) && memcmp(semantic_types, function_type->function.semantic_types, sizeof(semantic_types[0]) * (semantic_argument_count + 1)) == 0;
        if (is_equal)
        {
            result = function_type_ref;
            break;
        }

        function_type_ref = function_type->function.next;
    }

    if (is_ref_valid(result))
    {
        assert(!ref_eq(result, original_reference));
        garbage_collect_type(unit, original_reference);
    }
    else
    {
        result = original_reference;

        // No match, put this as the one reflecting the function type
        if (is_ref_valid(function_type_ref))
        {
            assert(is_ref_valid(unit->first_function_type));
            let function_type = type_pointer_from_reference(unit, function_type_ref);
            function_type->function.next = result;
        }
        else
        {
            assert(!is_ref_valid(unit->first_function_type));
            unit->first_function_type = result;
        }

        let semantic_return_type = get_semantic_return_type(&type->function);

        let calling_convention = type->function.calling_convention;
        let target = unit->target;
        let resolved_calling_convention = resolve_calling_convention(target, calling_convention);

        TypeReference abi_type_buffer[1024];
        u16 abi_type_count = 0;

        let semantic_argument_count = type->function.semantic_argument_count;
        let return_abi = get_return_abi(&type->function);

        switch (resolved_calling_convention)
        {
            break; case RESOLVED_CALLING_CONVENTION_SYSTEM_V:
            {
                bool is_register_call = false;

                type->function.available_registers = (AbiRegisterCount) {
                    .x86_64 = {
                        .gpr = is_register_call ? 11 : 6,
                        .sse = is_register_call ? 16 : 8,
                    },
                };

                *return_abi = abi_system_v_classify_return_type(unit, semantic_return_type);
            }
            break; case RESOLVED_CALLING_CONVENTION_WIN64:
            {
                bool is_vector_call = false;
                bool is_register_call = false;

                u32 free_sse_registers;
                if (is_vector_call)
                {
                    free_sse_registers = 4;
                }
                else if (is_register_call)
                {
                    free_sse_registers = 16;
                }
                else
                {
                    free_sse_registers = 0;
                }

                type->function.available_registers = (AbiRegisterCount) {
                    .x86_64 = {
                        .gpr = 0,
                        .sse = free_sse_registers,
                    },
                };

                let return_abi = get_return_abi(&type->function);
                *return_abi = win64_classify_type(unit, semantic_return_type, (Win64ClassifyOptions){
                    .free_sse = &type->function.available_registers.x86_64.sse,
                    .is_return_type = true,
                    .is_vector_call = is_vector_call,
                    .is_register_call = is_register_call,
                });
            }
            break; case RESOLVED_CALLING_CONVENTION_AARCH64:
            {
                let aarch64_abi = get_aarch64_abi_kind(target.os);
                *return_abi = aarch64_classify_return_type(unit, semantic_return_type, is_variable_argument, aarch64_abi);
            }
            break; default:
            {
                UNREACHABLE();
            }
        }

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

        assert(is_ref_valid(abi_return_type));
        abi_type_buffer[abi_type_count] = abi_return_type;
        abi_type_count += 1;

        if (return_abi_kind == ABI_KIND_INDIRECT)
        {
            assert(!return_abi->flags.sret_after_this);
            todo();
        }

        switch (resolved_calling_convention)
        {
            break; case RESOLVED_CALLING_CONVENTION_SYSTEM_V:
            {
                for (u16 i = 0; i < semantic_argument_count; i += 1)
                {
                    todo();
                }
            }
            break; case RESOLVED_CALLING_CONVENTION_WIN64:
            {
                bool is_vector_call = false;
                bool is_register_call = false;

                let free_sse_registers = type->function.available_registers.x86_64.sse;

                if (is_vector_call)
                {
                    free_sse_registers = 6;
                }
                else if (is_register_call)
                {
                    free_sse_registers = 16;
                }

                type->function.available_registers.x86_64.sse = free_sse_registers;

                for (u16 i = 0; i < semantic_argument_count; i += 1)
                {
                    todo();
                }

                if (is_vector_call)
                {
                    todo();
                }
            }
            break; case RESOLVED_CALLING_CONVENTION_AARCH64:
            {
                for (u16 i = 0; i < semantic_argument_count; i += 1)
                {
                    todo();
                }
            }
            break; default:
            {
                UNREACHABLE();
            }
        }

        let abi_types = arena_allocate(unit_arena(unit, UNIT_ARENA_COMPILE_UNIT), TypeReference, abi_type_count);
        memcpy(abi_types, abi_type_buffer, sizeof(abi_type_buffer[0]) * abi_type_count);
        type->function.abi_types = abi_types;
        type->function.abi_argument_count = abi_type_count - 1;

        type->analyzed = 1;
    }

    return result;
}

LOCAL TypeReference analyze_type(CompileUnit* restrict unit, TypeReference* restrict type_reference)
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
                result = get_function_type(unit, &original_reference);
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

LOCAL u64 integer_max_value(u64 bit_count, bool is_signed)
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

LOCAL IdentifierSearch reference_identifier(CompileUnit* restrict unit, ValueReference* value_ref, TypeReference expected_type, TypeAnalysis analysis)
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

LOCAL void check_types(CompileUnit* restrict unit, TypeReference expected, TypeReference source)
{
    assert(is_ref_valid(expected));
    assert(is_ref_valid(expected));

    if (!ref_eq(expected, source))
    {
        todo();
    }
}

LOCAL void typecheck(CompileUnit* restrict unit, TypeReference expected, TypeReference source)
{
    if (is_ref_valid(expected))
    {
        check_types(unit, expected, source);
    }
}

LOCAL bool value_is_boolean(ValueId id)
{
    switch (id)
    {
        break;
        case VALUE_ID_BINARY_COMPARE_EQUAL:
        case VALUE_ID_BINARY_COMPARE_NOT_EQUAL:
        case VALUE_ID_BINARY_COMPARE_LESS:
        case VALUE_ID_BINARY_COMPARE_LESS_EQUAL:
        case VALUE_ID_BINARY_COMPARE_GREATER:
        case VALUE_ID_BINARY_COMPARE_GREATER_EQUAL:
        {
            return 1;
        }
        break; default: return 0;
    }
}

LOCAL bool value_is_constant(CompileUnit* restrict unit, Value* restrict value)
{
    let id = value->id;
    bool result = 0;
    switch (id)
    {
        break; case VALUE_ID_CONSTANT_INTEGER:
        {
            result = 1;
        }
        break; case VALUE_ID_UNARY_MINUS:
        {
            let unary_value = value_pointer_from_reference(unit, value->unary);
            result = value_is_constant(unit, unary_value);
        }
        break; default: todo();
    }

    return result;
}

LOCAL bool value_receives_type(CompileUnit* restrict unit, Value* restrict value)
{
    let id = value->id;
    bool result = 0;

    switch (id)
    {
        break; case VALUE_ID_CONSTANT_INTEGER:
        {
            result = 1;
        }
        break; case VALUE_ID_UNARY_MINUS:
        {
            let unary_value = value_pointer_from_reference(unit, value->unary);
            result = value_receives_type(unit, unary_value);
        }
        break; default: todo();
    }

    return result;
}

STRUCT(AnalyzeBinaryOptions)
{
    TypeReference expected_type;
    bool is_boolean;
    bool must_be_constant;
    bool is_sub;
};

LOCAL void analyze_binary(CompileUnit* restrict unit, ValueReference* restrict left_ref, ValueReference* restrict right_ref, AnalyzeBinaryOptions options)
{
    let original_left_ref = *left_ref;
    let original_right_ref = *right_ref;
    let original_left = value_pointer_from_reference(unit, original_left_ref);
    let original_right = value_pointer_from_reference(unit, original_right_ref);
    let left_constant = value_is_constant(unit, original_left);
    let right_constant = value_is_constant(unit, original_right);
    let left_receives_type = value_receives_type(unit, original_left);
    let right_receives_type = value_receives_type(unit, original_right);

    let expected_type = options.expected_type;

    if (!is_ref_valid(expected_type) & (left_receives_type & right_receives_type))
    {
        if (original_left->id == original_right->id)
        {
            todo();
        }
        else
        {
            analysis_error();
        }
    }

    if (!left_receives_type & !right_receives_type)
    {
        todo();
    }
    else if (left_receives_type & !right_receives_type)
    {
        todo();
    }
    else if (!left_receives_type & right_receives_type)
    {
        todo();
    }
    else if (!!left_receives_type & !!right_receives_type)
    {
        assert(is_ref_valid(expected_type));

        if (options.is_boolean)
        {
            analysis_error();
        }

        analyze_value(unit, left_ref, expected_type, (TypeAnalysis){ .must_be_constant = options.must_be_constant });
        analyze_value(unit, right_ref, expected_type, (TypeAnalysis){ .must_be_constant = options.must_be_constant });
    }
    else
    {
        UNREACHABLE();
    }

    assert(ref_eq(*left_ref, original_left_ref));
    assert(ref_eq(*right_ref, original_right_ref));

    if (is_ref_valid(expected_type))
    {
        let et = type_pointer_from_reference(unit, expected_type);
        let left_type_ref = original_left->type;
        let right_type_ref = original_right->type;
        let left_type = type_pointer_from_reference(unit, left_type_ref);
        let right_type = type_pointer_from_reference(unit, right_type_ref);

        if (((et->id == TYPE_ID_INTEGER) & options.is_sub) & ((left_type->id == TYPE_ID_POINTER) & (right_type->id == TYPE_ID_POINTER)))
        {
            todo();
        }
        else if (!options.is_boolean)
        {
            typecheck(unit, expected_type, left_type_ref);
            typecheck(unit, expected_type, right_type_ref);
        }
    }
}

LOCAL ValueReference analyze_value(CompileUnit* restrict unit, ValueReference* restrict value_reference, TypeReference expected_type, TypeAnalysis analysis)
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

    let original_id = value->id;
    let original_is_boolean = value_is_boolean(original_id);

    switch (original_id)
    {
        break; case VALUE_ID_BINARY_ADD:
        {
            let left_ref = &value->binary[0];
            let right_ref = &value->binary[1];
            let is_sub = original_id == VALUE_ID_BINARY_SUB;
            let is_boolean = original_is_boolean;
            let options = (AnalyzeBinaryOptions) {
                .expected_type = expected_type,
                .is_boolean = is_boolean,
                .must_be_constant = analysis.must_be_constant,
                .is_sub = is_sub,
            };
            analyze_binary(unit, left_ref, right_ref, options);
            let left = value_pointer_from_reference(unit, *left_ref);
            let right = value_pointer_from_reference(unit, *right_ref);
            let left_type_ref = left->type;
            let right_type_ref = right->type;
            let left_type = type_pointer_from_reference(unit, left->type);
            let right_type = type_pointer_from_reference(unit, right->type);

            TypeReference value_type_ref;
            if (is_sub & ((left_type->id == TYPE_ID_POINTER) & (right_type->id == TYPE_ID_POINTER)))
            {
                todo();
            }
            else if (is_boolean)
            {
                todo();
            }
            else
            {
                value_type_ref = left_type_ref;
            }

            let value_type = type_pointer_from_reference(unit, value_type_ref);
            value->type = value_type_ref;

            switch (original_id)
            {
                break; case VALUE_ID_BINARY_ADD:
                {
                    switch (value_type->id)
                    {
                        break; case TYPE_ID_INTEGER:
                        {
                            value->id = VALUE_ID_BINARY_ADD_INTEGER;
                        }
                        break; default: UNREACHABLE();
                    }
                }
                break; default: UNREACHABLE();
            }

            result = original_reference;
        }
        // Unary-generic case
        break; case VALUE_ID_UNARY_MINUS:
        {
            let unary_expected_type = original_is_boolean ? expected_type : (TypeReference){};
            let unary_value_ref = analyze_value(unit, &value->unary, expected_type, (TypeAnalysis){ .must_be_constant = analysis.must_be_constant });
            assert(ref_eq(unary_value_ref, value->unary));
            let unary_value = value_pointer_from_reference(unit, unary_value_ref);
            let value_type_ref = original_is_boolean ? get_u1(unit) : unary_value->type;
            typecheck(unit, expected_type, value_type_ref);
            let value_type = type_pointer_from_reference(unit, value_type_ref);
            value->type = value_type_ref;

            switch (original_id)
            {
                break; case VALUE_ID_UNARY_MINUS:
                {
                    switch (value_type->id)
                    {
                        break; case TYPE_ID_INTEGER:
                        {
                            value->id = VALUE_ID_UNARY_MINUS_INTEGER;
                        }
                        break; default: UNREACHABLE();
                    }
                }
                break; default: UNREACHABLE();
            }

            result = original_reference;
        }
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
                    os_file_write(os_get_stdout(), format_integer(get_default_arena(unit), (FormatIntegerOptions) { .value = type->id }, true));
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
                            assert(callable_type->id == TYPE_ID_POINTER);

                            let element_type_ref = callable_type->pointer.element_type;
                            let element_type = type_pointer_from_reference(unit, element_type_ref);
                            assert(element_type->id == TYPE_ID_FUNCTION);
                            function_type_ref = element_type_ref;
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

LOCAL TypeReference get_pointer_type(CompileUnit* restrict unit, TypeReference* pointer_type_reference, TypeReference element_type_reference)
{
    assert(unit->phase >= COMPILE_PHASE_ANALYSIS);

    Type* element_type = type_pointer_from_reference(unit, element_type_reference);
    assert(element_type->analyzed);
    let last_pointer_type = unit->first_pointer_type;

    TypeReference result = {};

    while (is_ref_valid(last_pointer_type))
    {
        let lpt = type_pointer_from_reference(unit, last_pointer_type);
        assert(lpt->id == TYPE_ID_POINTER);
        if (ref_eq(lpt->pointer.element_type, element_type_reference))
        {
            result = last_pointer_type;
            break;
        }

        let next = lpt->pointer.next;
        if (!is_ref_valid(next))
        {
            break;
        }

        last_pointer_type = next;
    }

    if (is_ref_valid(result))
    {
        if (pointer_type_reference)
        {
            assert(!ref_eq(result, *pointer_type_reference));
            garbage_collect_type(unit, *pointer_type_reference);
            *pointer_type_reference = result;
        }
    }
    else
    {
        StringReference name = {};
        if (is_ref_valid(element_type->name))
        {
            str name_parts[] = {
                S("&"),
                string_from_reference(unit, element_type->name),
            };
            name = allocate_and_join_string(unit, string_array_to_slice(name_parts));
        }

        let pointer = pointer_type_reference ? type_pointer_from_reference(unit, *pointer_type_reference) : new_type(unit);
        *pointer = (Type) {
            .pointer = {
                .element_type = element_type_reference,
            },
            .name = name,
            .scope = element_type->scope,
            .id = TYPE_ID_POINTER,
            .analyzed = 1,
        };

        result = type_reference_from_pointer(unit, pointer);

        if (is_ref_valid(last_pointer_type))
        {
            assert(is_ref_valid(unit->first_pointer_type));
            let lpt = type_pointer_from_reference(unit, last_pointer_type);
            lpt->pointer.next = result;
        }
        else
        {
            assert(!is_ref_valid(unit->first_pointer_type));
            unit->first_pointer_type = result;
        }
    }

    return result;
}

LOCAL void analyze_statement(CompileUnit* restrict unit, Statement* restrict statement)
{
    assert(!statement->analyzed);
    let statement_id = statement->id;

    let current_function = get_current_function(unit);
    let current_function_type = get_function_type_from_storage(unit, current_function);

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
            assert(!is_ref_valid(storage->type));
            storage->type = get_pointer_type(unit, 0, local_type_ref);
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

LOCAL void analyze_block(CompileUnit* restrict unit, BlockReference block_ref)
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

PUB_IMPL void analyze(CompileUnit* restrict unit)
{
    unit->phase = COMPILE_PHASE_ANALYSIS;

    FileReference file_ref = unit->first_file;

    TopLevelDeclarationReference first_tld = {};
    if (is_ref_valid(file_ref))
    {
        let file = file_pointer_from_reference(unit, file_ref);
        first_tld = file->first_tld;
    }

    while (is_ref_valid(file_ref))
    {
        let file = file_pointer_from_reference(unit, file_ref);
        queue_top_level_declarations(unit, file_ref, file->first_tld);
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
                        assert(global_type->analyzed);
                        if (global_type->id != TYPE_ID_FUNCTION)
                        {
                            analysis_error();
                        }

                        assert(!is_ref_valid(global_storage->type));
                        let global_storage_type = get_pointer_type(unit, 0, global_type_ref);
                        assert(type_pointer_from_reference(unit, global_storage_type)->analyzed);
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

#if BB_INCLUDE_TESTS
PUB_IMPL bool analysis_tests(TestArguments* restrict arguments)
{
    return 1;
}
#endif
