#pragma once

#include <analysis.h>

#define analysis_error() todo()

STRUCT(TypeAnalysis)
{
    TypeReference indexing_type;
    bool must_be_constant;
};

LOCAL str type_to_string(CompileUnit* unit, TypeReference type_ref);

LOCAL str calling_convention_to_string(CallingConvention cc)
{
    switch (cc)
    {
        break; case CALLING_CONVENTION_C: return S("cc(c)");
        break; default: UNREACHABLE();
    }
}

LOCAL str type_content_to_string(CompileUnit* unit, TypeReference type_ref)
{
    let type = type_pointer_from_reference(unit, type_ref);
    let arena = get_default_arena(unit);

    str part_buffer[1024];
    u64 part_count = 0;

    switch (type->id)
    {
        break; case TYPE_ID_FUNCTION:
        {
            check(!is_ref_valid(type->name));

            part_buffer[part_count++] = S("fn [");
            let cc = type->function.calling_convention;
            let cc_str = calling_convention_to_string(cc);
            part_buffer[part_count++] = cc_str;
            part_buffer[part_count++] = S(" ");

            let var_args_str = type->function.is_variable_argument ? S("varags") : S("no_varargs");
            part_buffer[part_count++] = var_args_str;
            part_buffer[part_count++] = S("] (");

            let semantic_return_type = get_semantic_return_type(&type->function);

            let semantic_argument_count = type->function.semantic_argument_count;

            for (u64 i = 0; i < semantic_argument_count; i += 1)
            {
                let argument_type = get_semantic_argument_type(&type->function, i);
                part_buffer[part_count++] = type_to_string(unit, argument_type);

                part_buffer[part_count++] = S(", ");
            }

            part_buffer[part_count] = S(") -> ");
            part_count += semantic_argument_count == 0;

            part_buffer[part_count++] = type_to_string(unit, semantic_return_type);
        }
        break; case TYPE_ID_POINTER:
        {
            part_buffer[part_count++] = S("POINTER TO ");
            part_buffer[part_count++] = type_to_string(unit, type->pointer.element_type);
        }
        break; default:
        {
            check(is_ref_valid(type->name));
            part_buffer[part_count++] = string_from_reference(unit, type->name);
        }
    }

    part_buffer[part_count++] = S(", analyzed: ");
    part_buffer[part_count++] = type->analyzed ? S("YES") : S("NO");

    let result = arena_join_string(arena, (StringSlice){ .pointer = part_buffer, .length = part_count }, false);
    return result;
}

LOCAL str type_to_string(CompileUnit* unit, TypeReference type_ref)
{
    let arena = get_default_arena(unit);
    str parts[] = {
        S("Type{"),
        format_integer(arena, (FormatIntegerOptions) { .value = type_ref.v }, false),
        S(", "),
        type_content_to_string(unit, type_ref),
        S("}"),
    };

    return arena_join_string(arena, string_array_to_slice(parts), false);
}

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
                    check(is_ref_valid(file->first_global));
                    let last_global = global_pointer_from_reference(unit, file->last_global);
                    last_global->next = global_ref;
                }
                else
                {
                    check(!is_ref_valid(file->first_global));
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
    print(S("Deleting type "));
    print(format_integer(get_default_arena(unit), (FormatIntegerOptions) { .value = type_ref.v }, false));
    print(S("\n"));

    let type = type_pointer_from_reference(unit, type_ref);
    memset(type, 0, sizeof(Type));

    let first_free_type = unit->free_types;
    type->next = first_free_type;
    unit->free_types = type_ref;
}

LOCAL void recycle_type(CompileUnit* unit, TypeReference type_ref)
{
}

LOCAL TypeReference get_function_type(CompileUnit* restrict unit, TypeReference* restrict type_reference)
{
    let original_reference = *type_reference;
    let type = type_pointer_from_reference(unit, original_reference);
    check(type->id == TYPE_ID_FUNCTION);
    check(!is_ref_valid(type->name));
    check(!type->analyzed);

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

    print(S("===\nGetting function type: "));
    print(type_to_string(unit, original_reference));
    print(S("\n"));

    TypeReference result = {};
    let function_type_ref = unit->first_function_type;

    while (is_ref_valid(function_type_ref))
    {
        check(!ref_eq(function_type_ref, original_reference));

        let function_type = type_pointer_from_reference(unit, function_type_ref);
        check(function_type->id == TYPE_ID_FUNCTION);

        bool is_equal = (((calling_convention == function_type->function.calling_convention) & (is_variable_argument == function_type->function.is_variable_argument)) & ((semantic_argument_count == function_type->function.semantic_argument_count) & (has_debug_info ? ref_eq(file, function_type->function.file) : 1))) && memcmp(semantic_types, function_type->function.semantic_types, sizeof(semantic_types[0]) * (semantic_argument_count + 1)) == 0;
        if (is_equal)
        {
            result = function_type_ref;
            break;
        }

        let next = function_type->function.next;
        if (!is_ref_valid(next))
        {
            break;
        }

        function_type_ref = next;
    }

    if (is_ref_valid(result))
    {
        print(S("Found a function type already: "));
        print(type_to_string(unit, result));
        print(S("\n"));

        let result_type = type_pointer_from_reference(unit, result);
        check(result_type->analyzed);
        result_type->use_count += 1;
        check(!ref_eq(result, original_reference));
        garbage_collect_type(unit, original_reference);
    }
    else
    {
        print(S("No function type found. Reusing...\n"));

        result = original_reference;

        // No match, put this as the one reflecting the function type
        if (is_ref_valid(function_type_ref))
        {
            check(is_ref_valid(unit->first_function_type));
            let function_type = type_pointer_from_reference(unit, function_type_ref);
            function_type->function.next = result;
        }
        else
        {
            check(!is_ref_valid(unit->first_function_type));
            unit->first_function_type = result;
        }

        let semantic_return_type = get_semantic_return_type(&type->function);

        let target = unit->target;
        let resolved_calling_convention = resolve_calling_convention(target, calling_convention);

        TypeReference abi_type_buffer[1024];
        u16 abi_type_count = 0;

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

        check(is_ref_valid(abi_return_type));
        abi_type_buffer[abi_type_count] = abi_return_type;
        abi_type_count += 1;

        if (return_abi_kind == ABI_KIND_INDIRECT)
        {
            check(!return_abi->flags.sret_after_this);
            todo();
        }

        switch (resolved_calling_convention)
        {
            break; case RESOLVED_CALLING_CONVENTION_SYSTEM_V:
            {
                for (u16 i = 0; i < semantic_argument_count; i += 1)
                {
                    let is_named_argument = i < semantic_argument_count;
                    check(is_named_argument);
                    let argument_abi = get_argument_abi(&type->function, i);
                    let semantic_argument_type = get_semantic_argument_type(&type->function, i);

                    let abi = abi_system_v_classify_argument(unit, &type->function.available_registers, abi_type_buffer, (AbiSystemVClassifyArgumentOptions){
                        .type = semantic_argument_type,
                        .abi_start = abi_type_count,
                        .is_named_argument = is_named_argument,
                    });
                    *argument_abi = abi;
                    abi_type_count += abi.abi_count;
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

        let arena = unit_arena(unit, UNIT_ARENA_COMPILE_UNIT);
        let abi_types = arena_allocate(arena, TypeReference, abi_type_count);
        memcpy(abi_types, abi_type_buffer, sizeof(abi_type_buffer[0]) * abi_type_count);
        type->function.abi_types = abi_types;
        type->function.abi_argument_count = abi_type_count - 1;
        check(type->use_count == 1);
        type->analyzed = 1;
    }

    print(S("===\n"));
    return result;
}

LOCAL TypeReference get_pointer_type(CompileUnit* restrict unit, TypeReference* pointer_type_reference, TypeReference element_type_reference)
{
    check(unit->phase >= COMPILE_PHASE_ANALYSIS);

    Type* element_type = type_pointer_from_reference(unit, element_type_reference);
    check(element_type->analyzed);
    let last_pointer_type = unit->first_pointer_type;

    TypeReference result = {};

    print(S("---\nGetting pointer type..."));
    if (pointer_type_reference)
    {
        print(S(" from "));
        print(type_to_string(unit, *pointer_type_reference));
        let type = type_pointer_from_reference(unit, *pointer_type_reference);
        check(!is_ref_valid(type->name));
        check(!type->analyzed);
    }
    print(S(" of element "));
    print(type_to_string(unit, element_type_reference));
    print(S("\n"));

    while (is_ref_valid(last_pointer_type))
    {
        let lpt = type_pointer_from_reference(unit, last_pointer_type);
        check(lpt->id == TYPE_ID_POINTER);
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
        print(S("Found a pointer type already: "));
        print(type_to_string(unit, result));
        print(S("\n"));

        let result_type = type_pointer_from_reference(unit, result);
        check(result_type->use_count);
        check(result_type->analyzed);
        result_type->use_count += 1;
        if (pointer_type_reference)
        {
            let garbage_type_ref = *pointer_type_reference;
            check(!ref_eq(result, garbage_type_ref));
            let garbage_type = type_pointer_from_reference(unit, garbage_type_ref);
            let use_count = garbage_type->use_count;
            check(use_count);
            use_count -= 1;
            garbage_type->use_count = use_count;

            if (use_count)
            {
                todo();
            }
            else
            {
                garbage_collect_type(unit, garbage_type_ref);
            }

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
        result = type_reference_from_pointer(unit, pointer);

        print(S("No pointer type found. Reusing "));
        print(format_integer(get_default_arena(unit), (FormatIntegerOptions){ .value = pointer_type_reference ? pointer_type_reference->v : type_reference_from_pointer(unit, pointer).v }, false));
        print(S("...\n"));

        if (pointer_type_reference)
        {
            check(pointer->use_count == 1);
        }

        *pointer = (Type) {
            .pointer = {
                .element_type = element_type_reference,
            },
            .name = name,
            .scope = element_type->scope,
            .id = TYPE_ID_POINTER,
            .analyzed = 1,
            .use_count = 1,
        };

        if (is_ref_valid(last_pointer_type))
        {
            check(is_ref_valid(unit->first_pointer_type));
            let lpt = type_pointer_from_reference(unit, last_pointer_type);
            lpt->pointer.next = result;
        }
        else
        {
            check(!is_ref_valid(unit->first_pointer_type));
            unit->first_pointer_type = result;
        }
    }

    print(S("---\n"));

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
            break; case TYPE_ID_POINTER:
            {
                let element_type = analyze_type(unit, &type_pointer->pointer.element_type);
                result = get_pointer_type(unit, &original_reference, element_type);
            }
            break; default:
            {
                todo();
            }
        }

        check(is_ref_valid(result));
        *type_reference = result;
    }

    check(is_ref_valid(result));
    return result;
}

LOCAL u64 integer_max_value(u64 bit_count, bool is_signed)
{
    __typeof__(integer_max_value(0, 0)) result = {};
    let max_bit_count = sizeof(result) * 8;
    check(bit_count <= max_bit_count);
    result = bit_count == max_bit_count ? ~(__typeof__(integer_max_value(0, 0)))0 : ((__typeof__(integer_max_value(0, 0)))1 << (bit_count - is_signed)) - 1;
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
    check(value->id == VALUE_ID_UNRESOLVED_IDENTIFIER);
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
                    check(storage->id == VALUE_ID_FUNCTION);

                    let argument_ref = storage->function.arguments;
                    while (is_ref_valid(argument_ref))
                    {
                        let argument = argument_pointer_from_reference(unit, argument_ref);
                        if (ref_eq(identifier_ref, argument->variable.name))
                        {
                            variable = &argument->variable;
                            break;
                        }

                        argument_ref = argument->next;
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
    check(is_ref_valid(expected));
    check(is_ref_valid(expected));

    if (!ref_eq(expected, source))
    {
        let e = type_pointer_from_reference(unit, expected);
        let s = type_pointer_from_reference(unit, source);
        let e_name = string_from_reference(unit, e->name);
        let s_name = string_from_reference(unit, s->name);
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
        break; case VALUE_ID_UNRESOLVED_IDENTIFIER:
        {
            // TODO: this might bring some problems
            result = false;
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
        break; case VALUE_ID_UNRESOLVED_IDENTIFIER:
        {
            // TODO: change?
            result = false;
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
        analyze_value(unit, left_ref, (TypeReference){}, (TypeAnalysis){ .must_be_constant = options.must_be_constant });
        analyze_value(unit, right_ref, (TypeReference){}, (TypeAnalysis){ .must_be_constant = options.must_be_constant });
    }
    else if (left_receives_type & !right_receives_type)
    {
        let _right_ref = analyze_value(unit, right_ref, (TypeReference){}, (TypeAnalysis){ .must_be_constant = options.must_be_constant });
        let _right = value_pointer_from_reference(unit, _right_ref);
        analyze_value(unit, left_ref, _right->type, (TypeAnalysis){ .must_be_constant = options.must_be_constant });
    }
    else if (!left_receives_type & right_receives_type)
    {
        let _left_ref = analyze_value(unit, left_ref, (TypeReference){}, (TypeAnalysis){ .must_be_constant = options.must_be_constant });
        let _left = value_pointer_from_reference(unit, _left_ref);
        analyze_value(unit, right_ref, _left->type, (TypeAnalysis){ .must_be_constant = options.must_be_constant });
    }
    else if (!!left_receives_type & !!right_receives_type)
    {
        check(is_ref_valid(expected_type));

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

    check(ref_eq(*left_ref, original_left_ref));
    check(ref_eq(*right_ref, original_right_ref));

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

    check(!value->analyzed);
    check(!is_ref_valid(value->type));

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
                check(ref_eq(original_reference, search.value));
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
        break;
        case VALUE_ID_BINARY_ADD:
        case VALUE_ID_BINARY_SUB:
        case VALUE_ID_BINARY_COMPARE_EQUAL:
        case VALUE_ID_BINARY_BITWISE_AND:
        case VALUE_ID_BINARY_BITWISE_OR:
        case VALUE_ID_BINARY_BITWISE_XOR:
        case VALUE_ID_BINARY_DIVIDE:
        case VALUE_ID_BINARY_MULTIPLY:
        case VALUE_ID_BINARY_REMAINDER:
        case VALUE_ID_BINARY_BITWISE_SHIFT_LEFT:
        case VALUE_ID_BINARY_BITWISE_SHIFT_RIGHT:
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
                value_type_ref = get_u1(unit);

                if (left_type->id == TYPE_ID_VECTOR)
                {
                    todo();
                }
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
                break; case VALUE_ID_BINARY_SUB:
                {
                    switch (value_type->id)
                    {
                        break; case TYPE_ID_INTEGER:
                        {
                            value->id = VALUE_ID_BINARY_SUB_INTEGER;
                        }
                        break; default: UNREACHABLE();
                    }
                }
                break; case VALUE_ID_BINARY_COMPARE_EQUAL:
                {
                    switch (value_type->id)
                    {
                        break; case TYPE_ID_INTEGER:
                        {
                            value->id = VALUE_ID_BINARY_COMPARE_EQUAL_INTEGER;
                        }
                        break; default: UNREACHABLE();
                    }
                }
                break;
                case VALUE_ID_BINARY_BITWISE_AND:
                case VALUE_ID_BINARY_BITWISE_OR:
                case VALUE_ID_BINARY_BITWISE_XOR:
                {
                    if (value_type->id != TYPE_ID_INTEGER)
                    {
                        analysis_error();
                    }
                }
                break;
                case VALUE_ID_BINARY_BITWISE_SHIFT_LEFT:
                case VALUE_ID_BINARY_BITWISE_SHIFT_RIGHT:
                {
                    if (value_type->id != TYPE_ID_INTEGER)
                    {
                        analysis_error();
                    }

                    check(value_type->id == TYPE_ID_INTEGER);
                    value->id = value_type->integer.is_signed ? VALUE_ID_BINARY_BITWISE_SHIFT_RIGHT_LOGICAL : VALUE_ID_BINARY_BITWISE_SHIFT_RIGHT_ARITHMETIC;
                }
                break; case VALUE_ID_BINARY_DIVIDE:
                {
                    switch (value_type->id)
                    {
                        break; case TYPE_ID_INTEGER:
                        {
                            value->id = value_type->integer.is_signed ? VALUE_ID_BINARY_DIVIDE_INTEGER_SIGNED : VALUE_ID_BINARY_DIVIDE_INTEGER_UNSIGNED;
                        }
                        break; default: UNREACHABLE();
                    }
                }
                break; case VALUE_ID_BINARY_REMAINDER:
                {
                    switch (value_type->id)
                    {
                        break; case TYPE_ID_INTEGER:
                        {
                            value->id = value_type->integer.is_signed ? VALUE_ID_BINARY_REMAINDER_INTEGER_SIGNED : VALUE_ID_BINARY_REMAINDER_INTEGER_UNSIGNED;
                        }
                        break; default: UNREACHABLE();
                    }
                }
                break; case VALUE_ID_BINARY_MULTIPLY:
                {
                    switch (value_type->id)
                    {
                        break; case TYPE_ID_INTEGER:
                        {
                            value->id = VALUE_ID_BINARY_MULTIPLY_INTEGER;
                        }
                        break; default: UNREACHABLE();
                    }
                }
                break; default: UNREACHABLE();
            }

            result = original_reference;
        }
        // Unary-generic case
        break;
        case VALUE_ID_UNARY_MINUS:
        case VALUE_ID_UNARY_BOOLEAN_NOT:
        case VALUE_ID_UNARY_ADDRESS_OF:
        {
            let unary_expected_type = original_is_boolean ? expected_type : (TypeReference){};
            let unary_value_ref = analyze_value(unit, &value->unary, expected_type, (TypeAnalysis){ .must_be_constant = analysis.must_be_constant });
            check(ref_eq(unary_value_ref, value->unary));
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
                break; case VALUE_ID_UNARY_BOOLEAN_NOT: {}
                break; case VALUE_ID_UNARY_ADDRESS_OF: {}
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
                    analysis_error();
                }
            }

            typecheck(unit, expected_type, value->type);
            result = original_reference;
        }
        break; case VALUE_ID_CALL:
        {
            let callable_ref = analyze_value(unit, &value->call.callable, (TypeReference){}, (TypeAnalysis){});

            check(!is_ref_valid(value->call.function_type));
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
                            check(callable_type->id == TYPE_ID_FUNCTION);
                            function_type_ref = callable_type_ref;
                        }
                        break; case VALUE_KIND_LEFT:
                        {
                            check(callable_type->id == TYPE_ID_POINTER);

                            let element_type_ref = callable_type->pointer.element_type;
                            let element_type = type_pointer_from_reference(unit, element_type_ref);
                            check(element_type->id == TYPE_ID_FUNCTION);
                            function_type_ref = element_type_ref;
                        }
                    }
                }
                break; default: todo();
            }

            check(is_ref_valid(function_type_ref));
            let function_type = type_pointer_from_reference(unit, function_type_ref);
            check(function_type->id == TYPE_ID_FUNCTION);
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

                argument_node_ref = argument_node->next;
            }

            check(!is_ref_valid(argument_node_ref) || is_variable_argument);

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
        break; case VALUE_ID_INTRINSIC_TRAP:
        {
            result = original_reference;
            value->type = get_noreturn_type(unit);
        }
        break; case VALUE_ID_INTRINSIC_EXTEND:
        {
            if (!is_ref_valid(expected_type))
            {
                analysis_error();
            }

            let extended_value_ref = &value->unary;
            analyze_value(unit, extended_value_ref, (TypeReference){}, (TypeAnalysis){ .must_be_constant = analysis.must_be_constant });
            let extended_value = value_pointer_from_reference(unit, *extended_value_ref);
            let extended_value_type_ref = extended_value->type;
            check(is_ref_valid(extended_value_type_ref));
            let source_type = type_pointer_from_reference(unit, extended_value_type_ref);

            let source_bit_size = get_bit_size(unit, source_type);
            let et = type_pointer_from_reference(unit, expected_type);
            let expected_bit_size = get_bit_size(unit, et);

            if (source_bit_size > expected_bit_size)
            {
                analysis_error();
            }
            else if ((source_bit_size == expected_bit_size) & (type_is_signed(unit, source_type) == type_is_signed(unit, et)))
            {
                analysis_error();
            }

            value->type = expected_type;

            result = original_reference;
        }
        break; case VALUE_ID_INTRINSIC_INTEGER_MAX:
        {
            let unary_type_ref = analyze_type(unit, &value->unary_type);
            let unary_type = type_pointer_from_reference(unit, unary_type_ref);

            TypeReference value_type_ref = {};

            if (is_ref_valid(expected_type))
            {
                value_type_ref = expected_type;
            }
            else
            {
                value_type_ref = unary_type_ref;
            }

            let value_type = type_pointer_from_reference(unit, value_type_ref);

            if (value_type->id != TYPE_ID_INTEGER)
            {
                analysis_error();
            }

            let max_value = integer_max_value(value_type->integer.bit_count, value_type->integer.is_signed);
            if (unary_type->id != TYPE_ID_INTEGER)
            {
                analysis_error();
            }
            let result_value = integer_max_value(unary_type->integer.bit_count, unary_type->integer.is_signed);

            if (result_value > max_value)
            {
                analysis_error();
            }

            typecheck(unit, expected_type, value_type_ref);

            value->integer = result_value;
            value->id = VALUE_ID_CONSTANT_INTEGER;
            value->type = value_type_ref;

            result = original_reference;
        }
        break; case VALUE_ID_INTRINSIC_TRUNCATE:
        {
            if (!is_ref_valid(expected_type))
            {
                analysis_error();
            }

            let unary_value_ref = analyze_value(unit, &value->unary, (TypeReference){}, (TypeAnalysis){ .must_be_constant = analysis.must_be_constant });
            let unary_value = value_pointer_from_reference(unit, unary_value_ref);

            let et = type_pointer_from_reference(unit, expected_type);

            let unary_value_type_ref = unary_value->type;
            let unary_value_type = type_pointer_from_reference(unit, unary_value_type_ref);

            let expected_bit_size = get_bit_size(unit, et);
            let source_bit_size = get_bit_size(unit, unary_value_type);

            if (expected_bit_size >= source_bit_size)
            {
                analysis_error();
            }

            value->type = expected_type;

            result = original_reference;
        }
        break; case VALUE_ID_POINTER_DEREFERENCE:
        {
            let pointer_value_ref = analyze_value(unit, &value->unary, (TypeReference){}, (TypeAnalysis){ .must_be_constant = analysis.must_be_constant });
            let pointer_value = value_pointer_from_reference(unit, pointer_value_ref);

            if (value->kind == VALUE_KIND_LEFT)
            {
                analysis_error();
            }

            let pointer_type_ref = pointer_value->type;
            let pointer_type = type_pointer_from_reference(unit, pointer_type_ref);
            check(pointer_type->id == TYPE_ID_POINTER);
            let dereference_type_ref = pointer_type->pointer.element_type;

            typecheck(unit, expected_type, dereference_type_ref);

            value->type = dereference_type_ref;

            result = original_reference;
        }
        break; default:
        {
            todo();
        }
    }

    check(is_ref_valid(result));
    check(is_ref_valid(value_pointer_from_reference(unit, result)->type));

    return result;
}

LOCAL void analyze_block(CompileUnit* restrict unit, BlockReference block_ref);

LOCAL void analyze_statement(CompileUnit* restrict unit, Statement* restrict statement)
{
    check(!statement->analyzed);
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
            check(!is_ref_valid(storage->type));
            storage->type = get_pointer_type(unit, 0, local_type_ref);
        }
        break; case STATEMENT_ID_EXPRESSION:
        {
            analyze_value(unit, &statement->value, (TypeReference){}, (TypeAnalysis){});
        }
        break; case STATEMENT_ID_IF:
        {
            let condition = &statement->branch.condition;

            analyze_value(unit, condition, (TypeReference){}, (TypeAnalysis){});

            let taken_branch = statement_pointer_from_reference(unit, statement->branch.taken_branch);
            analyze_statement(unit, taken_branch);

            let else_branch_ref = statement->branch.else_branch;
            if (is_ref_valid(else_branch_ref))
            {
                let else_branch = statement_pointer_from_reference(unit, else_branch_ref);
                analyze_statement(unit, else_branch);
            }
        }
        break; case STATEMENT_ID_BLOCK:
        {
            let block_ref = statement->block;
            analyze_block(unit, block_ref);
        }
        break; case STATEMENT_ID_ASSIGNMENT:
        {
            let left = &statement->assignment[0];
            let right = &statement->assignment[1];

            analyze_value(unit, left, (TypeReference){}, (TypeAnalysis){});
            let l = value_pointer_from_reference(unit, *left);
            let left_type = type_pointer_from_reference(unit, l->type);
            if (left_type->id != TYPE_ID_POINTER)
            {
                analysis_error();
            }

            let element_type_ref = left_type->pointer.element_type;
            let is_storing_to_vector_element = 0; // left->id == VALUE_ID_ARRAY_EXPRESSION;

            if (is_storing_to_vector_element)
            {
                todo();
            }

            analyze_value(unit, right, element_type_ref, (TypeAnalysis){});
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
    check(!block->analyzed);

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
            check(!is_ref_valid(unit->current_function));

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
                        check(global_type->analyzed);
                        if (global_type->id != TYPE_ID_FUNCTION)
                        {
                            analysis_error();
                        }

                        check(!is_ref_valid(global_storage->type));
                        let global_storage_type_ref = get_pointer_type(unit, 0, global_type_ref);
                        let global_storage_type = type_pointer_from_reference(unit, global_storage_type_ref);
                        check(global_storage_type->analyzed);
                        check(global_storage_type->id == TYPE_ID_POINTER);
                        let global_value_type_ref = global_storage_type->pointer.element_type;
                        check(ref_eq(global_value_type_ref, global_type_ref));
                        let global_value_type = type_pointer_from_reference(unit, global_value_type_ref);
                        check(global_value_type == global_type);
                        check(global_type->id == TYPE_ID_FUNCTION);
                        global_storage->type = global_storage_type_ref;


                        let semantic_argument_count = global_type->function.semantic_argument_count;
                        let argument_ref = global_storage->function.arguments;

                        for (u16 i = 0; i < semantic_argument_count; i += 1)
                        {
                            check(global_type->id == TYPE_ID_FUNCTION);
                            let semantic_argument_type = get_semantic_argument_type(&global_type->function, i);
                            let argument = argument_pointer_from_reference(unit, argument_ref);
                            argument->variable.type = semantic_argument_type;

                            argument_ref = argument->next;
                        }

                        check(!is_ref_valid(argument_ref));

                        print(S("'"));
                        print(string_from_reference(unit, global->variable.name));
                        print(S("': "));
                        print(format_integer(get_default_arena(unit), (FormatIntegerOptions){ .value = global_type_ref.v }, false));
                        print(S(" -> "));
                        print(format_integer(get_default_arena(unit), (FormatIntegerOptions){ .value = global_storage_type_ref.v }, false));
                        print(S("\n"));

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
