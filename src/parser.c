#pragma once

#include <parser.h>

#define parser_error() todo();

STRUCT(Parser)
{
    str content;
    Token* restrict pointer;
    u32 offset;
    u32 line_byte_offset;
    u32 line_number_offset;
    FileReference file;
};

typedef enum Precedence : u8
{
    PRECEDENCE_NONE,
    PRECEDENCE_ASSIGNMENT,
    PRECEDENCE_BOOLEAN_OR,
    PRECEDENCE_BOOLEAN_AND,
    PRECEDENCE_COMPARISON,
    PRECEDENCE_BITWISE,
    PRECEDENCE_SHIFT,
    PRECEDENCE_ADD_LIKE,
    PRECEDENCE_DIV_LIKE,
    PRECEDENCE_PREFIX,
    PRECEDENCE_AGGREGATE_INITIALIZATION,
    PRECEDENCE_POSTFIX,
} Precedence;

LOCAL Precedence get_token_precedence(CompileUnit* unit, TokenId id)
{
    switch (id)
    {
        break;
        case TOKEN_ID_SEMICOLON:
        case TOKEN_ID_RIGHT_PARENTHESIS:
        {
            return PRECEDENCE_NONE;
        }
        break;
        case TOKEN_ID_ASSIGN:
        {
            return PRECEDENCE_ASSIGNMENT;
        }
        break;
        case TOKEN_ID_COMPARE_EQUAL:
        case TOKEN_ID_COMPARE_NOT_EQUAL:
        case TOKEN_ID_COMPARE_LESS:
        case TOKEN_ID_COMPARE_LESS_EQUAL:
        case TOKEN_ID_COMPARE_GREATER:
        case TOKEN_ID_COMPARE_GREATER_EQUAL:
        {
            return PRECEDENCE_COMPARISON;
        }
        break;
        case TOKEN_ID_AMPERSAND:
        case TOKEN_ID_BAR:
        case TOKEN_ID_CARET:
        {
            return PRECEDENCE_BITWISE;
        }
        break;
        case TOKEN_ID_SHIFT_LEFT:
        case TOKEN_ID_SHIFT_RIGHT:
        {
            return PRECEDENCE_SHIFT;
        }
        break;
        case TOKEN_ID_PLUS:
        case TOKEN_ID_DASH:
        {
            return PRECEDENCE_ADD_LIKE;
        }
        break;
        case TOKEN_ID_ASTERISK:
        case TOKEN_ID_FORWARD_SLASH:
        case TOKEN_ID_PERCENTAGE:
        {
            return PRECEDENCE_DIV_LIKE;
        }
        break;
        case TOKEN_ID_LEFT_PARENTHESIS:
        case TOKEN_ID_POINTER_DEREFERENCE:
        {
            return PRECEDENCE_POSTFIX;
        }
        break; default:
        {
            todo();
        }
    }
}

STRUCT(ValueParsing)
{
    Token* restrict token;
    ValueReference left;
    Precedence precedence;
    ValueKind kind;
    bool is_statement;
};

LOCAL SourceLocation get_source_location(Parser* restrict parser, Token* restrict token)
{
    return (SourceLocation) {
        .line_number_offset = parser->line_number_offset,
        .line_byte_offset = parser->line_byte_offset,
        .column_offset = token->offset,
    };
}

LOCAL Token* get_token_internal(Parser* restrict parser, u32 index)
{
    Token* token = &parser->pointer[index];
    return token;
}

LOCAL Token* get_current_token(Parser* restrict parser)
{
    return get_token_internal(parser, parser->offset);
}

LOCAL Token* restrict get_token(Parser* restrict parser)
{
    let t = get_current_token(parser);
    if (unlikely(t->id == TOKEN_ID_LINE_BYTE_OFFSET))
    {
        let line_byte_offset = t;
        let line_number_offset = t + 1;
        check(line_number_offset->id == TOKEN_ID_LINE_NUMBER_OFFSET);
        parser->line_byte_offset = line_byte_offset->offset;
        parser->line_number_offset = line_number_offset->offset;
        parser->offset += 2;
        let nt = get_current_token(parser);
        check(nt->id != TOKEN_ID_LINE_BYTE_OFFSET);
        check(nt->id != TOKEN_ID_LINE_NUMBER_OFFSET);
    }

    let nt = get_current_token(parser);
    check(nt->id != TOKEN_ID_LINE_BYTE_OFFSET);
    check(nt->id != TOKEN_ID_LINE_NUMBER_OFFSET);
    return nt;
}

LOCAL void rewind_token(Parser* restrict parser)
{
    let previous_token = get_token_internal(parser, parser->offset - 1);
    let is_line_token = (previous_token->id == TOKEN_ID_LINE_NUMBER_OFFSET) | (previous_token->id == TOKEN_ID_LINE_BYTE_OFFSET);
    let previous_offset = parser->offset;
    parser->offset -= 1 + (is_line_token * 2);
    if (is_line_token)
    {
        let previous_previous_token = previous_token - 1;
        check(previous_previous_token->id == TOKEN_ID_LINE_BYTE_OFFSET);
    }
}

LOCAL Token* restrict peek_token(Parser* restrict parser)
{
    let t = get_token(parser);
    return t;
}

LOCAL Token* restrict consume_token(Parser* restrict parser)
{
    let token = get_token(parser);
    parser->offset += 1;
    return token;
}

LOCAL Token* restrict expect_token(Parser* restrict parser, TokenId id)
{
    Token* result = 0;
    let token = get_token(parser);

    let token_match = token->id == id;
    parser->offset += token_match;

    if (likely(token_match))
    {
        result = token;
    }

    return result;
}

LOCAL Token* restrict expect_token_of_many(Parser* restrict parser, TokenId* ids, u32 id_count)
{
    Token* result = 0;
    let token = get_token(parser);
    TokenId tid = token->id;

    u32 match = 0;

    for (u32 i = 0; i < id_count; i += 1)
    {
        let id = ids[i];
        match |= id == tid;
    }

    if (likely(match))
    {
        result = token;
    }

    return result;
}

STRUCT(IdentifierParsing)
{
    StringReference string;
    u32 line_offset;
};

LOCAL bool identifier_parsing_valid(IdentifierParsing p)
{
    return p.string.v != 0;
}

LOCAL str file_content(CompileUnit* unit, FileReference file_index)
{
    let file = file_pointer_from_reference(unit, file_index);
    unused(file);
    parser_error();
}

LOCAL char* restrict pointer_from_token_start(Parser* restrict parser, Token* token)
{
    u32 start = token->offset;
    char* restrict pointer = parser->content.pointer + parser->line_byte_offset + start;
    return pointer;
}

LOCAL IdentifierParsing end_identifier(CompileUnit* restrict unit, Parser* restrict parser, Token* restrict start)
{
    check(start);
    check(start->id == TOKEN_ID_IDENTIFIER_START);

    IdentifierParsing result = {};

    let end = expect_token(parser, TOKEN_ID_IDENTIFIER_END);

    if (end)
    {
        let pointer = pointer_from_token_start(parser, start);
        u32 start_index = start->offset;
        u32 end_index = end->offset;
        check(end_index > start_index);
        str s = { pointer, end_index - start_index };
        result = (IdentifierParsing) {
            .string = allocate_string(unit, s),
            .line_offset = start_index,
        };
    }

    return result;
}

LOCAL IdentifierParsing expect_identifier(CompileUnit* restrict unit, Parser* restrict parser)
{
    IdentifierParsing result = {};

    let identifier_start = expect_token(parser, TOKEN_ID_IDENTIFIER_START);

    if (identifier_start)
    {
        result = end_identifier(unit, parser, identifier_start);
    }

    return result;
}

STRUCT(ParseInteger)
{
    u64 value;
    u64 digit_count;
};

LOCAL ParseInteger end_integer(CompileUnit* restrict unit, Parser* restrict parser, Token* restrict start)
{
    check(start);
    check(start->id == TOKEN_ID_INTEGER_START_HEXADECIMAL_PREFIXED || start->id == TOKEN_ID_INTEGER_START_DECIMAL_PREFIXED || start->id == TOKEN_ID_INTEGER_START_DECIMAL_INFERRED || start->id == TOKEN_ID_INTEGER_START_OCTAL_PREFIXED || start->id == TOKEN_ID_INTEGER_START_BINARY_PREFIXED);

    ParseInteger result = {};

    let end = expect_token(parser, TOKEN_ID_INTEGER_END);

    if (end)
    {
        TokenId start_id = start->id;
        bool is_prefixed = start_id != TOKEN_ID_INTEGER_START_DECIMAL_INFERRED;
        let original_start_pointer = pointer_from_token_start(parser, start);
        let start_pointer = original_start_pointer + ((u64)is_prefixed << 1);

        IntegerParsing p;

        switch (start->id)
        {
            break; case TOKEN_ID_INTEGER_START_HEXADECIMAL_PREFIXED:
            {
                p = parse_hexadecimal_scalar(start_pointer);
            }
            break; case TOKEN_ID_INTEGER_START_DECIMAL_PREFIXED:
            {
                todo();
            }
            break; case TOKEN_ID_INTEGER_START_OCTAL_PREFIXED:
            {
                todo();
            }
            break; case TOKEN_ID_INTEGER_START_BINARY_PREFIXED:
            {
                todo();
            }
            break; case TOKEN_ID_INTEGER_START_DECIMAL_INFERRED:
            {
                p = parse_decimal_scalar(start_pointer);
            }
            break; default:
            {
                UNREACHABLE();
            }
        }

        result.value = p.value;
        result.digit_count = p.i;
    }

    return result;
}

LOCAL ParseInteger expect_integer(CompileUnit* restrict unit, Parser* restrict parser)
{
    ParseInteger result = {};
    TokenId expected_ids[] = {
        TOKEN_ID_INTEGER_START_HEXADECIMAL_PREFIXED,
        TOKEN_ID_INTEGER_START_DECIMAL_PREFIXED,
        TOKEN_ID_INTEGER_START_OCTAL_PREFIXED,
        TOKEN_ID_INTEGER_START_BINARY_PREFIXED,
        TOKEN_ID_INTEGER_START_DECIMAL_INFERRED,
    };
    let start = expect_token_of_many(parser, expected_ids, array_length(expected_ids));

    if (start)
    {
        result = end_integer(unit, parser, start);
    }

    return result;
}

LOCAL ValueReference parse_value(CompileUnit* restrict unit, Parser* restrict parser, ScopeReference scope, ValueParsing parsing);
LOCAL ValueReference parse_precedence(CompileUnit* restrict unit, Parser* restrict parser, ScopeReference scope, ValueParsing parsing);
LOCAL BlockReference parse_block(CompileUnit* restrict unit, Parser* restrict parser, ScopeReference parent_scope, Token* restrict left_brace);

LOCAL TypeReference parse_type(CompileUnit* restrict unit, Parser* restrict parser, ScopeReference scope, ArgumentReference* argument_list)
{
    let token = consume_token(parser);

    let default_arena = get_default_arena(unit);

    switch (token->id)
    {
        break; case TOKEN_ID_KEYWORD_TYPE_FN:
        {
            CallingConvention calling_convention = CALLING_CONVENTION_C;
            bool is_variable_argument = false;

            if (expect_token(parser, TOKEN_ID_LEFT_BRACKET))
            {
                while (!expect_token(parser, TOKEN_ID_RIGHT_BRACKET))
                {
                    let identifier = expect_identifier(unit, parser);
                    let identifier_string = string_from_reference(unit, identifier.string);

                    if (str_equal(identifier_string, S("cc")))
                    {
                        if (!expect_token(parser, TOKEN_ID_LEFT_PARENTHESIS))
                        {
                            parser_error();
                        }

                        let cc_identifier = expect_identifier(unit, parser);
                        let cc_identifier_string = string_from_reference(unit, cc_identifier.string);

                        if (str_equal(cc_identifier_string, S("c")))
                        {
                            calling_convention = CALLING_CONVENTION_C;
                        }
                        else
                        {
                            parser_error();
                        }

                        if (!expect_token(parser, TOKEN_ID_RIGHT_PARENTHESIS))
                        {
                            parser_error();
                        }
                    }
                    else
                    {
                        parser_error();
                    }

                    if (!expect_token(parser, TOKEN_ID_COMMA))
                    {
                        if (!expect_token(parser, TOKEN_ID_RIGHT_BRACKET))
                        {
                            parser_error();
                        }

                        break;
                    }
                }
            }

            if (!expect_token(parser, TOKEN_ID_LEFT_PARENTHESIS))
            {
                parser_error();
            }

            ArgumentReference first_argument = {};
            ArgumentReference previous_argument = {};
            u64 argument_count = 0;

            while (!expect_token(parser, TOKEN_ID_RIGHT_PARENTHESIS))
            {
                if (expect_token(parser, TOKEN_ID_TRIPLE_DOT))
                {
                    is_variable_argument = 1;

                    if (!expect_token(parser, TOKEN_ID_RIGHT_PARENTHESIS))
                    {
                        parser_error();
                    }

                    break;
                }

                let argument = arena_allocate(default_arena, Argument, 1);
                let argument_ref = argument_reference_from_pointer(unit, argument);

                let identifier_token = consume_token(parser);
                let argument_location = get_source_location(parser, identifier_token);
                IdentifierParsing identifier_parsing = {};

                if (identifier_token->id == TOKEN_ID_IDENTIFIER_START)
                {
                    identifier_parsing = end_identifier(unit, parser, identifier_token);
                }
                else if (identifier_token->id != TOKEN_ID_KEYWORD_STATEMENT_UNDERSCORE)
                {
                    parser_error();
                }

                if (!expect_token(parser, TOKEN_ID_COLON))
                {
                    parser_error();
                }

                let argument_storage = new_value(unit);
                *argument_storage = (Value) {
                    .id = VALUE_ID_ARGUMENT,
                };

                let argument_type = parse_type(unit, parser, scope, 0);
                *argument = (Argument) {
                    .variable = {
                        .name = identifier_parsing.string,
                        .storage = value_reference_from_pointer(unit, argument_storage),
                        .type = argument_type,
                        .scope = scope,
                        .location = argument_location,
                    },
                    .index = argument_count + 1,
                };

                if (is_ref_valid(previous_argument))
                {
                    let prev_arg = argument_pointer_from_reference(unit, previous_argument);
                    prev_arg->next = argument_ref;
                }
                else
                {
                    first_argument = argument_ref;
                }

                previous_argument = argument_ref;

                argument_count += 1;

                if (!expect_token(parser, TOKEN_ID_COMMA))
                {
                    if (!expect_token(parser, TOKEN_ID_RIGHT_PARENTHESIS))
                    {
                        parser_error();
                    }
                    break;
                }
            }

            let return_type = parse_type(unit, parser, scope, 0);
            let allocation_size = align_forward(sizeof(TypeReference) * (argument_count + 1), alignof(AbiInformation)) + (sizeof(AbiInformation) * (argument_count + 1));
            static_assert(alignof(TypeReference) == alignof(AbiInformation));
            let semantic_type_allocation = arena_allocate_bytes(get_default_arena(unit), allocation_size, MAX(alignof(TypeReference), alignof(AbiInformation)));
            let semantic_types = (TypeReference*)semantic_type_allocation;
            semantic_types[0] = return_type;

            if (argument_count)
            {
                let it = first_argument;
                *argument_list = it;

                for (u64 i = 0; i < argument_count; i += 1)
                {
                    let argument = argument_pointer_from_reference(unit, it);
                    semantic_types[i + 1] = argument->variable.type;
                    it = argument->next;
                }
            }

            let function_type = new_type(unit);
            *function_type = (Type) {
                .function = {
                    .semantic_types = semantic_types,
                    .abi_types = 0,
                    .available_registers = {},
                    .file = parser->file,
                    .semantic_argument_count = argument_count,
                    .abi_argument_count = 0,
                    .calling_convention = calling_convention,
                    .is_variable_argument = is_variable_argument,
                },
                .name = {},
                .scope = scope,
                .id = TYPE_ID_FUNCTION,
                .analyzed = 0,
                .use_count = 1,
            };

            let reference = type_reference_from_pointer(unit, function_type);
            return reference;
        }
        break; case TOKEN_ID_IDENTIFIER_START:
        {
            // IdentifierParsing identifier_parsing = end_identifier(unit, parser, token);
            // let identifier = string_from_reference(unit, identifier_parsing.string);
            todo();
        }
        break; case TOKEN_ID_KEYWORD_TYPE_VOID:
        {
            return get_void_type(unit);
        }
        break; case TOKEN_ID_KEYWORD_TYPE_INTEGER:
        {
            let token_start = pointer_from_token_start(parser, token);
            check(*token_start == 's' || *token_start == 'u');
            let parsing_result = parse_decimal_scalar(token_start + 1);
            check(parsing_result.i);
            let bit_count = parsing_result.value;
            let is_signed = *token_start == 's';

            let integer_type = get_integer_type(unit, bit_count, is_signed);
            return integer_type;
        }
        break; case TOKEN_ID_AMPERSAND:
        {
            let element_type = parse_type(unit, parser, scope, 0);
            let type = new_type(unit);
            *type = (Type) {
                .pointer = {
                    .element_type = element_type,
                },
                .name = {},
                .scope = scope,
                .id = TYPE_ID_POINTER,
                .use_count = 1,
            };
            return type_reference_from_pointer(unit, type);
        }
        break; case TOKEN_ID_LEFT_BRACKET:
        {
            ValueReference element_count = {};
            if (get_token(parser)->id != TOKEN_ID_KEYWORD_STATEMENT_UNDERSCORE)
            {
                element_count = parse_value(unit, parser, scope, (ValueParsing){});
            }
            else
            {
                consume_token(parser);
            }

            if (!expect_token(parser, TOKEN_ID_RIGHT_BRACKET))
            {
                parser_error();
            }

            let element_type = parse_type(unit, parser, scope, 0);
            let type = new_type(unit);
            *type = (Type) {
                .unresolved_array = {
                    .element_type = element_type,
                    .element_count = element_count,
                },
                .name = {},
                .scope = scope,
                .id = TYPE_ID_UNRESOLVED_ARRAY,
                .use_count = 1,
            };
            return type_reference_from_pointer(unit, type);
        }
        break; default:
        {
            todo();
        }
    }
}

LOCAL Global* global_from_parser(CompileUnit* restrict unit)
{
    let global = arena_allocate(get_default_arena(unit), Global, 1);
    *global = (Global) {};
    return global;
}

LOCAL ValueList parse_value_list(CompileUnit* restrict unit, Parser* restrict parser, ScopeReference scope, TokenId end_token)
{
    ValueNodeReference previous = {};
    ValueNodeReference first = {};
    u32 count = 0;

    let default_arena = get_default_arena(unit);

    if (!expect_token(parser, end_token))
    {
        let first_node = arena_allocate(default_arena, ValueNode, 1);
        *first_node = (ValueNode) {
            .item = parse_value(unit, parser, scope, (ValueParsing){}),
        };
        count += 1;

        first = value_node_reference_from_pointer(unit, first_node);
        previous = first;

        while (!expect_token(parser, end_token))
        {
            let node = arena_allocate(default_arena, ValueNode, 1);
            *node = (ValueNode) {
                .item = parse_value(unit, parser, scope, (ValueParsing){}),
            };
            count += 1;

            let node_reference = value_node_reference_from_pointer(unit, node);
            let previous_pointer = value_node_pointer_from_reference(unit, previous);
            previous_pointer->next = node_reference;

            previous = node_reference;

            todo();
        }
    }

    return (ValueList) {
        .first = first,
        .count = count,
    };
}

LOCAL void parse_argument_start(CompileUnit* restrict unit, Parser* restrict parser)
{
    if (!expect_token(parser, TOKEN_ID_LEFT_PARENTHESIS))
    {
        parser_error();
    }
}

LOCAL void parse_argument_end(CompileUnit* restrict unit, Parser* restrict parser)
{
    if (!expect_token(parser, TOKEN_ID_RIGHT_PARENTHESIS))
    {
        parser_error();
    }
}

LOCAL void parse_zero_arguments(CompileUnit* restrict unit, Parser* restrict parser)
{
    parse_argument_start(unit, parser);
    parse_argument_end(unit, parser);
}

LOCAL ValueReference parse_one_argument(CompileUnit* restrict unit, Parser* restrict parser, ScopeReference scope, ValueParsing parsing)
{
    parse_argument_start(unit, parser);
    let value = parse_value(unit, parser, scope, parsing);
    parse_argument_end(unit, parser);
    return value;
}

LOCAL TypeReference parse_argument_type(CompileUnit* restrict unit, Parser* restrict parser, ScopeReference scope)
{
    parse_argument_start(unit, parser);
    let type = parse_type(unit, parser, scope, 0);
    parse_argument_end(unit, parser);
    return type;
}

LOCAL ValueReference parse_left(CompileUnit* restrict unit, Parser* restrict parser, ScopeReference scope, ValueParsing parsing)
{
    let first_token = consume_token(parser);
    ValueReference result = {};

    TokenId first_id = first_token->id;

    switch (first_id)
    {
        break;
        case TOKEN_ID_INTEGER_START_HEXADECIMAL_PREFIXED:
        case TOKEN_ID_INTEGER_START_DECIMAL_PREFIXED:
        case TOKEN_ID_INTEGER_START_OCTAL_PREFIXED:
        case TOKEN_ID_INTEGER_START_BINARY_PREFIXED:
        case TOKEN_ID_INTEGER_START_DECIMAL_INFERRED:
        {
            let integer_parsing = end_integer(unit, parser, first_token);
            if (integer_parsing.digit_count == 0)
            {
                parser_error();
            }
            let value = new_value(unit);
            *value = (Value) {
                .integer = integer_parsing.value,
                .type = 0,
                .id = VALUE_ID_CONSTANT_INTEGER,
            };
            result = value_reference_from_pointer(unit, value);
        }
        break;
        case TOKEN_ID_EXCLAMATION_DOWN:
        case TOKEN_ID_DASH:
        case TOKEN_ID_AMPERSAND:
        case TOKEN_ID_TILDE:
        {
            check(!is_ref_valid(parsing.left));

            ValueId id;

            switch (first_id)
            {
                break; case TOKEN_ID_EXCLAMATION_DOWN: id = VALUE_ID_UNARY_BOOLEAN_NOT;
                break; case TOKEN_ID_DASH: id = VALUE_ID_UNARY_MINUS;
                break; case TOKEN_ID_AMPERSAND: id = VALUE_ID_UNARY_ADDRESS_OF;
                break; case TOKEN_ID_TILDE: id = VALUE_ID_UNARY_BITWISE_NOT;
                break; default: UNREACHABLE();
            }

            let value = new_value(unit);

            parsing.precedence = PRECEDENCE_PREFIX;
            parsing.token = 0;
            parsing.kind = id == VALUE_ID_UNARY_ADDRESS_OF ? VALUE_KIND_LEFT : parsing.kind;

            let unary_value = parse_precedence(unit, parser, scope, parsing);

            *value = (Value) {
                .unary = unary_value,
                .id = id,
            };

            result = value_reference_from_pointer(unit, value);
        }
        break; case TOKEN_ID_IDENTIFIER_START:
        {
            let identifier_p = end_identifier(unit, parser, first_token);
            let identifier = identifier_p.string;

            let value = new_value(unit);

            *value = (Value) {
                .unresolved_identifier = {
                    .string = identifier,
                    .scope = scope,
                },
                .type = {},
                .next = {},
                .kind = parsing.kind,
                .id = VALUE_ID_UNRESOLVED_IDENTIFIER,
            };

            result = value_reference_from_pointer(unit, value);
        }
        break; case TOKEN_ID_AT:
        {
            let identifier = expect_identifier(unit, parser);

            if (!is_ref_valid(identifier.string))
            {
                parser_error();
            }

            let name = string_from_reference(unit, identifier.string);

            ValueId intrinsics_ids[] = {
                VALUE_ID_INTRINSIC_TRAP,
                VALUE_ID_INTRINSIC_EXTEND,
                VALUE_ID_INTRINSIC_INTEGER_MAX,
                VALUE_ID_INTRINSIC_TRUNCATE,
            };

            str intrinsic_names[] = {
                S("trap"),
                S("extend"),
                S("integer_max"),
                S("truncate"),
            };

            static_assert(array_length(intrinsic_names) == array_length(intrinsics_ids));

            u64 i;
            for (i = 0; i < array_length(intrinsic_names); i += 1)
            {
                str intrinsic_name = intrinsic_names[i];
                if (str_equal(name, intrinsic_name))
                {
                    break;
                }
            }

            let value = new_value(unit);

            if (i == array_length(intrinsic_names))
            {
                if (!expect_token(parser, TOKEN_ID_LEFT_PARENTHESIS))
                {
                    parser_error();
                }

                let arguments = parse_value_list(unit, parser, scope, TOKEN_ID_RIGHT_PARENTHESIS);
                todo();
            }
            else
            {
                let intrinsic_id = intrinsics_ids[i];

                switch (intrinsic_id)
                {
                    break; case VALUE_ID_INTRINSIC_TRAP:
                    {
                        parse_zero_arguments(unit, parser);

                        *value = (Value) {
                            .id = intrinsic_id,
                        };
                    }
                    break;
                    case VALUE_ID_INTRINSIC_EXTEND:
                    case VALUE_ID_INTRINSIC_TRUNCATE:
                    {
                        let argument = parse_one_argument(unit, parser, scope, (ValueParsing){});

                        *value = (Value) {
                            .unary = argument,
                            .id = intrinsic_id,
                        };
                    }
                    break; case VALUE_ID_INTRINSIC_INTEGER_MAX:
                    {
                        let type = parse_argument_type(unit, parser, scope);

                        *value = (Value) {
                            .unary_type = type,
                            .id = intrinsic_id,
                        };
                    }
                    break; default: UNREACHABLE();
                }
            }

            result = value_reference_from_pointer(unit, value);
        }
        break; case TOKEN_ID_LEFT_BRACKET:
        {
            todo();
        }
        break; default:
        {
            todo();
        }
    }

    check(is_ref_valid(result));
    return result;
}

LOCAL ValueReference parse_right_internal(CompileUnit* restrict unit, Parser* restrict parser, ScopeReference scope, ValueParsing parsing)
{
    let left = parsing.left;
    check(is_ref_valid(left));

    let right_token = parsing.token;

    TokenId right_token_id = right_token->id;

    ValueReference result = {};

    switch (right_token_id)
    {
        break; case TOKEN_ID_LEFT_PARENTHESIS:
        {
            let l = value_pointer_from_reference(unit, left);
            l->kind = VALUE_KIND_LEFT;
            let arguments = parse_value_list(unit, parser, scope, TOKEN_ID_RIGHT_PARENTHESIS);
            let left_node = value_pointer_from_reference(unit, left);

            let value = new_value(unit);

            if (value_id_is_intrinsic(left_node->id))
            {
                todo();
            }
            else
            {
                *value = (Value) {
                    .call = {
                        .callable = left,
                        .arguments = arguments,
                        .function_type = {},
                    },
                    .id = VALUE_ID_CALL,
                };
            }

            result = value_reference_from_pointer(unit, value);
        }
        break;
        case TOKEN_ID_PLUS:
        case TOKEN_ID_DASH:
        case TOKEN_ID_ASTERISK:
        case TOKEN_ID_FORWARD_SLASH:
        case TOKEN_ID_PERCENTAGE:
        case TOKEN_ID_AMPERSAND:
        case TOKEN_ID_BAR:
        case TOKEN_ID_CARET:
        case TOKEN_ID_SHIFT_LEFT:
        case TOKEN_ID_SHIFT_RIGHT:
        case TOKEN_ID_COMPARE_EQUAL:
        case TOKEN_ID_COMPARE_NOT_EQUAL:
        case TOKEN_ID_COMPARE_LESS:
        case TOKEN_ID_COMPARE_LESS_EQUAL:
        case TOKEN_ID_COMPARE_GREATER:
        case TOKEN_ID_COMPARE_GREATER_EQUAL:
        {
            let precedence = get_token_precedence(unit, right_token_id);
            check(precedence != PRECEDENCE_ASSIGNMENT);

            ValueId id;

            switch (right_token_id)
            {
                break; case TOKEN_ID_PLUS: id = VALUE_ID_BINARY_ADD;
                break; case TOKEN_ID_DASH: id = VALUE_ID_BINARY_SUB;
                break; case TOKEN_ID_ASTERISK: id = VALUE_ID_BINARY_MULTIPLY;
                break; case TOKEN_ID_FORWARD_SLASH: id = VALUE_ID_BINARY_DIVIDE;
                break; case TOKEN_ID_PERCENTAGE: id = VALUE_ID_BINARY_REMAINDER;
                break; case TOKEN_ID_AMPERSAND: id = VALUE_ID_BINARY_BITWISE_AND;
                break; case TOKEN_ID_BAR: id = VALUE_ID_BINARY_BITWISE_OR;
                break; case TOKEN_ID_CARET: id = VALUE_ID_BINARY_BITWISE_XOR;
                break; case TOKEN_ID_SHIFT_LEFT: id = VALUE_ID_BINARY_BITWISE_SHIFT_LEFT;
                break; case TOKEN_ID_SHIFT_RIGHT: id = VALUE_ID_BINARY_BITWISE_SHIFT_RIGHT;
                break; case TOKEN_ID_COMPARE_EQUAL: id = VALUE_ID_BINARY_COMPARE_EQUAL;
                break; case TOKEN_ID_COMPARE_NOT_EQUAL: id = VALUE_ID_BINARY_COMPARE_NOT_EQUAL;
                break; case TOKEN_ID_COMPARE_LESS: id = VALUE_ID_BINARY_COMPARE_LESS;
                break; case TOKEN_ID_COMPARE_LESS_EQUAL: id = VALUE_ID_BINARY_COMPARE_LESS_EQUAL;
                break; case TOKEN_ID_COMPARE_GREATER: id = VALUE_ID_BINARY_COMPARE_GREATER;
                break; case TOKEN_ID_COMPARE_GREATER_EQUAL: id = VALUE_ID_BINARY_COMPARE_GREATER_EQUAL;
                break; default: UNREACHABLE();
            }

            let right_parsing = parsing;
            right_parsing.precedence = precedence + 1;
            right_parsing.token = 0;
            right_parsing.left = (ValueReference){};

            let right = parse_precedence(unit, parser, scope, right_parsing);

            let value = new_value(unit);
            *value = (Value) {
                .binary = { left, right },
                .id = id,
            };

            result = value_reference_from_pointer(unit, value);
        }
        break; case TOKEN_ID_POINTER_DEREFERENCE:
        {
            let value = new_value(unit);
            *value = (Value) {
                .unary = left,
                .id = VALUE_ID_POINTER_DEREFERENCE,
            };

            result = value_reference_from_pointer(unit, value);
        }
        break; default: todo();
    }

    check(is_ref_valid(result));

    return result;
}

LOCAL ValueReference parse_right(CompileUnit* restrict unit, Parser* restrict parser, ScopeReference scope, ValueParsing parsing)
{
    ValueReference result = parsing.left;
    check(is_ref_valid(result));
    Precedence precedence = parsing.precedence;

    while (1)
    {
        let loop_token = peek_token(parser);
        let loop_token_precedence = get_token_precedence(unit, loop_token->id);

        if (loop_token_precedence == PRECEDENCE_ASSIGNMENT)
        {
            loop_token_precedence = parsing.is_statement ? loop_token_precedence : PRECEDENCE_NONE;
        }

        if (precedence > loop_token_precedence)
        {
            break;
        }

        let t = consume_token(parser);
        check(loop_token == t);

        let left = result;

        let right_parsing = parsing;
        right_parsing.token = loop_token;
        right_parsing.precedence = PRECEDENCE_NONE;
        right_parsing.left = left;

        let right = parse_right_internal(unit, parser, scope, right_parsing);
        result = right;
    }

    check(is_ref_valid(result));
    return result;
}

LOCAL ValueReference parse_precedence(CompileUnit* restrict unit, Parser* restrict parser, ScopeReference scope, ValueParsing parsing)
{
    check(!parsing.token);
    let left = parse_left(unit, parser, scope, parsing);
    parsing.left = left;
    let result = parse_right(unit, parser, scope, parsing);
    return result;
}

LOCAL ValueReference parse_value(CompileUnit* restrict unit, Parser* restrict parser, ScopeReference scope, ValueParsing parsing)
{
    check(parsing.precedence == PRECEDENCE_NONE);
    check(!is_ref_valid(parsing.left));
    parsing.precedence = PRECEDENCE_ASSIGNMENT;
    let value = parse_precedence(unit, parser, scope, parsing);
    return value;
}

LOCAL StatementReference parse_statement(CompileUnit* restrict unit, Parser* restrict parser, ScopeReference scope)
{
    bool require_semicolon = 1;
    let first_token = consume_token(parser);
    let statement = arena_allocate(get_default_arena(unit), Statement, 1);
    *statement = (Statement)
    {
        .location = get_source_location(parser, first_token),
    };

    TokenId first_id = first_token->id;

    switch (first_id)
    {
        break; case TOKEN_ID_KEYWORD_STATEMENT_RETURN:
        {
            ValueReference return_value = {};

            if (peek_token(parser)->id != TOKEN_ID_SEMICOLON)
            {
                return_value = parse_value(unit, parser, scope, (ValueParsing){});
            }

            statement->value = return_value;
            statement->id = STATEMENT_ID_RETURN;
        }
        break; case TOKEN_ID_KEYWORD_STATEMENT_IF: case TOKEN_ID_KEYWORD_STATEMENT_WHEN:
        {
            require_semicolon = 0;

            let is_runtime = first_id == TOKEN_ID_KEYWORD_STATEMENT_IF;

            if (!expect_token(parser, TOKEN_ID_LEFT_PARENTHESIS))
            {
                parser_error();
            }

            let condition = parse_value(unit, parser, scope, (ValueParsing){});

            if (!expect_token(parser, TOKEN_ID_RIGHT_PARENTHESIS))
            {
                parser_error();
            }

            let taken_branch = parse_statement(unit, parser, scope);
            if (!statement_is_block_like(statement_pointer_from_reference(unit, taken_branch)->id))
            {
                parser_error();
            }

            StatementReference else_branch = {};
            if (expect_token(parser, TOKEN_ID_KEYWORD_STATEMENT_ELSE))
            {
                else_branch = parse_statement(unit, parser, scope);
                if (!statement_is_block_like(statement_pointer_from_reference(unit, else_branch)->id))
                {
                    parser_error();
                }
            }

            statement->branch = (Branch) {
                .condition = condition,
                .taken_branch = taken_branch,
                .else_branch = else_branch,
            };
            statement->id = is_runtime ? STATEMENT_ID_IF : STATEMENT_ID_WHEN;
        }
        break;
        case TOKEN_ID_IDENTIFIER_START:
        case TOKEN_ID_AT:
        {
            StatementId id;

            bool is_local_declaration = false;
            IdentifierParsing i = {};

            if (first_id == TOKEN_ID_IDENTIFIER_START)
            {
                i = end_identifier(unit, parser, first_token);

                is_local_declaration = !!expect_token(parser, TOKEN_ID_COLON);
            }

            if (is_local_declaration)
            {
                id = STATEMENT_ID_LOCAL;

                TypeReference local_type = {};

                if (get_token(parser)->id != TOKEN_ID_ASSIGN)
                {
                    local_type = parse_type(unit, parser, scope, 0);
                }

                if (!expect_token(parser, TOKEN_ID_ASSIGN))
                {
                    parser_error();
                }

                let initial_value = parse_value(unit, parser, scope, (ValueParsing){});

                let storage = new_value(unit);
                *storage = (Value){
                    .id = VALUE_ID_LOCAL,
                };

                let local = arena_allocate(get_default_arena(unit), Local, 1);
                *local = (Local) {
                    .variable = {
                        .name = i.string,
                        .storage = value_reference_from_pointer(unit, storage),
                        .type = local_type,
                        .scope = scope,
                        .location = statement->location,
                    },
                    .initial_value = initial_value,
                };

                let local_ref = local_reference_from_pointer(unit, local);

                statement->local = local_ref;

                let scope_p = scope_pointer_from_reference(unit, scope);
                check(scope_p->id == SCOPE_ID_BLOCK);
                let block = block_pointer_from_reference(unit, scope_p->block);

                if (is_ref_valid(block->last_local))
                {
                    check(is_ref_valid(block->first_local));
                    let last_local = local_pointer_from_reference(unit, block->last_local);
                    last_local->next = local_ref;
                }
                else
                {
                    check(!is_ref_valid(block->first_local));
                    block->first_local = local_ref;
                }

                block->last_local = local_ref;
            }
            else
            {
                rewind_token(parser);
                if (first_id == TOKEN_ID_IDENTIFIER_START)
                {
                    rewind_token(parser);
                }
                let value = parse_value(unit, parser, scope, (ValueParsing){ .kind = VALUE_KIND_LEFT });

                let next_token = peek_token(parser);

                bool is_assign_token = false;

                switch (next_token->id)
                {
                    break;
                    case TOKEN_ID_SEMICOLON:
                    {
                        id = STATEMENT_ID_EXPRESSION;
                    }
                    break; 
                    case TOKEN_ID_ASSIGN:
                    {
                        is_assign_token = true;
                        id = STATEMENT_ID_ASSIGNMENT;
                        next_token = consume_token(parser);
                    }
                    break; default: UNREACHABLE();
                }

                if (id == STATEMENT_ID_EXPRESSION)
                {
                    statement->value = value;
                }
                else if (is_assign_token)
                {
                    let left = value;
                    let right = parse_value(unit, parser, scope, (ValueParsing){});

                    if (next_token->id != TOKEN_ID_ASSIGN)
                    {
                        todo();
                    }

                    statement->assignment[0] = left;
                    statement->assignment[1] = right;
                }
                else
                {
                    todo();
                }
            }

            statement->id = id;
        }
        break; case TOKEN_ID_LEFT_BRACE:
        {
            require_semicolon = 0;
            let block = parse_block(unit, parser, scope, first_token);
            statement->block = block;
            statement->id = STATEMENT_ID_BLOCK;
        }
        break; default:
        {
            todo();
        }
    }

    if (require_semicolon)
    {
        if (!expect_token(parser, TOKEN_ID_SEMICOLON))
        {
            parser_error();
        }
    }

    return statement_reference_from_pointer(unit, statement);
}

LOCAL BlockReference parse_block(CompileUnit* restrict unit, Parser* restrict parser, ScopeReference parent_scope, Token* restrict left_brace)
{
    if (!left_brace)
    {
        parser_error();
    }

    check(left_brace->id == TOKEN_ID_LEFT_BRACE);

    let scope = new_scope(unit);
    Block* restrict block = arena_allocate(get_default_arena(unit), Block, 1);
    let scope_ref = scope_reference_from_pointer(unit, scope);
    let block_ref = block_reference_from_pointer(unit, block);

    *scope = (Scope){
        .parent = parent_scope,
        .location = get_source_location(parser, left_brace),
        .id = SCOPE_ID_BLOCK,
        .block = block_ref,
    };

    *block = (Block) {
        .scope = scope_ref,
    };

    StatementReference current_statement = {};

    while (!expect_token(parser, TOKEN_ID_RIGHT_BRACE))
    {
        let statement_reference = parse_statement(unit, parser, scope_ref);
        let statement_pointer = statement_pointer_from_reference(unit, statement_reference);
        check(!is_ref_valid(statement_pointer->next));
        
        if (!is_ref_valid(block->first_statement))
        {
            block->first_statement = statement_reference;
        }

        if (is_ref_valid(current_statement))
        {
            let current_statement_pointer = statement_pointer_from_reference(unit, current_statement);
            current_statement_pointer->next = statement_reference;
        }

        current_statement = statement_reference;
    }

    return block_ref;
}

PUB_IMPL void parse(CompileUnit* restrict unit, File* file_pointer, TokenList tl)
{
    unit->phase = COMPILE_PHASE_PARSER;

    Parser p = {
        .content = file_pointer->content,
        .pointer = tl.pointer,
        .file = file_reference_from_pointer(unit, file_pointer),
    };
    Parser* restrict parser = &p;

    let scope = file_pointer->scope;

    TopLevelDeclarationReference previous_tld = {};
    TopLevelDeclarationReference first_tld = {};

    Token* global_token;
    while ((global_token = consume_token(parser))->id != TOKEN_ID_EOF)
    {
        let top_level_declaration = arena_allocate(get_default_arena(unit), TopLevelDeclaration, 1);
        let top_level_declaration_reference = top_level_declaration_reference_from_pointer(unit, top_level_declaration);

        let global_location = get_source_location(parser, global_token);
        switch (global_token->id)
        {
            break; case TOKEN_ID_IDENTIFIER_START:
            {
                FunctionAttributes function_attributes = {};
                Linkage linkage = {};
                bool linkage_set = false;
                bool is_export = false;
                bool is_extern = false;

                let global = global_from_parser(unit);
                let global_reference = global_reference_from_pointer(unit, global);
                let global_storage_pointer = new_value(unit);
                *global_storage_pointer = (Value){};
                let global_storage = value_reference_from_pointer(unit, global_storage_pointer);
                global->variable.storage = global_storage;

                let global_identifier = end_identifier(unit, parser, global_token);
                let global_name = global_identifier.string;

                if (expect_token(parser, TOKEN_ID_LEFT_BRACKET))
                {
                    while (!expect_token(parser, TOKEN_ID_RIGHT_BRACKET))
                    {
                        let identifier = expect_identifier(unit, parser);
                        let identifier_string = string_from_reference(unit, identifier.string);

                        if (str_equal(identifier_string, S("export")))
                        {
                            is_export = true;
                        }
                        else if (str_equal(identifier_string, S("extern")))
                        {
                            is_extern = true;
                        }
                        else
                        {
                            parser_error();
                        }

                        if (!expect_token(parser, TOKEN_ID_COMMA))
                        {
                            if (!expect_token(parser, TOKEN_ID_RIGHT_BRACKET))
                            {
                                parser_error();
                            }
                            break;
                        }
                    }
                }

                if (is_export | is_extern)
                {
                    if (linkage_set)
                    {
                        if (linkage == LINKAGE_INTERNAL)
                        {
                            parser_error();
                        }
                    }
                    else
                    {
                        // TODO
                    }

                    linkage = LINKAGE_EXTERNAL;
                }

                if (unlikely(!expect_token(parser, TOKEN_ID_COLON)))
                {
                    parser_error();
                }

                TypeReference global_type = {};
                ArgumentReference argument_list = {};

                let assign = expect_token(parser, TOKEN_ID_ASSIGN);
                if (unlikely(!assign))
                {
                    let token = get_token(parser);
                    if (token->id == TOKEN_ID_KEYWORD_TYPE_FN)
                    {
                        unit->current_function = global_reference;
                    }
                    global_type = parse_type(unit, parser, scope, &argument_list);
                    assign = expect_token(parser, TOKEN_ID_ASSIGN);
                }

                if (!assign)
                {
                    parser_error();
                }

                bool is_function = 0;
                if (is_ref_valid(global_type))
                {
                    let global_type_p = type_pointer_from_reference(unit, global_type);
                    is_function = global_type_p->id == TYPE_ID_FUNCTION;
                }

                check(!is_ref_valid(global_storage_pointer->type));

                ValueReference initial_value = {};

                if (is_function)
                {
                    let function_scope = new_scope(unit);
                    *function_scope = (Scope) {
                        .parent = scope,
                        .id = SCOPE_ID_FUNCTION,
                        .function = global_reference,
                    };
                    let function_scope_ref = scope_reference_from_pointer(unit, function_scope);
                    global_storage_pointer->function = (ValueFunction) {
                        .scope = function_scope_ref,
                        .arguments = argument_list,
                        .block = {},
                        .attributes = function_attributes,
                    };
                    global_storage_pointer->id = VALUE_ID_FUNCTION;

                    // Fix up argument scopes (from file to function)
                    let argument_ref = argument_list;

                    while (is_ref_valid(argument_ref))
                    {
                        let argument = argument_pointer_from_reference(unit, argument_ref);
                        argument->variable.scope = function_scope_ref;
                        argument_ref = argument->next;
                    }

                    let block_ref = parse_block(unit, parser, function_scope_ref, expect_token(parser, TOKEN_ID_LEFT_BRACE));
                    let block = block_pointer_from_reference(unit, block_ref);
                    let block_scope = scope_pointer_from_reference(unit, block->scope);
                    function_scope->location = block_scope->location;
                    global_storage_pointer->function.block = block_ref;
                }
                else
                {
                    todo();
                }

                *global = (Global) {
                    .variable = {
                        .name = global_name,
                        .storage = global_storage,
                        .type = global_type,
                        .scope = scope,
                        .location = global_location,
                    },
                    .initial_value = initial_value,
                    .linkage = linkage,
                };

                *top_level_declaration = (TopLevelDeclaration) {
                    .global = global_reference,
                    .id = TOP_LEVEL_DECLARATION_GLOBAL,
                };

                if (likely(is_ref_valid(previous_tld)))
                {
                    let p_tld = top_level_declaration_pointer_from_reference(unit, previous_tld);
                    p_tld->next = top_level_declaration_reference;
                }
                else
                {
                    first_tld = top_level_declaration_reference;
                }

                previous_tld = top_level_declaration_reference;

                unit->current_function = (GlobalReference){};
            }
            break; case TOKEN_ID_KEYWORD_TYPE:
            {
                parser_error();
            }
            break; default: todo();
        }
    }

    file_pointer->first_tld = first_tld;
}

#if BB_INCLUDE_TESTS
PUB_IMPL bool parser_tests(TestArguments* restrict arguments)
{
    return 1;
}
#endif
