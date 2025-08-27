#include <parser.h>
#include <immintrin.h>

#define parser_error() trap();
#define todo() trap()

STRUCT(Parser)
{
    str content;
    Token* restrict pointer;
    u32 offset;
    u32 line_byte_offset;
    u32 line_number_offset;
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

static Precedence get_token_precedence(Token* restrict token)
{
    switch (token->id)
    {
        break; case TOKEN_ID_SEMICOLON:
        {
            return PRECEDENCE_NONE;
        }
        break; default:
        {
            todo();
        }
    }
}

typedef enum ValueKind : u8
{
    VALUE_KIND_RIGHT,
    VALUE_KIND_LEFT,
} ValueKind;

STRUCT(ValueParsing)
{
    Token* restrict token;
    ValueReference left;
    Precedence precedence;
    ValueKind kind;
    bool is_statement;
};

static SourceLocation get_source_location(Parser* restrict parser, Token* restrict token)
{
    return (SourceLocation) {
        .line_number_offset = parser->line_number_offset,
        .line_byte_offset = parser->line_byte_offset,
        .column_offset = token->offset,
    };
}

static Token* get_token_internal(Parser* restrict parser)
{
    Token* token = &parser->pointer[parser->offset];
    return token;
}

static Token* restrict get_token(Parser* restrict parser)
{
    let t = get_token_internal(parser);
    if (unlikely(t->id == TOKEN_ID_LINE_BYTE_OFFSET))
    {
        let line_byte_offset = t;
        let line_number_offset = t + 1;
        parser->line_byte_offset = line_byte_offset->offset;
        parser->line_number_offset = line_number_offset->offset;
        parser->offset += 2;
    }

    t = get_token_internal(parser);
    return t;
}

static Token* restrict peek_token(Parser* restrict parser)
{
    let t = get_token(parser);
    return t;
}

static Token* restrict consume_token(Parser* restrict parser)
{
    let token = get_token(parser);
    parser->offset += 1;
    return token;
}

static Token* restrict expect_token(Parser* restrict parser, TokenId id)
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

static Token* restrict expect_token_of_many(Parser* restrict parser, TokenId* ids, u32 id_count)
{
    Token* result = 0;
    let token = get_token(parser);
    let tid = token->id;

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

static bool identifier_parsing_valid(IdentifierParsing p)
{
    return p.string.v != 0;
}

static str file_content(CompileUnit* unit, FileReference file_index)
{
    let file = file_pointer_from_reference(unit, file_index);
    unused(file);
    parser_error();
}

static char* restrict pointer_from_token_start(Parser* restrict parser, Token* token)
{
    u32 start = token->offset;
    char* restrict pointer = parser->content.pointer + parser->line_byte_offset + start;
    return pointer;
}

static IdentifierParsing end_identifier(CompileUnit* restrict unit, Parser* restrict parser, Token* restrict start)
{
    assert(start);
    assert(start->id == TOKEN_ID_IDENTIFIER_START);

    IdentifierParsing result = {};

    let end = expect_token(parser, TOKEN_ID_IDENTIFIER_END);

    if (end)
    {
        let pointer = pointer_from_token_start(parser, start);
        u32 start_index = start->offset;
        u32 end_index = end->offset;
        assert(end_index > start_index);
        str s = { pointer, end_index - start_index };
        result = (IdentifierParsing) {
            .string = allocate_string(unit, s),
            .line_offset = start_index,
        };
    }

    return result;
}

static IdentifierParsing expect_identifier(CompileUnit* restrict unit, Parser* restrict parser)
{
    IdentifierParsing result = {};

    let identifier_start = expect_token(parser, TOKEN_ID_IDENTIFIER_START);

    if (identifier_start)
    {
        result = end_identifier(unit, parser, identifier_start);
    }

    return result;
}

static IntegerParsing parse_decimal_vectorized(const char* restrict p)
{
    let zero = _mm512_set1_epi8('0');
    let nine = _mm512_set1_epi8('9');
    let chunk = _mm512_loadu_epi8(&p[0]);
    let lower_limit = _mm512_cmpge_epu8_mask(chunk, zero);
    let upper_limit = _mm512_cmple_epu8_mask(chunk, nine);
    let is = _kand_mask64(lower_limit, upper_limit);

    let digit_count = _tzcnt_u64(~_cvtmask64_u64(is));

    let digit_mask = _cvtu64_mask64((1ULL << digit_count) - 1);
    let digit2bin = _mm512_maskz_sub_epi8(digit_mask, chunk, zero);
    // let lo0 = _mm512_castsi512_si128(digit2bin);
    // let a = _mm512_cvtepu8_epi64(lo0);
    let digit_count_splat = _mm512_set1_epi8((u8)digit_count);

    let to_sub = _mm512_set_epi8(
            64, 63, 62, 61, 60, 59, 58, 57,
            56, 55, 54, 53, 52, 51, 50, 49,
            48, 47, 46, 45, 44, 43, 42, 41,
            40, 39, 38, 37, 36, 35, 34, 33,
            32, 31, 30, 29, 28, 27, 26, 25,
            24, 23, 22, 21, 20, 19, 18, 17,
            16, 15, 14, 13, 12, 11, 10, 9,
            8, 7, 6, 5, 4, 3, 2, 1);
    let ib = _mm512_maskz_sub_epi8(digit_mask, digit_count_splat, to_sub);
    let asds = _mm512_maskz_permutexvar_epi8(digit_mask, ib, digit2bin);

    let a128_0_0 = _mm512_extracti64x2_epi64(asds, 0);
    let a128_1_0 = _mm512_extracti64x2_epi64(asds, 1);

    let a128_0_1 = _mm_srli_si128(a128_0_0, 8);
    // let a128_1_1 = _mm_srli_si128(a128_1_0, 8);

    let a8_0_0 = _mm512_cvtepu8_epi64(a128_0_0);
    let a8_0_1 = _mm512_cvtepu8_epi64(a128_0_1);
    let a8_1_0 = _mm512_cvtepu8_epi64(a128_1_0);

    let powers_of_ten_0_0 = _mm512_set_epi64(
            10000000,
            1000000,
            100000,
            10000,
            1000,
            100,
            10,
            1);
    let powers_of_ten_0_1 = _mm512_set_epi64(
            1000000000000000,
            100000000000000,
            10000000000000,
            1000000000000,
            100000000000,
            10000000000,
            1000000000,
            100000000
            );
    let powers_of_ten_1_0 = _mm512_set_epi64(
            0,
            0,
            0,
            0,
            10000000000000000000ULL,
            1000000000000000000,
            100000000000000000,
            10000000000000000
            );

    let a0_0 = _mm512_mullo_epi64(a8_0_0, powers_of_ten_0_0);
    let a0_1 = _mm512_mullo_epi64(a8_0_1, powers_of_ten_0_1);
    let a1_0 = _mm512_mullo_epi64(a8_1_0, powers_of_ten_1_0);

    let add = _mm512_add_epi64(_mm512_add_epi64(a0_0, a0_1), a1_0);
    let reduce_add = _mm512_reduce_add_epi64(add);
    let value = reduce_add;

    return (IntegerParsing){ .value = value, .i = digit_count };
}

STRUCT(ParseInteger)
{
    u64 value;
    u64 digit_count;
};

static ParseInteger end_integer(CompileUnit* restrict unit, Parser* restrict parser, Token* restrict start)
{
    assert(start);
    assert(start->id == TOKEN_ID_INTEGER_START_HEXADECIMAL_PREFIXED || start->id == TOKEN_ID_INTEGER_START_DECIMAL_PREFIXED || start->id == TOKEN_ID_INTEGER_START_DECIMAL_INFERRED || start->id == TOKEN_ID_INTEGER_START_OCTAL_PREFIXED || start->id == TOKEN_ID_INTEGER_START_BINARY_PREFIXED);

    ParseInteger result = {};

    let end = expect_token(parser, TOKEN_ID_INTEGER_END);

    if (end)
    {
        let start_id = start->id;
        bool is_prefixed = start_id != TOKEN_ID_INTEGER_START_DECIMAL_INFERRED;
        let original_start_pointer = pointer_from_token_start(parser, start);
        let start_pointer = original_start_pointer + ((u64)is_prefixed << 1);

        IntegerParsing p;

        switch (start->id)
        {
            break; case TOKEN_ID_INTEGER_START_HEXADECIMAL_PREFIXED: case TOKEN_ID_INTEGER_START_DECIMAL_PREFIXED:
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
                p = parse_decimal_vectorized(start_pointer);
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

static ParseInteger expect_integer(CompileUnit* restrict unit, Parser* restrict parser)
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

static TypeReference parse_type(CompileUnit* restrict unit, Parser* restrict parser, ScopeReference scope, ArgumentReference* argument_list)
{
    let token = consume_token(parser);

    switch (token->id)
    {
        break; case TOKEN_ID_KEYWORD_TYPE_FN:
        {
            CallingConvention calling_convention = CALLING_CONVENTION_C;
            bool is_variable_argument = false;

            if (expect_token(parser, TOKEN_ID_LEFT_BRACKET))
            {
                // let identifier = expect_identifier(unit, parser);
                parser_error();
            }

            if (!expect_token(parser, TOKEN_ID_LEFT_PARENTHESIS))
            {
                parser_error();
            }

            u64 argument_count = 0;
            // let argument_arena = unit_arena(unit, UNIT_ARENA_COMPILE_UNIT);
            // let first_argument = arena_current_position(argument_arena, alignof(Argument));

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

#if 0
                let argument = arena_allocate(argument_arena, Argument, 1);

                let identifier_token = consume_token(parser);
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
#endif

                parser_error();
            }

            let return_type = parse_type(unit, parser, scope, 0);
            let allocation_size = (sizeof(TypeReference) * (argument_count + 1)) + (sizeof(AbiInformation) * (argument_count + 1));
            static_assert(alignof(TypeReference) == alignof(AbiInformation));
            let semantic_type_allocation = arena_allocate_bytes(unit_arena(unit, UNIT_ARENA_COMPILE_UNIT), allocation_size, MAX(alignof(TypeReference), alignof(AbiInformation)));
            let semantic_types = (TypeReference*)semantic_type_allocation;
            semantic_types[0] = return_type;

            if (argument_count)
            {
                // let first_argument_index = argument_reference_from_pointer(unit, first_argument);
                trap();
            }

            let function_type = arena_allocate(unit_arena(unit, UNIT_ARENA_TYPE), Type, 1);
            *function_type = (Type) {
                .function = {
                    .semantic_types = semantic_types,
                    .abi_types = 0,
                    .register_count = {},
                    .semantic_argument_count = argument_count,
                    .abi_argument_count = 0,
                    .calling_convention = calling_convention,
                    .is_variable_argument = is_variable_argument,
                },
                .name = {},
                .scope = scope,
                .id = TYPE_ID_FUNCTION,
                .analyzed = 0,
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
        break; case TOKEN_ID_KEYWORD_TYPE_INTEGER:
        {
            let token_start = pointer_from_token_start(parser, token);
            assert(*token_start == 's' || *token_start == 'u');
            let parsing_result = parse_decimal_vectorized(token_start + 1);
            assert(parsing_result.i);
            let bit_count = parsing_result.value;
            let is_signed = *token_start == 's';

            let integer_type = get_integer_type(unit, bit_count, is_signed);
            return integer_type;
        }
        break; default:
        {
            todo();
        }
    }
}

static Global* global_from_parser(CompileUnit* restrict unit)
{
    let global = arena_allocate(unit_arena(unit, UNIT_ARENA_COMPILE_UNIT), Global, 1);
    *global = (Global) {};
    return global;
}

static ValueReference parse_left(CompileUnit* restrict unit, Parser* restrict parser, ScopeReference scope, ValueParsing parsing)
{
    let first_token = consume_token(parser);
    ValueReference result = {};

    switch (first_token->id)
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
                .constant_integer = integer_parsing.value,
                .type = 0,
                .id = VALUE_ID_CONSTANT_INTEGER,
            };
            result = value_reference_from_pointer(unit, value);
        }
        break; default:
        {
            todo();
        }
    }

    assert(is_ref_valid(result));
    return result;
}

static ValueReference parse_right(CompileUnit* restrict unit, Parser* restrict parser, ScopeReference scope, ValueParsing parsing)
{
    ValueReference final_result = parsing.left;
    assert(is_ref_valid(final_result));
    Precedence precedence = parsing.precedence;

    while (1)
    {
        let loop_token = peek_token(parser);
        let loop_token_precedence = get_token_precedence(loop_token);

        if (loop_token_precedence == PRECEDENCE_ASSIGNMENT)
        {
            loop_token_precedence = parsing.is_statement ? loop_token_precedence : PRECEDENCE_NONE;
        }

        if (precedence > loop_token_precedence)
        {
            break;
        }

        todo();
    }

    assert(is_ref_valid(final_result));
    return final_result;
}

static ValueReference parse_precedence(CompileUnit* restrict unit, Parser* restrict parser, ScopeReference scope, ValueParsing parsing)
{
    assert(!parsing.token);
    let left = parse_left(unit, parser, scope, parsing);
    parsing.left = left;
    let result = parse_right(unit, parser, scope, parsing);
    return result;
}

static ValueReference parse_value(CompileUnit* restrict unit, Parser* restrict parser, ScopeReference scope, ValueParsing parsing)
{
    assert(parsing.precedence == PRECEDENCE_NONE);
    assert(!is_ref_valid(parsing.left));
    parsing.precedence = PRECEDENCE_ASSIGNMENT;
    let value = parse_precedence(unit, parser, scope, parsing);
    return value;
}

static StatementReference parse_statement(CompileUnit* restrict unit, Parser* restrict parser, ScopeReference scope)
{
    bool require_semicolon = 1;
    let first_token = consume_token(parser);
    let statement = arena_allocate(unit_arena(unit, UNIT_ARENA_COMPILE_UNIT), Statement, 1);
    *statement = (Statement)
    {
        .location = get_source_location(parser, first_token),
    };

    switch (first_token->id)
    {
        break; case TOKEN_ID_KEYWORD_STATEMENT_RETURN:
        {
            ValueReference return_value = {};

            if (peek_token(parser)->id != TOKEN_ID_SEMICOLON)
            {
                return_value = parse_value(unit, parser, scope, (ValueParsing){});
            }

            statement->return_st = return_value;
            statement->id = STATEMENT_ID_RETURN;
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

static BlockReference parse_block(CompileUnit* restrict unit, Parser* restrict parser, ScopeReference parent_scope, Token* restrict left_brace)
{
    if (!left_brace)
    {
        parser_error();
    }

    assert(left_brace->id == TOKEN_ID_LEFT_BRACE);

    Block* restrict block = arena_allocate(unit_arena(unit, UNIT_ARENA_COMPILE_UNIT), Block, 1);
    *block = (Block)
    {
        .scope = {
            .parent = parent_scope,
            .location = get_source_location(parser, left_brace),
            .id = SCOPE_ID_BLOCK,
        },
    };

    let scope = scope_reference_from_pointer(unit, &block->scope);
    StatementReference current_statement = {};

    while (!expect_token(parser, TOKEN_ID_RIGHT_BRACE))
    {
        let statement_reference = parse_statement(unit, parser, scope);
        let statement_pointer = statement_pointer_from_reference(unit, statement_reference);
        assert(!is_ref_valid(statement_pointer->next));
        
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

    return block_reference_from_pointer(unit, block);
}

void parse_file(CompileUnit* restrict unit, File* file_pointer, TokenList tl)
{
    Parser p = {
        .content = file_pointer->content,
        .pointer = tl.pointer,
    };
    Parser* restrict parser = &p;

    let scope = scope_reference_from_pointer(unit, &file_pointer->scope);

    TopLevelDeclarationReference previous_tld = {};

    Token* global_token;

    while ((global_token = consume_token(parser))->id != TOKEN_ID_EOF)
    {
        let top_level_declaration = arena_allocate(unit_arena(unit, UNIT_ARENA_COMPILE_UNIT), TopLevelDeclaration, 1);
        let top_level_declaration_reference = top_level_declaration_reference_from_pointer(unit, top_level_declaration);

        switch (global_token->id)
        {
            break; case TOKEN_ID_IDENTIFIER_START:
            {
                FunctionAttributes function_attributes = {};
                Linkage linkage = {};

                let global = global_from_parser(unit);
                let global_reference = global_reference_from_pointer(unit, global);
                let global_storage_pointer = new_value(unit);
                *global_storage_pointer = (Value){};
                let global_storage = value_reference_from_pointer(unit, global_storage_pointer);
                global->variable.storage = global_storage;

                let global_identifier = end_identifier(unit, parser, global_token);
                let global_name = global_identifier.string;

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
                    let pointer_type = get_pointer_type(unit, global_type);
                    global_storage_pointer->type = pointer_type;
                    let global_type_p = type_pointer_from_reference(unit, global_type);
                    is_function = global_type_p->id == TYPE_ID_FUNCTION;
                }

                ValueReference initial_value = {};

                if (is_function)
                {
                    global_storage_pointer->function = (ValueFunction) {
                        .llvm = {},
                            .arguments = argument_list,
                            .block = {},
                            .attributes = function_attributes,
                    };
                    global_storage_pointer->id = VALUE_ID_FUNCTION;
                    global->scope = (Scope) {
                        .parent = scope,
                        .location = get_source_location(parser, global_token),
                        .id = SCOPE_ID_FUNCTION,
                    };

                    let block = parse_block(unit, parser, scope_reference_from_pointer(unit, &global->scope), expect_token(parser, TOKEN_ID_LEFT_BRACE));
                    global_storage_pointer->function.block = block;
                }
                else
                {
                    todo();
                }

                let old_scope = global->scope;

                *global = (Global) {
                    .variable = {
                        .name = global_name,
                        .storage = global_storage,
                        .type = {},
                        .scope = scope,
                        .location = get_source_location(parser, global_token),
                    },
                    .scope = old_scope,
                    .initial_value = initial_value,
                    .linkage = linkage,
                };

                *top_level_declaration = (TopLevelDeclaration) {
                    .global = global_reference,
                    .id = TOP_LEVEL_DECLARATION_GLOBAL,
                };

                if (is_ref_valid(previous_tld))
                {
                    let p_tld = top_level_declaration_pointer_from_reference(unit, previous_tld);
                    p_tld->next = top_level_declaration_reference;
                }

                unit->current_function = (GlobalReference){};
            }
            break; case TOKEN_ID_KEYWORD_TYPE:
            {
                parser_error();
            }
            break; default: todo();
        }
    }
}
