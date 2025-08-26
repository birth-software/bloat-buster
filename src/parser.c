#include <parser.h>
#include <immintrin.h>

STRUCT(Parser)
{
    str content;
    Token* restrict pointer;
    u32 offset;
    u32 line_byte_offset;
    u32 line_number_offset;
};

#define parser_error() trap();
#define todo() trap()

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
    parser_error();
}

static char* restrict pointer_from_token_start(Parser* restrict parser, Token* token)
{
    u32 start = token->offset;
    char* restrict pointer = parser->content.pointer + parser->line_byte_offset + start;
    return pointer;
}

static IdentifierParsing end_identifier(CompileUnit* restrict unit, Parser* restrict parser, Token* restrict identifier_start)
{
    assert(identifier_start);

    IdentifierParsing result = {};

    let identifier_end = expect_token(parser, TOKEN_ID_IDENTIFIER_END);

    if (identifier_end)
    {
        u32 start = identifier_start->offset;
        char* restrict pointer = parser->content.pointer + parser->line_byte_offset + start;
        u32 end = identifier_end->offset;
        assert(end > start);
        str s = { pointer, end - start };
        result = (IdentifierParsing) {
            .string = allocate_string(unit, s),
            .line_offset = start,
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
    let lo0 = _mm512_castsi512_si128(digit2bin);
    let a = _mm512_cvtepu8_epi64(lo0);
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
    let a128_1_1 = _mm_srli_si128(a128_1_0, 8);

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
                let identifier = expect_identifier(unit, parser);
                parser_error();
            }

            if (!expect_token(parser, TOKEN_ID_LEFT_PARENTHESIS))
            {
                parser_error();
            }

            u64 argument_count = 0;
            let argument_arena = unit_arena(unit, UNIT_ARENA_COMPILE_UNIT);
            let first_argument = arena_current_position(argument_arena, alignof(Argument));

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

                parser_error();
            }

            let return_type = parse_type(unit, parser, scope, 0);
            let argument_types = arena_allocate(unit_arena(unit, UNIT_ARENA_COMPILE_UNIT), TypeReference, argument_count);

            todo();
        }
        break; case TOKEN_ID_IDENTIFIER_START:
        {
            IdentifierParsing identifier_parsing = end_identifier(unit, parser, token);
            let identifier = string_from_reference(unit, identifier_parsing.string);
            todo();
        }
        break; case TOKEN_ID_KEYWORD_TYPE_INTEGER:
        {
            let token_start = pointer_from_token_start(parser, token);
            assert(*token_start == 's' || *token_start == 'u');
            let parsing_result = parse_decimal_vectorized(token_start + 1);
            assert(parsing_result.i);
            let is_signed = *token_start == 's';

            todo();
        }
        break; default:
        {
            todo();
        }
    }

    todo();
}

void parse_file(CompileUnit* restrict unit, File* file_pointer, TokenList tl)
{
    Parser p = {
        .content = file_pointer->content,
        .pointer = tl.pointer,
    };
    Parser* restrict parser = &p;

    let arena = unit_arena(unit, UNIT_ARENA_COMPILE_UNIT);
    let scope = scope_reference_from_pointer(unit, &file_pointer->scope);

    Token* global_token;
    while ((global_token = consume_token(parser))->id != TOKEN_ID_EOF)
    {
        let top_level_declaration = arena_allocate(arena, TopLevelDeclaration, 1);

        switch (global_token->id)
        {
            break; case TOKEN_ID_IDENTIFIER_START:
            {
                let identifier_start = global_token;
                let identifier_end = expect_token(parser, TOKEN_ID_IDENTIFIER_END);

                if (unlikely(!identifier_end))
                {
                    parser_error();
                }

                if (unlikely(!expect_token(parser, TOKEN_ID_COLON)))
                {
                    parser_error();
                }

                TypeReference global_type = {};

                let assign = expect_token(parser, TOKEN_ID_ASSIGN);
                if (unlikely(!assign))
                {
                    global_type = parse_type(unit, parser, scope, 0);
                    assign = expect_token(parser, TOKEN_ID_COLON);
                }

                if (!assign)
                {
                    parser_error();
                }

                parser_error();
            }
            break; case TOKEN_ID_KEYWORD_TYPE:
            {
                parser_error();
            }
            break; default: UNREACHABLE();
        }

        parser_error();
        *top_level_declaration = (TopLevelDeclaration) {
        };
        parser_error();
    }
}
