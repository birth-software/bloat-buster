#include <parser.h>

STRUCT(Parser)
{
    StringReference content;
    Token* restrict pointer;
    u32 offset;
    u32 line_byte_offset;
    u32 line_number_offset;
};

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
    str string;
    u32 line_offset;
};

static bool identifier_parsing_valid(IdentifierParsing p)
{
    return p.string.pointer != 0;
}

static str file_content(CompileUnit* unit, FileReference file_index)
{
    let file = file_pointer_from_reference(unit, file_index);
    trap();
}

static IdentifierParsing end_identifier(CompileUnit* restrict unit, Parser* restrict parser, Token* restrict identifier_start)
{
    assert(identifier_start);

    IdentifierParsing result = {};

    let identifier_end = expect_token(parser, TOKEN_ID_IDENTIFIER_END);

    if (identifier_end)
    {
        u32 start = identifier_start->offset;
        u32 end = identifier_end->offset;
        assert(end > start);
        trap();
        // char* restrict pointer = parser->content.pointer + parser->line_byte_offset + start;
        // u64 length = (end - start);
        //
        // result = (IdentifierParsing) {
        //     .string = (str) { pointer, length },
        //     .line_offset = start,
        // };
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

static TypeReference parse_type(CompileUnit* restrict unit, Parser* restrict parser, ScopeReference scope)
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
                trap();
            }

            if (!expect_token(parser, TOKEN_ID_LEFT_PARENTHESIS))
            {
                trap();
            }

            trap();
        }
        break; default:
        {
            trap();
        }
    }

    trap();
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
                    trap();
                }

                if (unlikely(!expect_token(parser, TOKEN_ID_COLON)))
                {
                    trap();
                }

                TypeReference global_type = {};

                let assign = expect_token(parser, TOKEN_ID_ASSIGN);
                if (unlikely(!assign))
                {
                    global_type = parse_type(unit, parser, scope);
                    assign = expect_token(parser, TOKEN_ID_COLON);
                }

                if (!assign)
                {
                    trap();
                }

                trap();
            }
            break; case TOKEN_ID_KEYWORD_TYPE:
            {
                trap();
            }
            break; default: UNREACHABLE();
        }

        trap();
        *top_level_declaration = (TopLevelDeclaration) {
        };
        trap();
    }
}
