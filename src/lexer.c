#include <lexer.h>

#include <time.h>
#include <stdio.h>

static bool is_space(char ch)
{
    return ((ch == ' ') || (ch == '\t')) || ((ch == '\r') || (ch == '\n'));
}

static bool is_decimal(char ch)
{
    return (ch >= '0') & (ch <= '9');
}

static bool is_octal(char ch)
{
    return (ch >= '0') & (ch <= '7');
}

static bool is_binary(char ch)
{
    return (ch == '0') | (ch == '1');
}

static bool is_hexadecimal_alpha_lower(char ch)
{
    return (ch >= 'a') & (ch <= 'f');
}

static bool is_hexadecimal_alpha_upper(char ch)
{
    return (ch >= 'A') & (ch <= 'F');
}

static bool is_hexadecimal_alpha(char ch)
{
    return is_hexadecimal_alpha_upper(ch) | is_hexadecimal_alpha_lower(ch);
}

static bool is_hexadecimal(char ch)
{
    return is_decimal(ch) | is_hexadecimal_alpha(ch);
}

static bool is_identifier_start(char ch)
{
    return ((ch >= 'a') & (ch <= 'z')) | ((ch >= 'A') & (ch <= 'Z')) | (ch == '_');
}

static bool is_identifier(char ch)
{
    return is_identifier_start(ch) | is_decimal(ch);
}

static u128 accumulate_hexadecimal(u128 accumulator, u8 ch)
{
    u8 value;

    if (is_decimal(ch))
    {
        value = ch - '0';
    }
    else if (is_hexadecimal_alpha_upper(ch))
    {
        value = ch - 'A' + 10;
    }
    else if (is_hexadecimal_alpha_lower(ch))
    {
        value = ch - 'a' + 10;
    }
    else
    {
        UNREACHABLE();
    }

    return (accumulator * 16) + value;
}

static u128 accumulate_decimal(u128 accumulator, u8 ch)
{
    assert(is_decimal(ch));
    return (accumulator * 10) + (ch - '0');
}

static u128 accumulate_octal(u128 accumulator, u8 ch)
{
    assert(is_octal(ch));

    return (accumulator * 8) + (ch - '0');
}

static u128 accumulate_binary(u128 accumulator, u8 ch)
{
    assert(is_binary(ch));

    return (accumulator * 2) + (ch - '0');
}

static u128 parse_integer_decimal_assume_valid(str string)
{
    u128 value = 0;

    for (u64 i = 0; i < string.length; i += 1)
    {
        let ch = string.pointer[i];
        value = accumulate_decimal(value, ch);
    }

    return value;
}

static u128 parse_hexadecimal(str content, u64* offset_pointer)
{
    u128 value = 0;

    let i = *offset_pointer;

    while (1)
    {
        let ch = content.pointer[i];

        if (!is_hexadecimal(ch))
        {
            break;
        }

        i += 1;
        value = accumulate_hexadecimal(value, ch);
    }

    *offset_pointer = i;

    return value;
}

static u128 parse_decimal(str content, u64* offset_pointer)
{
    u128 value = 0;

    let i = *offset_pointer;

    while (1)
    {
        let ch = content.pointer[i];

        if (!is_decimal(ch))
        {
            break;
        }

        i += 1;
        value = accumulate_decimal(value, ch);
    }

    *offset_pointer = i;

    return value;
}

static u128 parse_octal(str content, u64* offset_pointer)
{
    u128 value = 0;

    let i = *offset_pointer;

    while (1)
    {
        let ch = content.pointer[i];

        if (!is_octal(ch))
        {
            break;
        }

        i += 1;
        value = accumulate_octal(value, ch);
    }

    *offset_pointer = i;

    return value;
}

static u128 parse_binary(str content, u64* offset_pointer)
{
    u128 value = 0;

    let i = *offset_pointer;

    while (1)
    {
        let ch = content.pointer[i];

        if (!is_binary(ch))
        {
            break;
        }

        i += 1;
        value = accumulate_binary(value, ch);
    }

    *offset_pointer = i;

    return value;
}

static u8 escape_character(u8 ch)
{
    switch (ch)
    {
        break; case 'n': return '\n';
        break; case 't': return '\t';
        break; case 'r': return '\r';
        break; case '\'': return '\'';
        break; case '\\': return '\\';
        break; default: return 0;
    }
}

TokenList lex(Arena* stable_arena, Arena* else_arena, str file, LexerError* error)
{
#if 0
    let lexing_start = take_timestamp();
#endif
    Token* tokens = (Token*)((u8*)stable_arena + align_forward(stable_arena->position, alignof(Token)));
    u64 token_count = 0;
    u64 i = 0;
    u64 line_offset = 0;
    u64 line_character_offset = 0;

    while (1)
    {
        bool skip_space = 1;
        while (skip_space)
        {
            let iteration_offset = i;

            bool space = 1;

            while ((i < file.length) & space)
            {
                let ch = file.pointer[i];
                let is_line_feed = ch == '\n';
                space = is_space(ch);
                i += space;

                line_offset += is_line_feed;
                line_character_offset = is_line_feed ? i : line_character_offset;
            }

            if (i + 1 < file.length)
            {
                let is_comment = file.pointer[i] == '/' && file.pointer[i + 1] == '/';

                if (is_comment)
                {
                    while (i < file.length && file.pointer[i] != '\n')
                    {
                        i += 1;
                    }

                    if (i < file.length)
                    {
                        line_offset += 1;
                        line_character_offset = i;
                        i += 1;
                    }
                }
            }

            skip_space = (i - iteration_offset) != 0;
        }

        let start_index = i;
        let line = line_offset + 1;
        let column = start_index - line_character_offset + 1;

        if ((i == file.length) | (line > UINT32_MAX) | (column > UINT32_MAX))
        {
            if (line > UINT32_MAX)
            {
                *error = (LexerError){
                    .id = LEXER_ERROR_ID_LINE_NUMBER_TOO_HIGH,
                    .offset = start_index,
                    .line = UINT32_MAX,
                    .column = column > UINT32_MAX ? UINT32_MAX : (u32)column,
                };
                return (TokenList) { tokens, token_count };
            }

            if (column > UINT32_MAX)
            {
                *error = (LexerError){
                    .id = LEXER_ERROR_ID_COLUMN_NUMBER_TOO_HIGH,
                    .offset = start_index,
                    .line = line > UINT32_MAX ? UINT32_MAX : (u32)line,
                    .column = UINT32_MAX,
                };
                return (TokenList) { tokens, token_count };
            }

            break;
        }

        let start = file.pointer[start_index];

        Token* token = arena_allocate(stable_arena, Token, 1);
        *token = (Token) {
            .line = (u32)line,
            .column = (u32)column,
        };

        if (is_identifier_start(start))
        {
            while (i < file.length)
            {
                let ch = file.pointer[i];
                if (!is_identifier(ch))
                {
                    break;
                }

                i += 1;
            }

            let candidate_identifier = str_from_ptr_start_end(file.pointer, start_index, i);

            let first_ch = candidate_identifier.pointer[0];
            let is_signed = first_ch == 's';
            let is_unsigned = first_ch == 'u';
            let is_plausible_primitive_type = (candidate_identifier.length > 1) & (candidate_identifier.length <= 4);
            let is_float_type = (first_ch == 'f') & is_plausible_primitive_type;
            let is_integer_type = (is_signed | is_unsigned) & is_plausible_primitive_type;

            if (is_integer_type | is_float_type)
            {
                bool is_decimal_ch = 1;

                for (u64 i = 1; i < candidate_identifier.length; i += 1)
                {
                    let ch = candidate_identifier.pointer[i];
                    is_decimal_ch = is_decimal_ch & is_decimal(ch);
                }

                is_integer_type = is_integer_type & is_decimal_ch;
                is_float_type = is_float_type & is_decimal_ch;
            }

            if (is_integer_type | is_float_type)
            {
                let bit_count_128 = parse_integer_decimal_assume_valid(str_slice_start(candidate_identifier, 1));
                assert(bit_count_128 < UINT64_MAX);
                let bit_count = (u64)bit_count_128;

                str type_name = is_signed ? S("signed integer") : (is_unsigned ? S("unsigned integer") : S("float"));

                if (bit_count == 0)
                {
                    str parts[] = {
                        type_name,
                        S(" type cannot have 0 bit count"),
                    };
                    *error = (LexerError){
                        .id = LEXER_ERROR_ID_PRIMITIVE_TYPE_0_BIT_COUNT,
                        .offset = start_index,
                        .line = line,
                        .column = column,
                    };

                    return (TokenList){ tokens, token_count };
                }

                if ((bit_count > 64) & (bit_count != 128))
                {
                    str parts[] = {
                        type_name,
                        S(" type cannot have that bit count"),
                    };
                    *error = (LexerError){
                        .id = LEXER_ERROR_ID_PRIMITIVE_TYPE_UNKNOWN_BIT_COUNT,
                        .offset = start_index,
                        .line = line,
                        .column = column,
                    };

                    return (TokenList){ tokens, token_count };
                }

                if (is_integer_type)
                {
                    token->content = (TokenContent) {
                        .integer_type = {
                            .bit_count = bit_count,
                            .is_signed = is_signed,
                        },
                    };
                    token->id = TOKEN_ID_KEYWORD_TYPE_INTEGER;
                }
                else
                {
                    token->content = (TokenContent) {
                        .integer = bit_count_128,
                    };
                    token->id = TOKEN_ID_KEYWORD_TYPE_FLOAT;
                }
            }
            else
            {
                str candidate_strings[] = {
                    S("type"),
                    S("void"),
                    S("noreturn"),
                    S("enum"),
                    S("struct"),
                    S("bits"),
                    S("union"),
                    S("fn"),
                    S("alias"),
                    S("vector"),
                    S("enum_array"),
                    S("opaque"),

                    S("_"),
                    S("return"),
                    S("if"),
                    S("when"),
                    S("for"),
                    S("while"),
                    S("switch"),
                    S("break"),
                    S("continue"),
                    S("unreachable"),
                    S("else"),

                    S("undefined"),
                    S("zero"),
                    
                    S("and"),
                    S("or"),
                    S("and?"),
                    S("or?"),
                };
                TokenId candidate_ids[] = {
                    TOKEN_ID_KEYWORD_TYPE,
                    TOKEN_ID_KEYWORD_TYPE_VOID,
                    TOKEN_ID_KEYWORD_TYPE_NORETURN,
                    TOKEN_ID_KEYWORD_TYPE_ENUM,
                    TOKEN_ID_KEYWORD_TYPE_STRUCT,
                    TOKEN_ID_KEYWORD_TYPE_BITS,
                    TOKEN_ID_KEYWORD_TYPE_UNION,
                    TOKEN_ID_KEYWORD_TYPE_FN,
                    TOKEN_ID_KEYWORD_TYPE_ALIAS,
                    TOKEN_ID_KEYWORD_TYPE_VECTOR,
                    TOKEN_ID_KEYWORD_TYPE_ENUM_ARRAY,
                    TOKEN_ID_KEYWORD_TYPE_OPAQUE,

                    TOKEN_ID_KEYWORD_STATEMENT_UNDERSCORE,
                    TOKEN_ID_KEYWORD_STATEMENT_RETURN,
                    TOKEN_ID_KEYWORD_STATEMENT_IF,
                    TOKEN_ID_KEYWORD_STATEMENT_WHEN,
                    TOKEN_ID_KEYWORD_STATEMENT_FOR,
                    TOKEN_ID_KEYWORD_STATEMENT_WHILE,
                    TOKEN_ID_KEYWORD_STATEMENT_SWITCH,
                    TOKEN_ID_KEYWORD_STATEMENT_BREAK,
                    TOKEN_ID_KEYWORD_STATEMENT_CONTINUE,
                    TOKEN_ID_KEYWORD_STATEMENT_UNREACHABLE,
                    TOKEN_ID_KEYWORD_STATEMENT_ELSE,

                    TOKEN_ID_KEYWORD_VALUE_UNDEFINED,
                    TOKEN_ID_KEYWORD_VALUE_ZERO,

                    TOKEN_ID_KEYWORD_OPERATOR_AND,
                    TOKEN_ID_KEYWORD_OPERATOR_OR,
                    TOKEN_ID_KEYWORD_OPERATOR_AND_SHORTCIRCUIT,
                    TOKEN_ID_KEYWORD_OPERATOR_OR_SHORTCIRCUIT,
                };
                static_assert(array_length(candidate_strings) == array_length(candidate_ids));

                u64 search_index;
                for (search_index = 0; search_index < array_length(candidate_strings); search_index += 1)
                {
                    str candidate_string = candidate_strings[search_index];
                    if (str_equal(candidate_identifier, candidate_string))
                    {
                        break;
                    }
                }

                if (search_index < array_length(candidate_strings))
                {
                    let candidate_id = candidate_ids[search_index];
                    let next_ch = file.pointer[i];
                    let is_question = next_ch == '?';
                    let is_and_or_operators = (candidate_id == TOKEN_ID_KEYWORD_OPERATOR_AND) | (candidate_id == TOKEN_ID_KEYWORD_OPERATOR_OR);
                    i += is_and_or_operators;
                    search_index += 2 * (u64)is_and_or_operators;
                    candidate_id = candidate_ids[search_index];
                    token->id = candidate_id;
                }
                else
                {
                    assert(search_index == array_length(candidate_strings));
                    token->content = (TokenContent){
                        .string = candidate_identifier,
                    };
                    token->id = TOKEN_ID_IDENTIFIER;
                }
            }
        }
        else if (is_decimal(start))
        {
            let is_first_zero = start == '0';
            i += 1;

            let prefix_ch = file.pointer[i];
            let is_valid_prefix_ch = ((prefix_ch == 'x') | (prefix_ch == 'd')) | ((prefix_ch == 'o') | (prefix_ch == 'b'));
            let is_valid_prefix = is_first_zero & is_valid_prefix_ch;

            i += is_valid_prefix;
            i -= !is_valid_prefix;

            typedef enum IntegerFormat
            {
                INTEGER_FORMAT_BINARY,
                INTEGER_FORMAT_OCTAL,
                INTEGER_FORMAT_DECIMAL,
                INTEGER_FORMAT_HEXADECIMAL,
            } IntegerFormat;

            IntegerFormat format = INTEGER_FORMAT_DECIMAL;

            if (is_valid_prefix)
            {
                switch (prefix_ch)
                {
                    break; case 'x': format = INTEGER_FORMAT_HEXADECIMAL;
                    break; case 'd': format = INTEGER_FORMAT_DECIMAL;
                    break; case 'o': format = INTEGER_FORMAT_OCTAL;
                    break; case 'b': format = INTEGER_FORMAT_BINARY;
                    break; default:
                        UNREACHABLE();
                }
            }

            let inferred_decimal = !is_valid_prefix;
            u128 value = 0;

            switch (format)
            {
                break; case INTEGER_FORMAT_HEXADECIMAL: value = parse_hexadecimal(file, &i);
                break; case INTEGER_FORMAT_DECIMAL: value = parse_decimal(file, &i);
                break; case INTEGER_FORMAT_OCTAL: value = parse_octal(file, &i);
                break; case INTEGER_FORMAT_BINARY: value = parse_binary(file, &i);
                break; default:
                    UNREACHABLE();
            }

            if (inferred_decimal && file.pointer[i] == '.' && file.pointer[i + 1] != '.')
            {
                i += 1;

                let mantissa = parse_decimal(file, &i);

                let float_string_literal = str_slice(file, start_index, i);
                token->content = (TokenContent) {
                    .string = float_string_literal,
                };
                token->id = TOKEN_ID_FLOAT_STRING_LITERAL;
            }
            else
            {
                token->content = (TokenContent) {
                    .integer = value,
                };
                token->id = TOKEN_ID_INTEGER;
            }
        }
        else if (start == '"')
        {
            i += 1;

            let string_literal_start = i;

            u64 escape_character_count = 0;

            while (i < file.length)
            {
                let ch = file.pointer[i];

                if (ch == '"')
                {
                    break;
                }

                escape_character_count += ch == '\\';
                i += 1;
            }

            let is_properly_finished = file.pointer[i] == '"';
            if (!is_properly_finished)
            {
                *error = (LexerError){
                    .id = LEXER_ERROR_ID_STRING_LITERAL_NO_DOUBLE_QUOTE_EOF,
                    .offset = start_index,
                    .line = line,
                    .column = column,
                };

                return (TokenList){ tokens, token_count };
            }

            let string_literal_end = i;

            let length = string_literal_end - start_index - escape_character_count;
            let pointer = arena_allocate_bytes(else_arena, length, 1);
            let original_string_bytes = str_slice(file, string_literal_start, string_literal_end);
            let string_literal = str_from_ptr_len(pointer, length);

            if (escape_character_count != 0)
            {
                assert(original_string_bytes.length < string_literal.length);

                let source_i = start;
                u64 destination_i = 0;

                while (source_i < string_literal_end)
                {
                    let ch = file.pointer[source_i];

                    if (ch == '\\')
                    {
                        source_i += 1;
                        ch = file.pointer[source_i];
                        string_literal.pointer[destination_i] = escape_character(ch);
                        if (!ch)
                        {
                            return (TokenList) { tokens, token_count };
                        }
                    }
                    else
                    {
                        string_literal.pointer[destination_i] = ch;
                    }

                    source_i += 1;
                    destination_i += 1;
                }

                assert(i == source_i);
            }
            else
            {
                memcpy(pointer, original_string_bytes.pointer, original_string_bytes.length);
            }

            i += 1;

            token->content = (TokenContent) {
                .string = string_literal,
            };
            token->id = TOKEN_ID_STRING_LITERAL;
        }
        else if (start == '\'')
        {
            i += 1;

            u8 ch = file.pointer[i];
            if (ch == '\\')
            {
                i += 1;
                ch = escape_character(file.pointer[i]);
            }
            else
            {
                if (ch == '\'')
                {
                    *error = (LexerError){
                        .id = LEXER_ERROR_ID_CHARACTER_LITERAL_EMPTY,
                        .offset = start_index,
                        .line = line,
                        .column = column,
                    };
                    return (TokenList) { tokens, token_count };
                }
            }

            i += 1;

            if (file.pointer[i] != '\'')
            {
                *error = (LexerError){
                    .id = LEXER_ERROR_ID_CHARACTER_LITERAL_BADLY_TERMINATED,
                    .offset = start_index,
                    .line = line,
                    .column = column,
                };
                return (TokenList) { tokens, token_count };
            }

            i += 1;

            token->content = (TokenContent) {
                .integer = ch,
            };
            token->id = TOKEN_ID_CHARACTER_LITERAL;
        }
        else if (start == '=')
        {
            i += 1;

            let ch = file.pointer[i];

            let is_compare_equal = ch == '=';
            let is_switch_token = ch == '>';

            i += is_compare_equal;
            i += is_switch_token;

            TokenId id;

            if (is_compare_equal)
            {
                id = TOKEN_ID_COMPARE_EQUAL;
            }
            else if (is_switch_token)
            {
                id = TOKEN_ID_SWITCH_CASE;
            }
            else
            {
                id = TOKEN_ID_ASSIGN;
            }

            token->id = id;
        }
        else if (start == '!')
        {
            i += 1;

            let ch = file.pointer[i];

            let is_compare_not_equal = ch == '=';
            i += is_compare_not_equal;

            token->id = is_compare_not_equal ? TOKEN_ID_COMPARE_NOT_EQUAL : TOKEN_ID_EXCLAMATION_DOWN;
        }
        else if (start == '<')
        {
            let ch2 = file.pointer[i + 1];

            TokenId id;
            if (ch2 == '<')
            {
                let ch3 = file.pointer[i + 2];

                if (ch3 == '=')
                {
                    id = TOKEN_ID_SHIFT_LEFT_ASSIGN;
                    i += 3;
                }
                else
                {
                    id = TOKEN_ID_SHIFT_LEFT;
                    i += 2;
                }
            }
            else if (ch2 == '=')
            {
                id = TOKEN_ID_COMPARE_LESS_EQUAL;
                i += 2;
            }
            else
            {
                id = TOKEN_ID_COMPARE_LESS;
                i += 1;
            }

            token->id = id;
        }
        else if (start == '>')
        {
            let ch2 = file.pointer[i + 1];

            TokenId id;
            if (ch2 == '>')
            {
                let ch3 = file.pointer[i + 2];

                if (ch3 == '=')
                {
                    id = TOKEN_ID_SHIFT_RIGHT_ASSIGN;
                    i += 3;
                }
                else
                {
                    id = TOKEN_ID_SHIFT_RIGHT;
                    i += 2;
                }
            }
            else if (ch2 == '=')
            {
                id = TOKEN_ID_COMPARE_GREATER_EQUAL;
                i += 2;
            }
            else
            {
                id = TOKEN_ID_COMPARE_GREATER;
                i += 1;
            }

            token->id = id;
        }
        else if (start == '+')
        {
            i += 1;

            let ch = file.pointer[i];
            let is_assign = ch == '=';

            i += is_assign;
            
            token->id = is_assign ? TOKEN_ID_ADD_ASSIGN : TOKEN_ID_PLUS;
        }
        else if (start == '-')
        {
            i += 1;

            let ch = file.pointer[i];
            let is_assign = ch == '=';

            i += is_assign;
            
            token->id = is_assign ? TOKEN_ID_SUB_ASSIGN : TOKEN_ID_DASH;
        }
        else if (start == '*')
        {
            i += 1;

            let ch = file.pointer[i];
            let is_assign = ch == '=';

            i += is_assign;
            
            token->id = is_assign ? TOKEN_ID_MUL_ASSIGN : TOKEN_ID_ASTERISK;
        }
        else if (start == '/')
        {
            i += 1;

            let ch = file.pointer[i];
            let is_assign = ch == '=';

            i += is_assign;
            
            token->id = is_assign ? TOKEN_ID_DIV_ASSIGN : TOKEN_ID_FORWARD_SLASH;
        }
        else if (start == '%')
        {
            i += 1;

            let ch = file.pointer[i];
            let is_assign = ch == '=';

            i += is_assign;
            
            token->id = is_assign ? TOKEN_ID_REM_ASSIGN : TOKEN_ID_PERCENTAGE;
        }
        else if (start == '&')
        {
            i += 1;

            let ch = file.pointer[i];
            let is_assign = ch == '=';

            i += is_assign;
            
            token->id = is_assign ? TOKEN_ID_BITWISE_AND_ASSIGN : TOKEN_ID_AMPERSAND;
        }
        else if (start == '|')
        {
            i += 1;

            let ch = file.pointer[i];
            let is_assign = ch == '=';

            i += is_assign;
            
            token->id = is_assign ? TOKEN_ID_BITWISE_OR_ASSIGN : TOKEN_ID_BAR;
        }
        else if (start == '^')
        {
            i += 1;

            let ch = file.pointer[i];
            let is_assign = ch == '=';

            i += is_assign;
            
            token->id = is_assign ? TOKEN_ID_BITWISE_XOR_ASSIGN : TOKEN_ID_CARET;
        }
        else if (start == '.')
        {
            let ch2 = file.pointer[i + 1];
            let ch3 = file.pointer[i + 2];

            let is_ch2_dot = ch2 == '.';
            let is_ch2_address = ch2 == '&';
            let is_ch2_question = ch2 == '?';
            let is_ch3_dot = ch3 == '.';

            TokenId id;

            if (is_ch3_dot & is_ch2_dot)
            {
                id = TOKEN_ID_TRIPLE_DOT;
                i += 3;
            }
            else if (is_ch2_dot)
            {
                id = TOKEN_ID_DOUBLE_DOT;
                i += 2;
            }
            else if (is_ch2_address)
            {
                id = TOKEN_ID_POINTER_DEREFERENCE;
                i += 2;
            }
            else if (is_ch2_question)
            {
                id = TOKEN_ID_OPTIONAL_DEREFERENCE;
                i += 2;
            }
            else
            {
                id = TOKEN_ID_DOT;
                i += 1;
            }

            token->id = id;
        }
        else if (start == ',')
        {
            i += 1;
            token->id = TOKEN_ID_COMMA;
        }
        else if (start == ';')
        {
            i += 1;
            token->id = TOKEN_ID_SEMICOLON;
        }
        else if (start == ':')
        {
            i += 1;
            token->id = TOKEN_ID_COLON;
        }
        else if (start == '?')
        {
            i += 1;
            token->id = TOKEN_ID_QUESTION;
        }
        else if (start == '(')
        {
            i += 1;
            token->id = TOKEN_ID_LEFT_PARENTHESIS;
        }
        else if (start == ')')
        {
            i += 1;
            token->id = TOKEN_ID_RIGHT_PARENTHESIS;
        }
        else if (start == '{')
        {
            i += 1;
            token->id = TOKEN_ID_LEFT_BRACE;
        }
        else if (start == '}')
        {
            i += 1;
            token->id = TOKEN_ID_RIGHT_BRACE;
        }
        else if (start == '[')
        {
            i += 1;
            token->id = TOKEN_ID_LEFT_BRACKET;
        }
        else if (start == ']')
        {
            i += 1;
            token->id = TOKEN_ID_RIGHT_BRACKET;
        }
        else if (start == '@')
        {
            i += 1;
            token->id = TOKEN_ID_AT;
        }
        else if (start == '\\')
        {
            i += 1;
            token->id = TOKEN_ID_BACKSLASH;
        }
        else if (start == '`')
        {
            i += 1;
            token->id = TOKEN_ID_BACKTICK;
        }
        else if (start == '#')
        {
            i += 1;
            token->id = TOKEN_ID_HASH;
        }
        else if (start == '$')
        {
            i += 1;
            token->id = TOKEN_ID_DOLLAR;
        }
        else if (start == '~')
        {
            i += 1;
            token->id = TOKEN_ID_TILDE;
        }
        else if (start > 0x7f)
        {
            *error = (LexerError){
                .id = LEXER_ERROR_ID_NOT_SUPPORTED_X_ASCII_OR_UNICODE,
                .offset = start_index,
                .line = line,
                .column = column,
            };
            return (TokenList) { tokens, token_count };
        }
        else if (start < ' ')
        {
            *error = (LexerError){
                .id = LEXER_ERROR_ID_NON_PRINTABLE_ASCII,
                .offset = start_index,
                .line = line,
                .column = column,
            };
            return (TokenList) { tokens, token_count };
        }
        else if (start == 0x7f) // DEL
        {
            *error = (LexerError){
                .id = LEXER_ERROR_ID_FOUND_DEL,
                .offset = start_index,
                .line = line,
                .column = column,
            };
            return (TokenList) { tokens, token_count };
        }
        else
        {
            UNREACHABLE();
        }

        token_count += 1;
    }

#if 0
    let lexing_end = take_timestamp();

    let lexing_ns = ns_between(lexing_start, lexing_end);
    let gbytes_per_s = (f64)(file.length * 1000000000ULL) / (lexing_ns * 1024 * 1024 * 1024);
    let lines = line_offset + 1;
    let millions_lines_s = (f64)(lines * 1000) / lexing_ns;
    printf("Lexing: %lu ns. %f GB/s. %f MLOCs/s\n", lexing_ns, gbytes_per_s, millions_lines_s);
#endif

    return (TokenList) { .pointer = tokens, .length = token_count };
}
