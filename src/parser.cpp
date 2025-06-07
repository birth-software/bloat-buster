#include <compiler.hpp>

enum class ValueIntrinsic
{
    align_of,
    build_mode,
    byte_size,
    enum_from_int,
    enum_name,
    enum_values,
    extend,
    field_parent_pointer,
    has_debug_info,
    integer_max,
    int_from_enum,
    int_from_pointer,
    max,
    min,
    pointer_cast,
    pointer_from_int,
    select,
    string_to_enum,
    trap,
    truncate,
    va_start,
    va_end,
    va_arg,
    va_copy,
    count,
};

enum class TokenId
{
    none,
    comma,
    end_of_statement,
    integer,
    left_brace,
    left_bracket,
    left_parenthesis,
    right_brace,
    right_bracket,
    right_parenthesis,

    plus,
    dash,
    asterisk,
    forward_slash,
    percentage,
    caret,
    bar,
    ampersand,
    exclamation,

    assign_plus,
    assign_dash,
    assign_asterisk,
    assign_forward_slash,
    assign_percentage,
    assign_caret,
    assign_bar,
    assign_ampersand,

    value_keyword,
    operator_keyword,
    identifier,
    string_literal,
    value_intrinsic,

    shift_left,
    shift_right,
    assign_shift_left,
    assign_shift_right,

    compare_less,
    compare_less_equal,
    compare_greater,
    compare_greater_equal,
    compare_equal,
    compare_not_equal,

    dot,
    double_dot,
    triple_dot,

    pointer_dereference,

    assign,
    tilde,
};

enum class TokenIntegerKind
{
    hexadecimal,
    decimal,
    octal,
    binary,
    character_literal,
};

struct TokenInteger
{
    u64 value;
    TokenIntegerKind kind;
};

enum class ValueKeyword
{
    undefined,
    unreachable,
    zero,
    count,
};

enum class OperatorKeyword
{
    and_op,
    or_op,
    and_op_shortcircuit,
    or_op_shortcircuit,
    count,
};

struct Token
{
    union
    {
        TokenInteger integer;
        ValueKeyword value_keyword;
        String identifier;
        OperatorKeyword operator_keyword;
        ValueIntrinsic value_intrinsic;
        String string_literal;
    };
    TokenId id;
};

enum class Precedence
{
    none,
    assignment,
    boolean_or,
    boolean_and,
    comparison,
    bitwise,
    shifting,
    add_like,
    div_like,
    prefix,
    aggregate_initialization,
    postfix,
};

struct ValueBuilder
{
    Token token;
    Value* left;
    Precedence precedence;
    ValueKind kind;
    bool allow_assignment_operators;

    inline ValueBuilder with_precedence(Precedence precedence)
    {
        auto result = *this;
        result.precedence = precedence;
        return result;
    }

    inline ValueBuilder with_token(Token token)
    {
        auto result = *this;
        result.token = token;
        return result;
    }

    inline ValueBuilder with_left(Value* value)
    {
        auto result = *this;
        result.left = value;
        return result;
    }

    inline ValueBuilder with_kind(ValueKind kind)
    {
        auto result = *this;
        result.kind = kind;
        return result;
    }
};

global_variable constexpr u8 left_bracket = '[';
global_variable constexpr u8 right_bracket = ']';
global_variable constexpr u8 left_brace = '{';
global_variable constexpr u8 right_brace = '}';
global_variable constexpr u8 left_parenthesis = '(';
global_variable constexpr u8 right_parenthesis = ')';

fn bool is_space(u8 ch)
{
    return ((ch == ' ') | (ch == '\n')) | ((ch == '\t') | (ch == '\r'));
}

fn bool is_lower(u8 ch)
{
    return ((ch >= 'a') & (ch <= 'z'));
}

fn bool is_upper(u8 ch)
{
    return ((ch >= 'A') & (ch <= 'Z'));
}

fn bool is_decimal(u8 ch)
{
    return ((ch >= '0') & (ch <= '9'));
}

fn bool is_octal(u8 ch)
{
    return ((ch >= '0') & (ch <= '7'));
}

fn bool is_binary(u8 ch)
{
    return ((ch == '0') | (ch == '1'));
}

fn bool is_hexadecimal_alpha_lower(u8 ch)
{
    return ((ch >= 'a') & (ch <= 'f'));
}

fn bool is_hexadecimal_alpha_upper(u8 ch)
{
    return ((ch >= 'A') & (ch <= 'F'));
}

fn bool is_hexadecimal_alpha(u8 ch)
{
    return is_hexadecimal_alpha_lower(ch) || is_hexadecimal_alpha_upper(ch);
}

fn bool is_hexadecimal(u8 ch)
{
    return is_decimal(ch) || is_hexadecimal_alpha(ch);
}

fn bool is_identifier_start(u8 ch)
{
    return (is_lower(ch) || is_upper(ch)) || (ch == '_');
}

fn bool is_identifier(u8 ch)
{
    return is_identifier_start(ch) || is_decimal(ch);
}

fn u32 get_line(Module* module)
{
    auto line = module->line_offset + 1;
    assert(line < ~(u32)0);
    return (u32)line;
}

fn u32 get_column(Module* module)
{
    auto column = module->offset - module->line_character_offset + 1;
    assert(column < ~(u32)0);
    return (u32)column;
}

struct Checkpoint
{
    u64 offset;
    u64 line_offset;
    u64 line_character_offset;
};

fn Checkpoint get_checkpoint(Module* module)
{
    return {
        .offset = module->offset,
        .line_offset = module->line_offset,
        .line_character_offset = module->line_character_offset,
    };
}

fn void set_checkpoint(Module* module, Checkpoint checkpoint)
{
    module->offset = checkpoint.offset;
    module->line_offset = checkpoint.line_offset;
    module->line_character_offset = checkpoint.line_character_offset;
}

fn bool consume_character_if_match(Module* module, u8 expected_ch)
{
    bool is_ch = false;
    auto i = module->offset;
    if (i < module->content.length)
    {
        auto ch = module->content[i];
        is_ch = expected_ch == ch;
        module->offset = i + is_ch;
    }

    return is_ch;
}

fn void expect_character(Module* module, u8 expected_ch)
{
    if (!consume_character_if_match(module, expected_ch))
    {
        report_error();
    }
}

fn void skip_space(Module* module)
{
    while (1)
    {
        auto iteration_offset = module->offset;

        while (module->offset < module->content.length)
        {
            auto ch = module->content[module->offset];
            if (!is_space(ch))
            {
                break;
            }

            module->line_offset += ch == '\n';
            module->line_character_offset = ch == '\n' ? module->offset : module->line_character_offset;
            module->offset += 1;
        }

        if (module->offset + 1 < module->content.length)
        {
            auto i = module->offset;
            auto first_ch = module->content[i];
            auto second_ch = module->content[i + 1];
            auto is_comment = first_ch == '/' && second_ch == '/';

            if (is_comment)
            {
                while (module->offset < module->content.length)
                {
                    auto ch = module->content[module->offset];
                    if (ch == '\n')
                    {
                        break;
                    }
                    module->offset += 1;
                }

                if (module->offset < module->content.length)
                {
                    module->line_offset += 1;
                    module->line_character_offset = module->offset;
                    module->offset += 1;
                }
            }
        }

        if (module->offset - iteration_offset == 0)
        {
            break;
        }
    }
}

fn String parse_identifier(Module* module)
{
    auto start = module->offset;

    if (is_identifier_start(module->content[start]))
    {
        module->offset = start + 1;

        while (module->offset < module->content.length)
        {
            auto i = module->offset;
            if (is_identifier(module->content[i]))
            {
                module->offset = i + 1;
            }
            else
            {
                break;
            }
        }
    }

    auto end = module->offset;
    if (end - start == 0)
    {
        report_error();
    }

    return module->content(start, end);
}

fn u64 accumulate_hexadecimal(u64 accumulator, u8 ch)
{
    u64 value;

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
        unreachable();
    }

    auto result = (accumulator * 16) + value;
    return result;
}

fn u64 accumulate_decimal(u64 accumulator, u8 ch)
{
    assert(is_decimal(ch));
    return (accumulator * 10) + (ch - '0');
}

fn u64 accumulate_octal(u64 accumulator, u8 ch)
{
    assert(is_octal(ch));
    return (accumulator * 8) + (ch - '0');
}

fn u64 accumulate_binary(u64 accumulator, u8 ch)
{
    assert(is_binary(ch));
    return (accumulator * 2) + (ch - '0');
}

fn u64 parse_integer_decimal_assume_valid(String string)
{
    u64 value = 0;

    for (u8 ch: string)
    {
        assert(is_decimal(ch));
        value = accumulate_decimal(value, ch);
    }

    return value;
}

fn Value* parse_value(Module* module, Scope* scope, ValueBuilder builder);

struct FunctionHeaderArgument
{
    String name;
    u32 line;
};

struct FunctionHeaderParsing
{
    Type* type;
    Slice<FunctionHeaderArgument> arguments;
    FunctionAttributes attributes;
};

fn bool type_function_base_compare(Module* module, TypeFunctionBase& a, TypeFunctionBase& b)
{
    auto same_return_type = resolve_alias(module, a.semantic_return_type) == b.semantic_return_type;
    auto same_calling_convention = a.calling_convention == b.calling_convention;
    auto same_is_variable_arguments = a.is_variable_arguments == b.is_variable_arguments;

    auto same_argument_length = a.semantic_argument_types.length == b.semantic_argument_types.length;
    auto same_argument_types = same_argument_length;

    if (same_argument_length)
    {
        for (u64 i = 0; i < a.semantic_argument_types.length; i += 1)
        {
            auto a_type = resolve_alias(module, a.semantic_argument_types[i]);
            auto b_type = resolve_alias(module, b.semantic_argument_types[i]);

            auto is_same_argument_type = a_type == b_type;

            same_argument_types = same_argument_types && is_same_argument_type;
        }
    }

    return same_return_type && same_calling_convention && same_is_variable_arguments && same_argument_types;
}

fn Type* get_function_type(Module* module, TypeFunctionBase base)
{
    base.semantic_return_type = resolve_alias(module, base.semantic_return_type);
    for (u64 i = 0; i < base.semantic_argument_types.length; i += 1)
    {
        base.semantic_argument_types[i] = resolve_alias(module, base.semantic_argument_types[i]);
    }

    Type* last_function_type = module->first_function_type;

    while (last_function_type)
    {
        assert(last_function_type->id == TypeId::function);
        if (type_function_base_compare(module, base, last_function_type->function.base))
        {
            return last_function_type;
        }

        auto next = last_function_type->function.next;
        if (!next)
        {
            break;
        }

        last_function_type = next;
    }

    auto result = type_allocate_init(module, Type{
        .function = {
            .base = base,
        },
        .id = TypeId::function,
        .name = string_literal(""),
        .scope = &module->scope,
    });

    if (last_function_type)
    {
        assert(module->first_function_type);
        last_function_type->function.next = result;
    }
    else
    {
        assert(!module->first_function_type);
        module->first_function_type = result;
    }

    return result;
}


fn Type* parse_type(Module* module, Scope* scope);
fn FunctionHeaderParsing parse_function_header(Module* module, Scope* scope, bool mandate_argument_names)
{
    auto calling_convention = CallingConvention::c;
    auto function_attributes = FunctionAttributes{};
    bool is_variable_arguments = false;

    if (consume_character_if_match(module, left_bracket))
    {
        while (module->offset < module->content.length)
        {
            auto function_identifier = parse_identifier(module);

            enum class FunctionKeyword
            {
                cc,
                count,
            };

            String function_keywords[] = {
                string_literal("cc"),
            };
            static_assert(array_length(function_keywords) == (u64)FunctionKeyword::count);

            backing_type(FunctionKeyword) i;
            for (i = 0; i < (backing_type(FunctionKeyword))(FunctionKeyword::count); i += 1)
            {
                auto function_keyword = function_keywords[i];
                if (function_keyword.equal(function_identifier))
                {
                    break;
                }
            }

            auto function_keyword = (FunctionKeyword)i;
            skip_space(module);

            switch (function_keyword)
            {
                case FunctionKeyword::cc:
                    {
                        expect_character(module, left_parenthesis);
                        skip_space(module);
                        auto calling_convention_string = parse_identifier(module);
                        String calling_conventions[] = {
                            string_literal("c"),
                        };
                        static_assert(array_length(calling_conventions) == (u64)CallingConvention::count);

                        backing_type(CallingConvention) i;
                        for (i = 0; i < (backing_type(CallingConvention))CallingConvention::count; i += 1)
                        {
                            auto calling_convention = calling_conventions[i];
                            if (calling_convention.equal(calling_convention_string))
                            {
                                break;
                            }
                        }

                        auto candidate_calling_convention = (CallingConvention)i;
                        if (candidate_calling_convention == CallingConvention::count)
                        {
                            report_error();
                        }

                        calling_convention = candidate_calling_convention;

                        skip_space(module);
                        expect_character(module, right_parenthesis);
                    } break;
                case FunctionKeyword::count:
                    {
                        report_error();
                    } break;
            }

            skip_space(module);

            if (consume_character_if_match(module, right_bracket))
            {
                break;
            }
            else
            {
                report_error();
            }
        }
    }

    skip_space(module);

    expect_character(module, left_parenthesis);

    Type* semantic_argument_type_buffer[64];
    String semantic_argument_name_buffer[64];
    u32 argument_line_buffer[64];
    u32 semantic_argument_count = 0;

    while (module->offset < module->content.length)
    {
        skip_space(module);

        if (consume_character_if_match(module, '.'))
        {
            expect_character(module, '.');
            expect_character(module, '.');
            skip_space(module);
            expect_character(module, right_parenthesis);
            is_variable_arguments = true;
            break;
        }

        if (consume_character_if_match(module, right_parenthesis))
        {
            break;
        }

        auto line = get_line(module);
        argument_line_buffer[semantic_argument_count] = line;

        String argument_name = {};

        if (mandate_argument_names)
        {
            argument_name = parse_identifier(module);

            skip_space(module);

            expect_character(module, ':');

            skip_space(module);
        }

        semantic_argument_name_buffer[semantic_argument_count] = argument_name;

        auto argument_type = parse_type(module, scope);
        semantic_argument_type_buffer[semantic_argument_count] = argument_type;

        skip_space(module);

        unused(consume_character_if_match(module, ','));

        semantic_argument_count += 1;
    }

    skip_space(module);

    auto return_type = parse_type(module, scope);

    skip_space(module);

    Slice<Type*> argument_types = {};
    if (semantic_argument_count != 0)
    {
        argument_types = new_type_array(module, semantic_argument_count);
        memcpy(argument_types.pointer, semantic_argument_type_buffer, semantic_argument_count * sizeof(Type*));
    }

    auto function_type = get_function_type(module, {
        .semantic_return_type = return_type,
        .semantic_argument_types = argument_types,
        .calling_convention = calling_convention,
        .is_variable_arguments = is_variable_arguments,
    });

    Slice<FunctionHeaderArgument> arguments = {};
    if (mandate_argument_names)
    {
        arguments = arena_allocate<FunctionHeaderArgument>(module->arena, semantic_argument_count);
        for (u64 i = 0; i < semantic_argument_count; i += 1)
        {
            arguments[i] = {
                .name = semantic_argument_name_buffer[i],
                .line = argument_line_buffer[i],
            };
        }
    }

    return {
        .type = function_type,
        .arguments = arguments,
        .attributes = function_attributes,
    };
}

fn Type* parse_type(Module* module, Scope* scope)
{
    auto start_character = module->content[module->offset];
    if (is_identifier_start(start_character))
    {
        auto identifier = parse_identifier(module);
        if (identifier.equal(string_literal("void")))
        {
            return void_type(module);
        }
        else if (identifier.equal(string_literal("noreturn")))
        {
            return noreturn_type(module);
        }
        else if (identifier.equal(string_literal("enum_array")))
        {
            skip_space(module);
            expect_character(module, left_bracket);
            auto enum_type = parse_type(module, scope);
            expect_character(module, right_bracket);

            expect_character(module, left_parenthesis);
            auto element_type = parse_type(module, scope);
            expect_character(module, right_parenthesis);

            auto enum_array_type = get_enum_array_type(module, enum_type, element_type);
            return enum_array_type;
        }
        else if (identifier.equal(string_literal("fn")))
        {
            skip_space(module);
            auto mandate_argument_names = false;
            auto function_header = parse_function_header(module, scope, mandate_argument_names);
            auto result = function_header.type;
            return result;
        }
        else
        {
            auto is_int_type = identifier.length > 1 && (identifier[0] == 's' || identifier[0] == 'u');

            if (is_int_type)
            {
                for (auto ch : identifier(1))
                {
                    is_int_type = is_int_type && is_decimal(ch);
                }
            }

            if (is_int_type)
            {
                bool is_signed;
                switch (identifier[0])
                {
                    case 's': is_signed = true; break;
                    case 'u': is_signed = false; break;
                    default: unreachable();
                }

                auto bit_count = parse_integer_decimal_assume_valid(identifier(1));
                if (bit_count == 0)
                {
                    report_error();
                }
                if (bit_count > 64)
                {
                    if (bit_count != 128)
                    {
                        report_error();
                    }
                }

                auto result = integer_type(module, { .bit_count = (u32)bit_count, .is_signed = is_signed });
                return result;
            }
            else
            {
                assert(scope);
                auto it_scope = scope;
                while (it_scope)
                {
                    for (Type* type = it_scope->types.first; type; type = type->next)
                    {
                        if (identifier.equal(type->name))
                        {
                            return type;
                        }
                    }

                    it_scope = it_scope->parent;
                }

                report_error();
            }
        }
    }
    else if (start_character == '&')
    {
        module->offset += 1;
        skip_space(module);
        auto element_type = parse_type(module, scope);
        auto pointer_type = get_pointer_type(module, element_type);
        return pointer_type;
    }
    else if (start_character == left_bracket)
    {
        module->offset += 1;
        skip_space(module);

        auto is_slice = consume_character_if_match(module, right_bracket);
        if (is_slice)
        {
            skip_space(module);
            auto element_type = parse_type(module, scope);
            auto slice_type = get_slice_type(module, element_type);
            return slice_type;
        }
        else
        {
            bool length_inferred = false;
            auto checkpoint = get_checkpoint(module);
            if (consume_character_if_match(module, '_'))
            {
                skip_space(module);

                length_inferred = consume_character_if_match(module, ']');
            }

            Value* length_value = 0;
            u64 element_count = 0;
            bool resolved = false;
            if (!length_inferred)
            {
                set_checkpoint(module, checkpoint);

                length_value = parse_value(module, scope, {});
                assert(length_value);

                if (length_value->is_constant())
                {
                    switch (length_value->id)
                    {
                        case ValueId::constant_integer:
                            {
                                element_count = length_value->constant_integer.value;
                                if (element_count == 0)
                                {
                                    report_error();
                                }
                                resolved = true;
                            } break;
                        default:
                            {
                                report_error();
                            } break;
                    }
                }

                skip_space(module);
                expect_character(module, right_bracket);
            }

            skip_space(module);

            auto element_type = parse_type(module, scope);

            if (length_inferred)
            {
                assert(!length_value);
                auto result = type_allocate_init(module, {
                    .array = {
                        .element_type = element_type,
                        .element_count = 0,
                    },
                    .id = TypeId::array,
                    .name = string_literal(""),
                    .scope = element_type->scope,
                });

                return result;
            }
            else
            {
                if (!resolved)
                {
                    report_error();
                }

                assert(element_count != 0);

                auto array_type = get_array_type(module, element_type, element_count);
                return array_type;
            }
        }
    }
    else if (start_character == '#')
    {
        module->offset += 1;
        auto identifier = parse_identifier(module);
        enum class TypeIntrinsic
        {
            return_type,
            count,
        };

        String type_intrinsics[] = {
            string_literal("ReturnType"),
        };

        static_assert(array_length(type_intrinsics) == (u64)TypeIntrinsic::count);

        backing_type(TypeIntrinsic) i;
        for (i = 0; i < (backing_type(TypeIntrinsic))TypeIntrinsic::count; i += 1)
        {
            String type_intrinsic = type_intrinsics[i];
            if (identifier.equal(type_intrinsic))
            {
                break;
            }
        }

        auto intrinsic = (TypeIntrinsic)i;
        switch (intrinsic)
        {
            case TypeIntrinsic::return_type:
                {
                    auto return_type = module->current_function->variable.type->function.base.semantic_return_type;
                    return return_type;
                } break;
            case TypeIntrinsic::count: report_error();
        }
    }
    else
    {
        report_error();
    }
}

fn u64 parse_hexadecimal(Module* module)
{
    u64 value = 0;

    while (true)
    {
        auto ch = module->content[module->offset];

        if (!is_hexadecimal(ch))
        {
            break;
        }

        module->offset += 1;
        value = accumulate_hexadecimal(value, ch);
    }

    return value;
}

fn u64 parse_decimal(Module* module)
{
    u64 value = 0;

    while (true)
    {
        auto ch = module->content[module->offset];

        if (!is_decimal(ch))
        {
            break;
        }

        module->offset += 1;
        value = accumulate_decimal(value, ch);
    }

    return value;
}

fn u64 parse_octal(Module* module)
{
    u64 value = 0;

    while (true)
    {
        auto ch = module->content[module->offset];

        if (!is_octal(ch))
        {
            break;
        }

        module->offset += 1;
        value = accumulate_octal(value, ch);
    }

    return value;
}

fn u64 parse_binary(Module* module)
{
    u64 value = 0;

    while (true)
    {
        auto ch = module->content[module->offset];

        if (!is_binary(ch))
        {
            break;
        }

        module->offset += 1;
        value = accumulate_binary(value, ch);
    }

    return value;
}

fn u8 escape_character(u8 ch)
{
    switch (ch)
    {
        case 'n': return '\n';
        case 't': return '\t';
        case 'r': return '\r';
        case '\'': return '\'';
        default: report_error();
    }
}

fn String parse_string_literal(Module* module)
{
    expect_character(module, '"');

    auto start = module->offset;
    u64 escape_character_count = 0;

    while (1)
    {
        auto ch = module->content[module->offset];
        if (ch == '"')
        {
            break;
        }
        escape_character_count += ch == '\\';
        module->offset += 1;
    }

    auto end = module->offset;
    auto length = end - start - escape_character_count;
    auto pointer = (u8*)arena_allocate_bytes(module->arena, length + 1, 1);
    auto string_literal = String{ .pointer = pointer, .length = length };

    for (u64 source_i = start, i = 0; source_i < end; source_i += 1, i += 1)
    {
        auto ch = module->content[source_i];
        if (ch == '\\')
        {
            source_i += 1;
            ch = module->content[source_i];
            string_literal[i] = escape_character(ch);
        }
        else
        {
            string_literal[i] = ch;
        }
    }

    expect_character(module, '"');

    return string_literal;
}

fn Token tokenize(Module* module)
{
    skip_space(module);

    auto start_index = module->offset;
    if (start_index == module->content.length)
    {
        report_error();
    }

    auto start_character = module->content[start_index];

    Token token;

    switch (start_character)
    {
        case ',':
        case ';':
        case '~':
        case left_brace:
        case left_parenthesis:
        case left_bracket:
        case right_brace:
        case right_parenthesis:
        case right_bracket:
            {
                module->offset += 1;
                TokenId id;
                switch (start_character)
                {
                    case ',': id = TokenId::comma; break;
                    case ';': id = TokenId::end_of_statement; break;
                    case '~': id = TokenId::tilde; break;
                    case left_brace: id = TokenId::left_brace; break;
                    case left_parenthesis: id = TokenId::left_parenthesis; break;
                    case left_bracket: id = TokenId::left_bracket; break;
                    case right_brace: id = TokenId::right_brace; break;
                    case right_parenthesis: id = TokenId::right_parenthesis; break;
                    case right_bracket: id = TokenId::right_bracket; break;
                    default: unreachable();
                }
                token = {
                    .id = id,
                };
            } break;
        case '#':
            {
                module->offset += 1;
                if (is_identifier_start(module->content[module->offset]))
                {
                    auto identifier = parse_identifier(module);

                    String value_intrinsics[] = {
                        string_literal("align_of"),
                        string_literal("build_mode"),
                        string_literal("byte_size"),
                        string_literal("enum_from_int"),
                        string_literal("enum_name"),
                        string_literal("enum_values"),
                        string_literal("extend"),
                        string_literal("field_parent_pointer"),
                        string_literal("has_debug_info"),
                        string_literal("integer_max"),
                        string_literal("int_from_enum"),
                        string_literal("int_from_pointer"),
                        string_literal("max"),
                        string_literal("min"),
                        string_literal("pointer_cast"),
                        string_literal("pointer_from_int"),
                        string_literal("select"),
                        string_literal("string_to_enum"),
                        string_literal("trap"),
                        string_literal("truncate"),
                        string_literal("va_start"),
                        string_literal("va_end"),
                        string_literal("va_arg"),
                        string_literal("va_copy"),
                    };
                    static_assert(array_length(value_intrinsics) == (u64)ValueIntrinsic::count);

                    backing_type(ValueIntrinsic) i;
                    for (i = 0; i < (backing_type(ValueIntrinsic))(ValueIntrinsic::count); i += 1)
                    {
                        String candidate = value_intrinsics[i];
                        if (identifier.equal(candidate))
                        {
                            break;
                        }
                    }

                    auto intrinsic = (ValueIntrinsic)i;
                    if (intrinsic == ValueIntrinsic::count)
                    {
                        report_error();
                    }

                    token = {
                        .value_intrinsic = intrinsic,
                        .id = TokenId::value_intrinsic,
                    };
                }
                else
                {
                    trap();
                }
            } break;
        case '<':
            {
                auto next_ch = module->content[start_index + 1];
                TokenId id;
                switch (next_ch)
                {
                    case '<':
                        switch (module->content[start_index + 2])
                        {
                            case '=': id = TokenId::assign_shift_left; break;
                            default: id = TokenId::shift_left; break;
                        } break;
                    case '=': id = TokenId::compare_less_equal; break;
                    default: id = TokenId::compare_less; break;
                }

                u64 add;
                switch (id)
                {
                    case TokenId::assign_shift_left: add = 3; break;
                    case TokenId::shift_left:
                    case TokenId::compare_less_equal: add = 2; break;
                    case TokenId::compare_less: add = 1; break;
                    default: unreachable();
                }

                module->offset += add;
                token = {
                    .id = id,
                };
            } break;
        case '>':
            {
                auto next_ch = module->content[start_index + 1];
                TokenId id;
                switch (next_ch)
                {
                    case '>':
                        switch (module->content[start_index + 2])
                        {
                            case '=': id = TokenId::assign_shift_right; break;
                            default: id = TokenId::shift_right; break;
                        } break;
                    case '=': id = TokenId::compare_greater_equal; break;
                    default: id = TokenId::compare_greater; break;
                }

                u64 add;
                switch (id)
                {
                    case TokenId::assign_shift_right: add = 3; break;
                    case TokenId::shift_right:
                    case TokenId::compare_greater_equal: add = 2; break;
                    case TokenId::compare_greater: add = 1; break;
                    default: unreachable();
                }

                module->offset += add;
                token = {
                    .id = id,
                };
            } break;
        case '=':
            {
                auto next_ch = module->content[start_index + 1];
                auto is_compare_equal = next_ch == '=';
                TokenId id = is_compare_equal ? TokenId::compare_equal : TokenId::assign;
                module->offset += is_compare_equal + 1;
                token = {
                    .id = id,
                };
            } break;
        case '.':
            {
                auto next_ch = module->content[start_index + 1];
                TokenId id;
                switch (next_ch)
                {
                    default: id = TokenId::dot; break;
                    case '&': id = TokenId::pointer_dereference; break;
                    case '.':
                        switch (module->content[start_index + 2])
                        {
                            case '.': id = TokenId::triple_dot; break;
                            default: id = TokenId::double_dot; break;
                        } break;
                }

                u64 add;
                switch (id)
                {
                    case TokenId::dot: add = 1; break;
                    case TokenId::double_dot: add = 2; break;
                    case TokenId::triple_dot: add = 3; break;
                    case TokenId::pointer_dereference: add = 2; break;
                    default: unreachable();
                }
                module->offset += add;

                token = {
                    .id = id,
                };
            } break;
        case '"':
            {
                auto string_literal = parse_string_literal(module);

                token = {
                    .string_literal = string_literal,
                    .id = TokenId::string_literal,
                };
            } break;
        case '\'':
            {
                module->offset += 1;

                u8 ch;
                if (module->content[module->offset] == '\\')
                {
                    module->offset += 1;
                    ch = escape_character(module->content[module->offset]);
                }
                else
                {
                    ch = module->content[module->offset];
                    if (ch == '\'')
                    {
                        report_error();
                    }
                }

                module->offset += 1;
                expect_character(module, '\'');
                token = Token{
                    .integer = {
                        .value = ch,
                        .kind = TokenIntegerKind::character_literal,
                    },
                    .id = TokenId::integer,
                };
            } break;
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            {
                auto next_ch = module->content[start_index + 1];
                TokenIntegerKind token_integer_kind = TokenIntegerKind::decimal;
                if (start_character == '0')
                {
                    switch (next_ch)
                    {
                        case 'x': token_integer_kind = TokenIntegerKind::hexadecimal; break;
                        case 'd': token_integer_kind = TokenIntegerKind::decimal; break;
                        case 'o': token_integer_kind = TokenIntegerKind::octal; break;
                        case 'b': token_integer_kind = TokenIntegerKind::binary; break;
                        default: token_integer_kind = TokenIntegerKind::decimal; break;
                    }
                    auto inferred_decimal = token_integer_kind == TokenIntegerKind::decimal && next_ch != 'd';
                    module->offset += 2 * (token_integer_kind != TokenIntegerKind::decimal || !inferred_decimal);
                }

                u64 value;
                switch (token_integer_kind)
                {
                    case TokenIntegerKind::hexadecimal: value = parse_hexadecimal(module); break;
                    case TokenIntegerKind::decimal: value = parse_decimal(module); break;
                    case TokenIntegerKind::octal: value = parse_octal(module); break;
                    case TokenIntegerKind::binary: value = parse_binary(module); break;
                    case TokenIntegerKind::character_literal: report_error(); break;
                }

                token = {
                    .integer = {
                        .value = value,
                        .kind = token_integer_kind,
                    },
                    .id = TokenId::integer,
                };
            } break;
        case '+':
        case '-':
        case '*':
        case '/':
        case '%':
        case '&':
        case '|':
        case '^':
        case '!':
            {
                auto next_ch = module->content[start_index + 1];
                TokenId id;
                if (next_ch == '=')
                {
                    switch (start_character)
                    {
                        case '+': id = TokenId::assign_plus; break;
                        case '-': id = TokenId::assign_dash; break;
                        case '*': id = TokenId::assign_asterisk; break;
                        case '/': id = TokenId::assign_forward_slash; break;
                        case '%': id = TokenId::assign_percentage; break;
                        case '&': id = TokenId::assign_ampersand; break;
                        case '|': id = TokenId::assign_bar; break;
                        case '^': id = TokenId::assign_caret; break;
                        case '!': id = TokenId::compare_not_equal; break;
                        default: unreachable();
                    }
                }
                else
                {
                    switch (start_character)
                    {
                        case '+': id = TokenId::plus; break;
                        case '-': id = TokenId::dash; break;
                        case '*': id = TokenId::asterisk; break;
                        case '/': id = TokenId::forward_slash; break;
                        case '%': id = TokenId::percentage; break;
                        case '&': id = TokenId::ampersand; break;
                        case '|': id = TokenId::bar; break;
                        case '^': id = TokenId::caret; break;
                        case '!': id = TokenId::exclamation; break;
                        default: unreachable();
                    }
                }

                token.id = id;

                module->offset += 1 + (next_ch == '=');
            } break;
        default:
            {
                if (is_identifier_start(start_character))
                {
                    auto identifier = parse_identifier(module);

                    String value_keywords[] = {
                        string_literal("undefined"),
                        string_literal("unreachable"),
                        string_literal("zero"),
                    };
                    static_assert(array_length(value_keywords) == (u64)ValueKeyword::count);

                    backing_type(ValueKeyword) i;
                    for (i = 0; i < (backing_type(ValueKeyword))ValueKeyword::count; i += 1)
                    {
                        String candidate = value_keywords[i];
                        if (candidate.equal(identifier))
                        {
                            break;
                        }
                    }

                    auto value_keyword = (ValueKeyword)i;

                    if (value_keyword == ValueKeyword::count)
                    {
                        auto advance = identifier.pointer[identifier.length] == '?';
                        identifier.length += advance;
                        module->offset += advance;

                        String operators[] = {
                            string_literal("and"),
                            string_literal("or"),
                            string_literal("and?"),
                            string_literal("or?"),
                        };
                        static_assert(array_length(operators) == (u64)OperatorKeyword::count);

                        backing_type(OperatorKeyword) i;
                        for (i = 0; i < (backing_type(OperatorKeyword))OperatorKeyword::count; i += 1)
                        {
                            auto candidate = operators[i];
                            if (candidate.equal(identifier))
                            {
                                break;
                            }
                        }

                        auto operator_keyword = (OperatorKeyword)i;
                        if (operator_keyword == OperatorKeyword::count)
                        {
                            identifier.length -= advance;
                            module->offset -= advance;
                            
                            token = {
                                .identifier = identifier,
                                .id = TokenId::identifier,
                            };
                        }
                        else
                        {
                            token = {
                                .operator_keyword = operator_keyword,
                                .id = TokenId::operator_keyword,
                            };
                        }
                    }
                    else
                    {
                        token = {
                            .value_keyword = value_keyword,
                            .id = TokenId::value_keyword,
                        };
                    }
                }
                else
                {
                    report_error();
                }
            } break;
    }

    assert(start_index != module->offset);
    return token;
}

fn Value* parse_value(Module* module, Scope* scope, ValueBuilder builder);

fn Value* parse_aggregate_initialization(Module* module, Scope* scope, ValueBuilder builder, u8 end_ch)
{
    skip_space(module);

    u64 field_count = 0;

    AggregateInitializationElement element_buffer[64];
    bool zero = false;

    while (1)
    {
        skip_space(module);

        if (consume_character_if_match(module, end_ch))
        {
            break;
        }

        auto field_index = field_count;
        auto checkpoint = get_checkpoint(module);
        if (consume_character_if_match(module, '.'))
        {
            auto name = parse_identifier(module);
            skip_space(module);
            expect_character(module, '=');
            skip_space(module);

            auto line = get_line(module);
            auto column = get_column(module);

            auto value = parse_value(module, scope, {});
            skip_space(module);
            consume_character_if_match(module, ',');

            element_buffer[field_index] = {
                .name = name,
                .value = value,
                .line = line,
                .column = column,
            };
        }
        else
        {
            auto token = tokenize(module);
            zero = token.id == TokenId::value_keyword && token.value_keyword == ValueKeyword::zero;
            if (zero)
            {
                skip_space(module);

                if (consume_character_if_match(module, ','))
                {
                    skip_space(module);
                }

                expect_character(module, right_brace);
                break;
            }
            else
            {
                report_error();
            }
        }

        field_count += 1;
    }

    auto elements = arena_allocate<AggregateInitializationElement>(module->arena, field_count);
    memcpy(elements.pointer, element_buffer, sizeof(element_buffer[0]) * field_count);

    auto result = new_value(module);
    *result = {
        .aggregate_initialization = {
            .elements = elements,
            .scope = scope,
            .is_constant = false,
            .zero = zero,
        },
        .id = ValueId::aggregate_initialization,
        .kind = builder.kind,
    };

    return result;
}

fn Value* parse_precedence(Module* module, Scope* scope, ValueBuilder builder);
fn Value* parse_left(Module* module, Scope* scope, ValueBuilder builder)
{
    Token token = builder.token;
    Value* result;
    switch (token.id)
    {
        case TokenId::integer:
            {
                auto integer_value = token.integer.value;
                result = new_value(module);
                *result = {
                    .constant_integer = {
                        .value = integer_value,
                        .is_signed = false,
                    },
                    .id = ValueId::constant_integer,
                    .kind = ValueKind::right,
                };
            } break;
        case TokenId::dash:
        case TokenId::ampersand:
        case TokenId::exclamation:
        case TokenId::tilde:
            // Unary
            {
                assert(!builder.left);
                UnaryId id;
                switch (token.id)
                {
                    case TokenId::dash: id = UnaryId::minus; break;
                    case TokenId::ampersand: id = UnaryId::ampersand; break;
                    case TokenId::exclamation: id = UnaryId::exclamation; break;
                    case TokenId::tilde: id = UnaryId::bitwise_not; break;
                    default: unreachable();
                }

                auto unary_value = parse_precedence(module, scope, builder.with_precedence(Precedence::prefix).with_token({}).with_kind(token.id == TokenId::ampersand ? ValueKind::left : builder.kind));

                result = new_value(module);
                *result = {
                    .unary = {
                        .value = unary_value,
                        .id = id,
                    },
                    .id = ValueId::unary,
                    .kind = ValueKind::right,
                };
            } break;
        case TokenId::identifier:
            {
                result = reference_identifier(module, scope, token.identifier, builder.kind);
            } break;
        case TokenId::value_intrinsic:
            {
                ValueIntrinsic intrinsic = token.value_intrinsic;
                result = new_value(module);

                switch (intrinsic)
                {
                    case ValueIntrinsic::enum_from_int:
                    case ValueIntrinsic::enum_name:
                    case ValueIntrinsic::extend:
                    case ValueIntrinsic::int_from_enum:
                    case ValueIntrinsic::int_from_pointer:
                    case ValueIntrinsic::truncate:
                    case ValueIntrinsic::pointer_cast:
                    case ValueIntrinsic::pointer_from_int:
                    case ValueIntrinsic::va_end:
                        {
                            UnaryId id;
                            switch (intrinsic)
                            {
                                case ValueIntrinsic::enum_from_int: id = UnaryId::enum_from_int; break;
                                case ValueIntrinsic::enum_name: id = UnaryId::enum_name; break;
                                case ValueIntrinsic::extend: id = UnaryId::extend; break;
                                case ValueIntrinsic::int_from_enum: id = UnaryId::int_from_enum; break;
                                case ValueIntrinsic::int_from_pointer: id = UnaryId::int_from_pointer; break;
                                case ValueIntrinsic::truncate: id = UnaryId::truncate; break;
                                case ValueIntrinsic::pointer_cast: id = UnaryId::pointer_cast; break;
                                case ValueIntrinsic::pointer_from_int: id = UnaryId::pointer_from_int; break;
                                case ValueIntrinsic::va_end: id = UnaryId::va_end; break;
                                default: unreachable();
                            }

                            skip_space(module);
                            expect_character(module, left_parenthesis);
                            skip_space(module);
                            auto argument = parse_value(module, scope, {});
                            expect_character(module, right_parenthesis);

                            *result = {
                                .unary = {
                                    .value = argument,
                                    .id = id,
                                },
                                .id = ValueId::unary,
                            };
                        } break;
                    case ValueIntrinsic::align_of:
                    case ValueIntrinsic::byte_size:
                    case ValueIntrinsic::enum_values:
                    case ValueIntrinsic::integer_max:
                        {
                            skip_space(module);
                            expect_character(module, left_parenthesis);
                            skip_space(module);

                            auto type = parse_type(module, scope);

                            expect_character(module, right_parenthesis);

                            UnaryTypeId id;
                            switch (intrinsic)
                            {
                                case ValueIntrinsic::align_of: id = UnaryTypeId::align_of; break;
                                case ValueIntrinsic::byte_size: id = UnaryTypeId::byte_size; break;
                                case ValueIntrinsic::enum_values: id = UnaryTypeId::enum_values; break;
                                case ValueIntrinsic::integer_max: id = UnaryTypeId::integer_max; break;
                                default: unreachable();
                            }

                            *result = {
                                .unary_type = {
                                    .type = type,
                                    .id = id,
                                },
                                .id = ValueId::unary_type,
                            };
                        } break;
                    case ValueIntrinsic::select:
                        {
                            skip_space(module);
                            expect_character(module, left_parenthesis);
                            skip_space(module);

                            auto condition = parse_value(module, scope, {});

                            expect_character(module, ',');
                            skip_space(module);

                            auto true_value = parse_value(module, scope, {});

                            expect_character(module, ',');
                            skip_space(module);

                            auto false_value = parse_value(module, scope, {});

                            skip_space(module);
                            expect_character(module, right_parenthesis);

                            *result = {
                                .select = {
                                    .condition = condition,
                                    .true_value = true_value,
                                    .false_value = false_value,
                                },
                                .id = ValueId::select,
                            };
                        } break;
                    case ValueIntrinsic::string_to_enum:
                        {
                            skip_space(module);
                            expect_character(module, left_parenthesis);
                            skip_space(module);

                            auto type = parse_type(module, scope);

                            skip_space(module);
                            expect_character(module, ',');
                            skip_space(module);

                            auto string_value = parse_value(module, scope, {});

                            skip_space(module);
                            expect_character(module, right_parenthesis);
                            *result = {
                                .string_to_enum = {
                                    .type = type,
                                    .string = string_value,
                                },
                                .id = ValueId::string_to_enum,
                            };
                        } break;
                    case ValueIntrinsic::trap:
                    case ValueIntrinsic::va_start:
                    case ValueIntrinsic::has_debug_info:
                        {
                            skip_space(module);
                            expect_character(module, left_parenthesis);
                            skip_space(module);
                            expect_character(module, right_parenthesis);

                            ValueId id;
                            switch (intrinsic)
                            {
                                case ValueIntrinsic::trap: id = ValueId::trap; break;
                                case ValueIntrinsic::va_start: id = ValueId::va_start; break;
                                case ValueIntrinsic::has_debug_info: id = ValueId::has_debug_info; break;
                                default: unreachable();
                            }
                            *result = {
                                .id = id,
                            };
                        } break;
                    case ValueIntrinsic::va_arg:
                        {
                            skip_space(module);
                            expect_character(module, left_parenthesis);
                            skip_space(module);
                            auto valist = parse_value(module, scope, {});
                            skip_space(module);
                            expect_character(module, ',');
                            skip_space(module);
                            auto ty = parse_type(module, scope);
                            skip_space(module);
                            expect_character(module, right_parenthesis);
                            *result = {
                                .va_arg = {
                                    .va_list = valist,
                                    .type = ty,
                                },
                                .id = ValueId::va_arg,
                            };
                        } break;
                    case ValueIntrinsic::va_copy:
                        {
                            trap();
                        } break;
                    case ValueIntrinsic::min:
                    case ValueIntrinsic::max:
                        {
                            skip_space(module);
                            expect_character(module, left_parenthesis);
                            skip_space(module);
                            auto left = parse_value(module, scope, {});
                            skip_space(module);
                            expect_character(module, ',');
                            skip_space(module);
                            auto right = parse_value(module, scope, {});
                            skip_space(module);
                            expect_character(module, right_parenthesis);

                            BinaryId binary_id;
                            switch (intrinsic)
                            {
                                case ValueIntrinsic::max: binary_id = BinaryId::max; break;
                                case ValueIntrinsic::min: binary_id = BinaryId::min; break;
                                default: unreachable();
                            }

                            *result = {
                                .binary = {
                                    .left = left,
                                    .right = right,
                                    .id = binary_id,
                                },
                                .id = ValueId::binary,
                            };
                        } break;
                    case ValueIntrinsic::build_mode:
                        {
                            *result = {
                                .id = ValueId::build_mode,
                            };
                        } break;
                    case ValueIntrinsic::field_parent_pointer:
                        {
                            skip_space(module);
                            expect_character(module, left_parenthesis);

                            auto field_pointer = parse_value(module, scope, {});

                            skip_space(module);
                            expect_character(module, ',');
                            skip_space(module);

                            auto field_name = parse_string_literal(module);

                            skip_space(module);
                            expect_character(module, right_parenthesis);

                            *result = {
                                .field_parent_pointer = {
                                    .pointer = field_pointer,
                                    .name = field_name,
                                },
                                .id = ValueId::field_parent_pointer,
                            };
                        } break;
                    case ValueIntrinsic::count: unreachable();
                }
            } break;
        case TokenId::left_bracket:
            {
                u64 element_count = 0;
                Value* value_buffer[64];

                skip_space(module);

                auto checkpoint = get_checkpoint(module);
                bool is_aggregate_initialization = false;
                if (consume_character_if_match(module, '.'))
                {
                    auto identifier = parse_identifier(module);

                    skip_space(module);
                    is_aggregate_initialization = consume_character_if_match(module, '=');
                    if (!is_aggregate_initialization)
                    {
                        if (!consume_character_if_match(module, ','))
                        {
                            report_error();
                        }
                    }
                }

                set_checkpoint(module, checkpoint);

                if (is_aggregate_initialization)
                {
                    result = parse_aggregate_initialization(module, scope, builder, right_bracket);
                }
                else
                {
                    while (1)
                    {
                        skip_space(module);

                        if (consume_character_if_match(module, right_bracket))
                        {
                            break;
                        }

                        auto value = parse_value(module, scope, {});
                        value_buffer[element_count] = value;
                        element_count += 1;

                        consume_character_if_match(module, ',');
                    }

                    auto values = new_value_array(module, element_count);
                    memcpy(values.pointer, value_buffer, element_count * sizeof(Value*));

                    result = new_value(module);
                    *result = {
                        .array_initialization = {
                            .values = values,
                            .is_constant = false, // This is analyzed later
                        },
                        .id = ValueId::array_initialization,
                    };
                }
            } break;
        case TokenId::dot:
            {
                auto identifier = parse_identifier(module);
                result = new_value(module);

                *result = {
                    .enum_literal = identifier,
                    .id = ValueId::enum_literal,
                };
            } break;
        case TokenId::left_parenthesis:
            {
                result = parse_value(module, scope, {
                    .kind = builder.kind,
                });
                expect_character(module, right_parenthesis);
            } break;
        case TokenId::string_literal:
            {
                result = new_value(module);
                *result = {
                    .string_literal = token.string_literal,
                    .id = ValueId::string_literal,
                };
            } break;
        case TokenId::left_brace:
            {
                result = parse_aggregate_initialization(module, scope, builder, right_brace);
            } break;
        case TokenId::value_keyword:
            {
                result = new_value(module);
                Value value;
                switch (token.value_keyword)
                {
                    case ValueKeyword::undefined: value = { .id = ValueId::undefined }; break;
                    case ValueKeyword::unreachable: value = { .id = ValueId::unreachable }; break;
                    case ValueKeyword::zero: value = { .id = ValueId::zero }; break;
                    case ValueKeyword::count: unreachable();
                }
                *result = value;
            } break;
        default: report_error();
    }

    return result;
}

fn Precedence get_token_precedence(Token token)
{
    switch (token.id)
    {
        case TokenId::none: unreachable();
        case TokenId::comma:
        case TokenId::double_dot:
        case TokenId::triple_dot:
        case TokenId::end_of_statement:
        case TokenId::right_brace:
        case TokenId::right_bracket:
        case TokenId::right_parenthesis:
            return Precedence::none;
        case TokenId::assign:
        case TokenId::assign_shift_left:
        case TokenId::assign_shift_right:
        case TokenId::assign_plus:
        case TokenId::assign_dash:
        case TokenId::assign_asterisk:
        case TokenId::assign_forward_slash:
        case TokenId::assign_percentage:
        case TokenId::assign_caret:
        case TokenId::assign_bar:
        case TokenId::assign_ampersand:
            return Precedence::assignment;
        case TokenId::operator_keyword: // TODO: check if any other operator that is not bitwise is added
            {
                switch (token.operator_keyword)
                {
                    case OperatorKeyword::and_op:
                    case OperatorKeyword::and_op_shortcircuit:
                        return Precedence::boolean_and;
                    case OperatorKeyword::or_op:
                    case OperatorKeyword::or_op_shortcircuit:
                        return Precedence::boolean_or;
                    case OperatorKeyword::count: unreachable();
                }
            } break;
        case TokenId::compare_equal:
        case TokenId::compare_not_equal:
        case TokenId::compare_less:
        case TokenId::compare_less_equal:
        case TokenId::compare_greater:
        case TokenId::compare_greater_equal:
            return Precedence::comparison;
        case TokenId::ampersand:
        case TokenId::bar:
        case TokenId::caret:
            return Precedence::bitwise;
        case TokenId::shift_left:
        case TokenId::shift_right:
            return Precedence::shifting;
        case TokenId::plus:
        case TokenId::dash:
            return Precedence::add_like;
        case TokenId::asterisk:
        case TokenId::forward_slash:
        case TokenId::percentage:
            return Precedence::div_like;
        case TokenId::pointer_dereference:
        case TokenId::left_parenthesis:
        case TokenId::left_bracket:
        case TokenId::dot:
            return Precedence::postfix;
        default: trap();
    }
}

fn Slice<Value*> parse_call_arguments(Module* module, Scope* scope)
{
    Slice<Value*> arguments = {};

    u32 semantic_argument_count = 0;
    Value* semantic_argument_buffer[64];

    while (1)
    {
        skip_space(module);

        if (consume_character_if_match(module, right_parenthesis))
        {
            break;
        }

        auto argument = parse_value(module, scope, {});
        auto argument_index = semantic_argument_count;
        semantic_argument_buffer[argument_index] = argument;

        skip_space(module);

        consume_character_if_match(module, ',');

        semantic_argument_count += 1;
    }

    if (semantic_argument_count != 0)
    {
        arguments = new_value_array(module, semantic_argument_count);
        memcpy(arguments.pointer, semantic_argument_buffer, semantic_argument_count * sizeof(Value*));
    }

    return arguments;
}

fn Value* parse_right(Module* module, Scope* scope, ValueBuilder builder)
{
    auto* left = builder.left;
    assert(left);

    Token token = builder.token;
    Value* result = 0;

    switch (token.id)
    {
        case TokenId::plus:
        case TokenId::dash:
        case TokenId::asterisk:
        case TokenId::forward_slash:
        case TokenId::percentage:
        case TokenId::ampersand:
        case TokenId::bar:
        case TokenId::caret:
        case TokenId::shift_left:
        case TokenId::shift_right:
        case TokenId::compare_equal:
        case TokenId::compare_not_equal:
        case TokenId::compare_less:
        case TokenId::compare_less_equal:
        case TokenId::compare_greater:
        case TokenId::compare_greater_equal:
        case TokenId::operator_keyword:
            // Binary
            {
                auto precedence = get_token_precedence(token);
                assert(precedence != Precedence::assignment);

                BinaryId id;
                switch (token.id)
                {
                    case TokenId::operator_keyword:
                        switch (token.operator_keyword)
                        {
                            case OperatorKeyword::and_op: id = BinaryId::logical_and; break;
                            case OperatorKeyword::or_op: id = BinaryId::logical_or; break;
                            case OperatorKeyword::and_op_shortcircuit: id = BinaryId::logical_and_shortcircuit; break;
                            case OperatorKeyword::or_op_shortcircuit: id = BinaryId::logical_or_shortcircuit; break;
                            case OperatorKeyword::count: unreachable();
                        } break;
                    case TokenId::plus: id = BinaryId::add; break;
                    case TokenId::dash: id = BinaryId::sub; break;
                    case TokenId::asterisk: id = BinaryId::mul; break;
                    case TokenId::forward_slash: id = BinaryId::div; break;
                    case TokenId::percentage: id = BinaryId::rem; break;
                    case TokenId::ampersand: id = BinaryId::bitwise_and; break;
                    case TokenId::bar: id = BinaryId::bitwise_or; break;
                    case TokenId::caret: id = BinaryId::bitwise_xor; break;
                    case TokenId::shift_left: id = BinaryId::shift_left; break;
                    case TokenId::shift_right: id = BinaryId::shift_right; break;
                    case TokenId::compare_equal: id = BinaryId::compare_equal; break;
                    case TokenId::compare_not_equal: id = BinaryId::compare_not_equal; break;
                    case TokenId::compare_less: id = BinaryId::compare_less; break;
                    case TokenId::compare_less_equal: id = BinaryId::compare_less_equal; break;
                    case TokenId::compare_greater: id = BinaryId::compare_greater; break;
                    case TokenId::compare_greater_equal: id = BinaryId::compare_greater_equal; break;
                    default: unreachable();
                }

                auto right_precedence = (Precedence)((backing_type(Precedence))precedence + (precedence != Precedence::assignment));
                auto right = parse_precedence(module, scope, builder.with_precedence(right_precedence).with_token({}).with_left(0));

                result = new_value(module);
                *result = {
                    .binary = {
                        .left = left,
                        .right = right,
                        .id = id,
                    },
                    .id = ValueId::binary,
                    .kind = ValueKind::right,
                };
            } break;
        case TokenId::pointer_dereference:
            {
                result = new_value(module);
                *result = {
                    .unary = {
                        .value = left,
                        .id = UnaryId::dereference,
                    },
                    .id = ValueId::unary,
                    .kind = ValueKind::right,
                };
            } break;
        case TokenId::left_parenthesis:
            {
                result = new_value(module);
                // Callable
                switch (left->id)
                {
                    case ValueId::macro_reference:
                        {
                            auto* declaration = left->macro_reference;
                            if (declaration->is_generic())
                            {
                                report_error();
                            }

                            auto instantiation_line = get_line(module);
                            auto instantiation_column = get_column(module);

                            auto arguments = parse_call_arguments(module, scope);

                            *result = {
                                .macro_instantiation = {
                                    .declaration = declaration,
                                    .instantiation_function = module->current_function,
                                    .declaration_arguments = {},
                                    .instantiation_arguments = arguments,
                                    .constant_arguments = {},
                                    .return_type = declaration->return_type,
                                    .scope = {
                                        .parent = scope,
                                        .line = declaration->scope.line,
                                        .column = declaration->scope.column,
                                        .kind = ScopeKind::macro_instantiation,
                                    },
                                    .line = instantiation_line,
                                    .column = instantiation_column,
                                },
                                .id = ValueId::macro_instantiation,
                            };
                        } break;
                    default:
                        {
                            auto arguments = parse_call_arguments(module, scope);
                            *result = {
                                .call = {
                                    .callable = left,
                                    .arguments = arguments,
                                },
                                .id = ValueId::call,
                                .kind = ValueKind::right,
                            };
                        } break;
                }
            } break;
        case TokenId::left_bracket:
            {
                skip_space(module);
                result = new_value(module);

                if (left->id == ValueId::macro_reference)
                {
                    auto* declaration = left->macro_reference;
                    if (!declaration->is_generic())
                    {
                        report_error();
                    }

                    auto instantiation_line = get_line(module);
                    auto instantiation_column = get_column(module);
                    auto original_constant_argument_count = declaration->constant_arguments.length;
                    auto constant_arguments = arena_allocate<ConstantArgument>(module->arena, original_constant_argument_count);
                    u64 constant_argument_count = 0;

                    while (1)
                    {
                        skip_space(module);

                        if (consume_character_if_match(module, right_bracket))
                        {
                            break;
                        }

                        auto constant_argument_index = constant_argument_count;
                        if (constant_argument_index == original_constant_argument_count)
                        {
                            report_error();
                        }

                        auto constant_argument = declaration->constant_arguments[constant_argument_index];

                        switch (constant_argument.id)
                        {
                        case ConstantArgumentId::value:
                            {
                                trap(); // TODO
                            } break;
                        case ConstantArgumentId::type:
                            {
                                auto argument_type = parse_type(module, scope);
                                constant_arguments[constant_argument_index] = {
                                    .name = constant_argument.name,
                                    .type = argument_type,
                                    .id = ConstantArgumentId::type,
                                };
                            } break;
                        }

                        constant_argument_count += 1;

                        skip_space(module);
                        consume_character_if_match(module, ',');
                    }

                    skip_space(module);

                    expect_character(module, left_parenthesis);

                    auto instantiation_arguments = parse_call_arguments(module, scope);

                    *result = {
                        .macro_instantiation = {
                            .declaration = declaration,
                            .instantiation_function = module->current_function,
                            .declaration_arguments = {},
                            .instantiation_arguments = instantiation_arguments,
                            .constant_arguments = constant_arguments,
                            .return_type = declaration->return_type,
                            .block = 0,
                            .scope = {
                                .parent = scope,
                                .line = declaration->scope.line,
                                .column = declaration->scope.column,
                                .kind = ScopeKind::macro_instantiation,
                            },
                            .line = instantiation_line,
                            .column = instantiation_column,
                        },
                        .id = ValueId::macro_instantiation,
                    };
                }
                else
                {
                    left->kind = ValueKind::left;

                    Value* start_value = 0;
                    auto start = !(module->content[module->offset] == '.' && module->content[module->offset + 1] == '.');
                    if (start)
                    {
                        start_value = parse_value(module, scope, {});
                    }

                    auto is_array = consume_character_if_match(module, right_bracket);
                    if (is_array)
                    {
                        if (!start_value)
                        {
                            report_error();
                        }

                        auto index = start_value;
                        *result = {
                            .array_expression = {
                                .array_like = left,
                                .index = index,
                            },
                            .id = ValueId::array_expression,
                            .kind = builder.kind,
                        };
                    }
                    else
                    {
                        expect_character(module, '.');
                        expect_character(module, '.');

                        Value* end_value = 0;
                        if (!consume_character_if_match(module, right_bracket))
                        {
                            end_value = parse_value(module, scope, {});
                            expect_character(module, right_bracket);
                        }

                        *result = {
                            .slice_expression = {
                                .array_like = left,
                                .start = start_value,
                                .end = end_value,
                            },
                            .id = ValueId::slice_expression,
                        };
                    }
                }
            } break;
        case TokenId::dot:
            {
                left->kind = ValueKind::left;

                skip_space(module);

                auto identifier = parse_identifier(module);
                result = new_value(module);
                *result = {
                    .field_access = {
                        .aggregate = left,
                        .field_name = identifier,
                    },
                    .id = ValueId::field_access,
                    .kind = builder.kind,
                };
            } break;
        default: report_error();
    }

    return result;
}

fn Value* parse_precedence_left(Module* module, Scope* scope, ValueBuilder builder)
{
    auto result = builder.left;
    auto precedence = builder.precedence;

    while (1)
    {
        auto checkpoint = get_checkpoint(module);
        auto token = tokenize(module);
        auto token_precedence = get_token_precedence(token);
        if (token_precedence == Precedence::assignment)
        {
            token_precedence = builder.allow_assignment_operators ? Precedence::assignment : Precedence::none;
        }

        if ((backing_type(Precedence))precedence > (backing_type(Precedence))token_precedence)
        {
            set_checkpoint(module, checkpoint);
            break;
        }

        auto left = result;
        auto right = parse_right(module, scope, builder.with_token(token).with_precedence(Precedence::none).with_left(left));
        result = right;
    }

    return result;
}

fn Value* parse_precedence(Module* module, Scope* scope, ValueBuilder builder)
{
    assert(builder.token.id == TokenId::none);
    auto token = tokenize(module);
    auto left = parse_left(module, scope, builder.with_token(token));
    auto result = parse_precedence_left(module, scope, builder.with_left(left));
    return result;
}

fn Value* parse_value(Module* module, Scope* scope, ValueBuilder builder)
{
    assert(builder.precedence == Precedence::none);
    assert(!builder.left);
    auto value = parse_precedence(module, scope, builder.with_precedence(Precedence::assignment));
    return value;
}

fn Block* parse_block(Module* module, Scope* parent_scope);

fn void print_value(Value* value, u32 identation)
{
    unused(identation);
    for (u32 i = 0; i < identation; i += 1)
    {
        print(string_literal("  "));
    }

    switch (value->id)
    {
        case ValueId::unary:
            {
                switch (value->unary.id)
                {
                    case UnaryId::extend:
                        {
                            print(string_literal("extend"));
                        } break;
                    default: unreachable();
                }

                print(string_literal("\n"));

                print_value(value->unary.value, identation + 1);
            } break;
        case ValueId::binary:
            {
                switch (value->binary.id)
                {
                    case BinaryId::compare_equal:
                        {
                            print(string_literal("=="));
                        } break;
                    case BinaryId::compare_not_equal:
                        {
                            print(string_literal("!="));
                        } break;
                    case BinaryId::logical_and:
                        {
                            print(string_literal("and"));
                        } break;
                    case BinaryId::logical_or:
                        {
                            print(string_literal("or"));
                        } break;
                    case BinaryId::logical_and_shortcircuit:
                        {
                            print(string_literal("and?"));
                        } break;
                    case BinaryId::logical_or_shortcircuit:
                        {
                            print(string_literal("or?"));
                        } break;
                    default: unreachable();
                }
                print(string_literal("\n"));

                print_value(value->binary.left, identation + 1);
                print_value(value->binary.right, identation + 1);
            } break;
        case ValueId::variable_reference:
            {
                print(value->variable_reference->name);
            } break;
        case ValueId::constant_integer:
            {
                print(string_literal("constant_integer"));
            } break;
        case ValueId::call:
            {
                print(string_literal("call "));
            } break;
        default: unreachable();
    }

    print(string_literal("\n"));
}

fn Statement* parse_statement(Module* module, Scope* scope)
{
    bool require_semicolon = true;

    auto statement_line = get_line(module);
    auto statement_column = get_column(module);

    auto* statement = &arena_allocate<Statement>(module->arena, 1)[0];
    *statement = Statement{
        .line = statement_line,
        .column = statement_column,
    };

    auto statement_start_character = module->content[module->offset];
    switch (statement_start_character)
    {
        case '>':
            {
                module->offset += 1;
                skip_space(module);

                auto local_name = parse_identifier(module);
                skip_space(module);

                Type* local_type = 0;

                if (consume_character_if_match(module, ':'))
                {
                    skip_space(module);
                    local_type = parse_type(module, scope);
                    skip_space(module);
                }
                expect_character(module, '=');
                auto initial_value = parse_value(module, scope, {});

                auto local = new_local(module, scope);
                *local = {
                    .variable = {
                        .storage = 0,
                        .initial_value = initial_value,
                        .type = local_type,
                        .scope = scope,
                        .name = local_name,
                        .line = statement_line,
                        .column = statement_column,
                    },
                };
                statement->local = local;
                statement->id = StatementId::local;
            } break;
        case '#':
            {
                statement->expression = parse_value(module, scope, {});
                statement->id = StatementId::expression;
            } break;
        case left_brace:
            {
                auto block = parse_block(module, scope);
                statement->block = block;
                statement->id = StatementId::block;
                require_semicolon = false;
            } break;
        default:
            {
                if (is_identifier_start(statement_start_character))
                {
                    auto checkpoint = get_checkpoint(module);
                    auto statement_start_identifier = parse_identifier(module);
                    skip_space(module);

                    enum class StatementStartKeyword
                    {
                        underscore_st,
                        return_st,
                        if_st,
                        // TODO: make `unreachable` a statement start keyword?
                        for_st,
                        while_st,
                        switch_st,
                        break_st,
                        continue_st,
                        count,
                    };

                    String statement_start_keywords[] = {
                        string_literal("_"),
                        string_literal("return"),
                        string_literal("if"),
                        string_literal("for"),
                        string_literal("while"),
                        string_literal("switch"),
                        string_literal("break"),
                        string_literal("continue"),
                    };

                    static_assert(array_length(statement_start_keywords) == (u64)StatementStartKeyword::count);

                    backing_type(StatementStartKeyword) i;
                    for (i = 0; i < (backing_type(StatementStartKeyword))StatementStartKeyword::count; i += 1)
                    {
                        auto statement_start_keyword = statement_start_keywords[i];
                        if (statement_start_keyword.equal(statement_start_identifier))
                        {
                            break;
                        }
                    }

                    auto statement_start_keyword = (StatementStartKeyword)i;
                    switch (statement_start_keyword)
                    {
                        case StatementStartKeyword::underscore_st:
                            {
                                trap();
                            } break;
                        case StatementStartKeyword::return_st:
                            {
                                auto return_value = parse_value(module, scope, {});
                                statement->return_st = return_value;
                                statement->id = StatementId::return_st;
                            } break;
                        case StatementStartKeyword::if_st:
                            {
                                skip_space(module);
                                expect_character(module, left_parenthesis);
                                skip_space(module);

                                auto condition = parse_value(module, scope, {});

                                skip_space(module);
                                expect_character(module, right_parenthesis);
                                skip_space(module);

                                auto if_statement = parse_statement(module, scope);

                                skip_space(module);

                                bool is_else = false;
                                Statement* else_statement = 0;
                                if (is_identifier_start(module->content[module->offset]))
                                {
                                    auto checkpoint = get_checkpoint(module);
                                    auto identifier = parse_identifier(module);
                                    is_else = identifier.equal(string_literal("else"));

                                    if (is_else)
                                    {
                                        skip_space(module);
                                        else_statement = parse_statement(module, scope);
                                    }
                                    else
                                    {
                                        set_checkpoint(module, checkpoint);
                                    }
                                }

                                require_semicolon = false;

                                statement->if_st = {
                                    .condition = condition,
                                    .if_statement = if_statement,
                                    .else_statement = else_statement,
                                };
                                statement->id = StatementId::if_st;
                            } break;
                        case StatementStartKeyword::for_st:
                            {
                                skip_space(module);
                                expect_character(module, left_parenthesis);
                                skip_space(module);

                                auto parent_scope = scope;

                                *statement = Statement{
                                    .for_each = {
                                        .first_local = 0,
                                        .last_local = 0,
                                        .left_values = {},
                                        .right_values = {},
                                        .predicate = 0,
                                        .scope = {
                                            .parent = parent_scope,
                                            .line = statement_line,
                                            .column = statement_column,
                                            .kind = ScopeKind::for_each,
                                        },
                                        .kind = {},
                                    },
                                    .id = StatementId::for_each,
                                    .line = statement_line,
                                    .column = statement_column,
                                };

                                auto scope = &statement->for_each.scope;

                                ValueKind left_value_buffer[64];
                                u64 left_value_count = 0;

                                while (1)
                                {
                                    skip_space(module);

                                    auto is_left = module->content[module->offset] == '&';
                                    module->offset += is_left;

                                    auto for_local_line = get_line(module);
                                    auto for_local_column = get_column(module);

                                    if (is_identifier_start(module->content[module->offset]))
                                    {
                                        auto local_name = parse_identifier(module);
                                        auto local = new_local(module, scope);
                                        *local = {
                                            .variable = {
                                                .storage = 0,
                                                .initial_value = 0,
                                                .type = 0,
                                                .scope = scope,
                                                .name = local_name,
                                                .line = for_local_line,
                                                .column = for_local_column,
                                            },
                                        };

                                        auto kind = is_left ? ValueKind::left : ValueKind::right;
                                        left_value_buffer[left_value_count] = kind;
                                        left_value_count += 1;
                                    }
                                    else
                                    {
                                        trap();
                                    }

                                    skip_space(module);

                                    if (!consume_character_if_match(module, ','))
                                    {
                                        expect_character(module, ':');
                                        break;
                                    }
                                }

                                skip_space(module);

                                Value* right_value_buffer[64];
                                u64 right_value_count = 0;

                                right_value_buffer[right_value_count] = parse_value(module, scope, { .kind = ValueKind::left });
                                right_value_count += 1;

                                skip_space(module);

                                auto token = tokenize(module);

                                ForEachKind kind;
                                switch (token.id)
                                {
                                    case TokenId::double_dot:
                                        {
                                            if (left_value_count != 1)
                                            {
                                                report_error();
                                            }

                                            right_value_buffer[0]->kind = ValueKind::right;

                                            right_value_buffer[right_value_count] = parse_value(module, scope, {});
                                            right_value_count += 1;

                                            expect_character(module, right_parenthesis);
                                            kind = ForEachKind::range;
                                        } break;
                                    case TokenId::right_parenthesis: kind = ForEachKind::slice; break;
                                    default: report_error();
                                }

                                statement->for_each.kind = kind;

                                if (kind == ForEachKind::slice && left_value_count != right_value_count)
                                {
                                    report_error();
                                }

                                auto left_values = arena_allocate<ValueKind>(module->arena, left_value_count);
                                memcpy(left_values.pointer, left_value_buffer, left_value_count * sizeof(left_value_buffer[0]));
                                auto right_values = arena_allocate<Value*>(module->arena, right_value_count);
                                memcpy(right_values.pointer, right_value_buffer, right_value_count * sizeof(right_value_buffer[0]));

                                statement->for_each.left_values = left_values;
                                statement->for_each.right_values = right_values;

                                skip_space(module);

                                auto predicate = parse_statement(module, scope);
                                statement->for_each.predicate = predicate;

                                skip_space(module);

                                require_semicolon = false;
                            } break;
                        case StatementStartKeyword::while_st:
                            {
                                skip_space(module);
                                expect_character(module, left_parenthesis);
                                skip_space(module);

                                auto condition = parse_value(module, scope, {});

                                skip_space(module);
                                expect_character(module, right_parenthesis);
                                skip_space(module);

                                auto block = parse_block(module, scope);

                                require_semicolon = false;
                                statement->while_st = {
                                    .condition = condition,
                                    .block = block,
                                };
                                statement->id = StatementId::while_st;
                            } break;
                        case StatementStartKeyword::switch_st:
                            {
                                skip_space(module);
                                expect_character(module, left_parenthesis);
                                skip_space(module);

                                auto discriminant = parse_value(module, scope, {});

                                skip_space(module);
                                expect_character(module, right_parenthesis);

                                skip_space(module);
                                expect_character(module, left_brace);

                                StatementSwitchClause clause_buffer[64];
                                u64 clause_count = 0;

                                while (1)
                                {
                                    skip_space(module);

                                    bool is_else = false;
                                    if (is_identifier_start(module->content[module->offset]))
                                    {
                                        auto else_checkpoint = get_checkpoint(module);
                                        auto i = parse_identifier(module);
                                        is_else = i.equal(string_literal("else"));
                                        if (!is_else)
                                        {
                                            set_checkpoint(module, else_checkpoint);
                                        }
                                    }

                                    Slice<ClauseDiscriminant> clause_values = {};
                                    if (is_else)
                                    {
                                        skip_space(module);

                                        expect_character(module, '=');
                                        expect_character(module, '>');
                                    }
                                    else
                                    {
                                        ClauseDiscriminant case_buffer[64];
                                        u64 case_count = 0;

                                        while (1)
                                        {
                                            auto first_case_value = parse_value(module, scope, {});

                                            skip_space(module);

                                            auto checkpoint = get_checkpoint(module);
                                            auto token = tokenize(module);

                                            ClauseDiscriminant clause_discriminant;
                                            switch (token.id)
                                            {
                                                case TokenId::triple_dot:
                                                    {
                                                        auto last_case_value = parse_value(module, scope, {});
                                                        clause_discriminant = {
                                                            .range = { first_case_value, last_case_value },
                                                            .id = ClauseDiscriminantId::range,
                                                        };
                                                    } break;
                                                default:
                                                    {
                                                        if (token.id != TokenId::comma) set_checkpoint(module, checkpoint);

                                                        clause_discriminant = {
                                                            .single = first_case_value,
                                                            .id = ClauseDiscriminantId::single,
                                                        };
                                                    } break;
                                            }

                                            switch (clause_discriminant.id)
                                            {
                                                case ClauseDiscriminantId::single:
                                                    {
                                                        assert(clause_discriminant.single);
                                                    } break;
                                                case ClauseDiscriminantId::range:
                                                    {
                                                        assert(clause_discriminant.range[0]);
                                                        assert(clause_discriminant.range[1]);
                                                    } break;
                                            }

                                            case_buffer[case_count] = clause_discriminant;
                                            case_count += 1;

                                            skip_space(module);

                                            if (consume_character_if_match(module, '='))
                                            {
                                                expect_character(module, '>');
                                                break;
                                            }
                                        }

                                        clause_values = arena_allocate<ClauseDiscriminant>(module->arena, case_count);
                                        memcpy(clause_values.pointer, case_buffer, case_count * sizeof(case_buffer[0]));
                                    }

                                    skip_space(module);

                                    auto clause_block = parse_block(module, scope);
                                    clause_buffer[clause_count] = {
                                        .values = clause_values,
                                        .block = clause_block,
                                    };
                                    clause_count += 1;

                                    consume_character_if_match(module, ',');

                                    skip_space(module);

                                    if (consume_character_if_match(module, right_brace))
                                    {
                                        break;
                                    }
                                }

                                auto clauses = arena_allocate<StatementSwitchClause>(module->arena, clause_count);
                                memcpy(clauses.pointer, clause_buffer, sizeof(clause_buffer[0]) * clause_count);

                                require_semicolon = false;

                                statement->switch_st = {
                                    .discriminant = discriminant,
                                    .clauses = clauses,
                                };
                                statement->id = StatementId::switch_st;
                            } break;
                        case StatementStartKeyword::break_st:
                            {
                                statement->id = StatementId::break_st;
                            } break;
                        case StatementStartKeyword::continue_st:
                            {
                                statement->id = StatementId::continue_st;
                            } break;
                        case StatementStartKeyword::count:
                            {
                                set_checkpoint(module, checkpoint);

                                auto left = parse_value(module, scope, { .kind = ValueKind::left });

                                skip_space(module);

                                if (consume_character_if_match(module, ';'))
                                {
                                    require_semicolon = false;
                                    statement->expression = left;
                                    statement->id = StatementId::expression;
                                }
                                else
                                {
                                    auto token = tokenize(module);

                                    StatementAssignmentId id;
                                    switch (token.id)
                                    {
                                        case TokenId::assign: id = StatementAssignmentId::assign; break;
                                        case TokenId::assign_plus: id = StatementAssignmentId::assign_add; break;
                                        case TokenId::assign_dash: id = StatementAssignmentId::assign_sub; break;
                                        case TokenId::assign_asterisk: id = StatementAssignmentId::assign_mul; break;
                                        case TokenId::assign_forward_slash: id = StatementAssignmentId::assign_div; break;
                                        case TokenId::assign_percentage: id = StatementAssignmentId::assign_rem; break;
                                        case TokenId::assign_shift_left: id = StatementAssignmentId::assign_shift_left; break;
                                        case TokenId::assign_shift_right: id = StatementAssignmentId::assign_shift_right; break;
                                        case TokenId::assign_ampersand: id = StatementAssignmentId::assign_and; break;
                                        case TokenId::assign_bar: id = StatementAssignmentId::assign_or; break;
                                        case TokenId::assign_caret: id = StatementAssignmentId::assign_xor; break;
                                        default: trap();
                                    }

                                    skip_space(module);

                                    auto right = parse_value(module, scope, {});
                                    statement->assignment = {
                                        .left = left,
                                        .right = right,
                                        .id = id,
                                    };
                                    statement->id = StatementId::assignment;
                                }
                            } break;
                    }
                }
                else
                {
                    trap();
                }
            } break;
    }

    if (require_semicolon)
    {
        expect_character(module, ';');
    }

    return statement;
}

fn Block* parse_block(Module* module, Scope* parent_scope)
{
    auto* block = &arena_allocate<Block>(module->arena, 1)[0];
    *block = {
        .scope = {
            .parent = parent_scope,
            .line = get_line(module),
            .column = get_column(module),
            .kind = ScopeKind::local,
        },
    };
    auto* scope = &block->scope;

    expect_character(module, left_brace);

    Statement* current_statement = 0;

    while (true)
    {
        skip_space(module);

        if (module->offset == module->content.length)
        {
            break;
        }

        if (consume_character_if_match(module, right_brace))
        {
            break;
        }

        auto* statement = parse_statement(module, scope);
        if (!block->first_statement)
        {
            block->first_statement = statement;
        }

        if (current_statement)
        {
            current_statement->next = statement;
        }

        assert(statement->next == 0);
        current_statement = statement;
    }

    return block;
}

fn String parse_name(Module* module)
{
    String result;
    if (module->content[module->offset] == '"')
    {
        result = parse_string_literal(module);
    }
    else
    {
        result = parse_identifier(module);
    }
    return result;
}

void parse(Module* module)
{
    auto scope = &module->scope;
    while (1)
    {
        skip_space(module);

        if (module->offset == module->content.length)
        {
            break;
        }

        bool is_export = false;
        bool is_extern = false;

        auto global_line = get_line(module);
        auto global_column = get_column(module);

        if (consume_character_if_match(module, left_bracket))
        {
            while (module->offset < module->content.length)
            {
                auto global_keyword_string = parse_identifier(module);
                enum class GlobalKeyword
                {
                    export_keyword,
                    extern_keyword,
                    count,
                };
                String global_keyword_strings[] = {
                    string_literal("export"),
                    string_literal("extern"),
                };
                static_assert(array_length(global_keyword_strings) == (u64)GlobalKeyword::count);

                u32 i;
                for (i = 0; i < array_length(global_keyword_strings); i += 1)
                {
                    String keyword = global_keyword_strings[i];
                    if (keyword.equal(global_keyword_string))
                    {
                        break;
                    }
                }

                auto global_keyword = (GlobalKeyword)i;
                switch (global_keyword)
                {
                    case GlobalKeyword::export_keyword:
                        {
                            is_export = true;
                        } break;
                    case GlobalKeyword::extern_keyword:
                        {
                            is_extern = true;
                        } break;
                    case GlobalKeyword::count:
                        {
                            report_error();
                        }
                }

                if (consume_character_if_match(module, right_bracket))
                {
                    break;
                }
                else
                {
                    report_error();
                }
            }

            skip_space(module);
        }

        auto global_name = parse_identifier(module);

        Global* global_forward_declaration = 0;
        Global* last_global = module->first_global;
        while (last_global)
        {
            if (global_name.equal(last_global->variable.name))
            {
                global_forward_declaration = last_global;
                if (last_global->variable.storage->id != ValueId::forward_declared_function)
                {
                    report_error();
                }

                if (last_global->linkage == Linkage::external)
                {
                    report_error();
                }

                break;
            }

            last_global = last_global->next;
        }

        Type* type_it = module->scope.types.first;
        Type* type_forward_declaration = 0;
        while (type_it)
        {
            if (global_name.equal(type_it->name))
            {
                if (type_it->id == TypeId::forward_declaration)
                {
                    type_forward_declaration = type_it;
                    break;
                }
                else
                {
                    report_error();
                }
            }

            if (!type_it->next)
            {
                break;
            }

            type_it = type_it->next;
        }

        skip_space(module);

        Type* global_type = 0;

        if (consume_character_if_match(module, ':'))
        {
            skip_space(module);

            global_type = parse_type(module, scope);

            skip_space(module);
        }

        expect_character(module, '=');

        skip_space(module);

        enum class GlobalKeyword
        {
            bits,
            enumerator,
            function,
            macro,
            opaque,
            structure,
            typealias,
            union_type,
            count,
        };

        auto i = (backing_type(GlobalKeyword))GlobalKeyword::count;

        if (is_identifier_start(module->content[module->offset]))
        {
            auto checkpoint = get_checkpoint(module);
            auto global_string = parse_identifier(module);
            skip_space(module);

            String global_keywords[] = {
                string_literal("bits"),
                string_literal("enum"),
                string_literal("fn"),
                string_literal("macro"),
                string_literal("opaque"),
                string_literal("struct"),
                string_literal("typealias"),
                string_literal("union"),
            };
            static_assert(array_length(global_keywords) == (u64)GlobalKeyword::count);

            for (i = 0; i < (backing_type(GlobalKeyword))GlobalKeyword::count; i += 1)
            {
                String global_keyword = global_keywords[i];
                if (global_string.equal(global_keyword))
                {
                    break;
                }
            }

            auto global_keyword = (GlobalKeyword)i;

            if (global_forward_declaration && global_keyword != GlobalKeyword::function)
            {
                report_error();
            }

            switch (global_keyword)
            {
                case GlobalKeyword::bits:
                    {
                        auto is_implicit_type = module->content[module->offset] == left_brace;
                        Type* backing_type = 0;
                        if (!is_implicit_type)
                        {
                            backing_type = parse_type(module, scope);
                        }

                        skip_space(module);
                        expect_character(module, left_brace);

                        u64 field_bit_offset = 0;
                        u64 field_count = 0;
                        Field field_buffer[64];

                        while (1)
                        {
                            skip_space(module);

                            if (consume_character_if_match(module, right_brace)) {
                                break;
                            }

                            auto field_line = get_line(module);
                            auto field_name = parse_identifier(module);

                            skip_space(module);
                            expect_character(module, ':');
                            skip_space(module);

                            auto field_type = parse_type(module, scope);

                            auto field_bit_count = get_bit_size(field_type);

                            skip_space(module);

                            consume_character_if_match(module, ',');

                            field_buffer[field_count] = {
                                .name = field_name,
                                .type = field_type,
                                .offset = field_bit_offset,
                                .line = field_line,
                            };

                            field_bit_offset += field_bit_count;
                            field_count += 1;
                        }

                        consume_character_if_match(module, ';');

                        auto fields = arena_allocate<Field>(module->arena, field_count);
                        memcpy(fields.pointer, field_buffer, sizeof(Field) * field_count);

                        auto needed_bit_count = MAX(next_power_of_two(field_bit_offset), 8);
                        if (needed_bit_count > ~(u32)0)
                        {
                            report_error();
                        }

                        auto bit_count = (u32)needed_bit_count;

                        if (!backing_type)
                        {
                            backing_type = integer_type(module, { .bit_count = bit_count, .is_signed = false });
                        }

                        if (backing_type->id != TypeId::integer)
                        {
                            report_error();
                        }

                        auto backing_type_bit_size = get_bit_size(backing_type);
                        if (backing_type_bit_size > 64)
                        {
                            report_error();
                        }

                        auto bits_type = type_allocate_init(module, {
                            .bits = {
                                .fields = fields,
                                .backing_type = backing_type,
                                .line = global_line,
                                .is_implicit_backing_type = is_implicit_type,
                            },
                            .id = TypeId::bits,
                            .name = global_name,
                            .scope = &module->scope,
                        });
                        unused(bits_type);
                    } break;
                case GlobalKeyword::enumerator:
                    {
                        auto is_implicit_type = module->content[module->offset] == left_brace;
                        Type* backing_type = 0;
                        if (!is_implicit_type)
                        {
                            backing_type = parse_type(module, scope);
                        }

                        skip_space(module);
                        expect_character(module, left_brace);

                        u64 field_count = 0;
                        String name_buffer[64];
                        u64 int_value_buffer[64];

                        bool is_resolved = true;
                        bool implicit_value = false;
                        unused(implicit_value);

                        while (1)
                        {
                            skip_space(module);

                            if (consume_character_if_match(module, right_brace)) {
                                break;
                            }

                            auto field_index = field_count;
                            field_count += 1;

                            auto field_name = parse_name(module);
                            name_buffer[field_index] = field_name;

                            skip_space(module);

                            u64 field_integer_value = field_index;

                            if (consume_character_if_match(module, '='))
                            {
                                skip_space(module);
                                auto field_value = parse_value(module, scope, {});
                                if (is_resolved)
                                {
                                    if (field_value->is_constant())
                                    {
                                        switch (field_value->id)
                                        {
                                            case ValueId::constant_integer:
                                                {
                                                    field_integer_value = field_value->constant_integer.value;
                                                } break;
                                            default: trap();
                                        }
                                    }
                                    else
                                    {
                                        trap();
                                    }
                                }
                                else
                                {
                                    trap();
                                }
                            }
                            else
                            {
                                if (!is_resolved)
                                {
                                    report_error();
                                }
                            }

                            int_value_buffer[field_index] = field_integer_value;

                            skip_space(module);
                            consume_character_if_match(module, ',');
                        }

                        if (is_resolved)
                        {
                            auto fields = arena_allocate<EnumField>(module->arena, field_count);
                            u64 highest_value = 0;
                            // auto lowest_value = ~(u64)0;

                            for (u64 i = 0; i < field_count; i += 1)
                            {
                                auto value = int_value_buffer[i];
                                highest_value = MAX(highest_value, value);
                                fields[i] = {
                                    .name = name_buffer[i],
                                    .value = value,
                                };
                            }

                            auto needed_bit_count = enum_bit_count(highest_value);

                            if (!backing_type)
                            {
                                backing_type = integer_type(module, { .bit_count = needed_bit_count, .is_signed = false });
                            }

                            auto enum_type = type_allocate_init(module, {
                                .enumerator = {
                                    .fields = fields,
                                    .backing_type = backing_type,
                                    .line = global_line,
                                },
                                .id = TypeId::enumerator,
                                .name = global_name,
                                .scope = &module->scope,
                            });

                            unused(enum_type);
                        }
                        else
                        {
                            trap();
                        }
                    } break;
                case GlobalKeyword::function:
                    {
                        auto mandate_argument_names = true;
                        auto function_header = parse_function_header(module, scope, mandate_argument_names);

                        auto function_type = function_header.type;
                        auto function_attributes = function_header.attributes;

                        auto semantic_argument_types = function_type->function.base.semantic_argument_types;

                        auto pointer_to_function_type = get_pointer_type(module, function_type);

                        Global* global = 0;
                        if (global_forward_declaration)
                        {
                            global = global_forward_declaration;
                            if (global_forward_declaration->variable.type != function_type)
                            {
                                report_error();
                            }

                            assert(global_forward_declaration->variable.storage->type == pointer_to_function_type);

                            global->variable.name = global_name;
                            global->variable.line = global_line;
                            global->variable.column = global_column;
                        }
                        else
                        {
                            auto storage = new_value(module);
                            *storage = {
                                .type = pointer_to_function_type,
                                .id = ValueId::forward_declared_function,
                                // TODO? .kind = ValueKind::left,
                            };

                            global = new_global(module);
                            *global = {
                                .variable = {
                                    .storage = storage,
                                    .initial_value = 0,
                                    .type = function_type,
                                    .scope = scope,
                                    .name = global_name,
                                    .line = global_line,
                                    .column = global_column,
                                },
                                .linkage = (is_export | is_extern) ? Linkage::external : Linkage::internal,
                            };
                        }

                        if (!consume_character_if_match(module, ';'))
                        {
                            module->current_function = global;
                            Slice<Argument> arguments = arena_allocate<Argument>(module->arena, semantic_argument_types.length);
                            for (u32 i = 0; i < semantic_argument_types.length; i += 1)
                            {
                                Argument* argument = &arguments[i];
                                auto header_argument = function_header.arguments[i];
                                auto name = header_argument.name;
                                auto* type = semantic_argument_types[i];
                                auto line = header_argument.line;

                                *argument = {
                                    .variable = {
                                        .storage = 0,
                                        .initial_value = 0,
                                        .type = type,
                                        .scope = &global->variable.storage->function.scope,
                                        .name = name,
                                        .line = line,
                                        .column = 0,
                                    },
                                    .index = i + 1,
                                };
                            }

                            global->variable.storage->function = {
                                .arguments = arguments,
                                .scope = {
                                    .parent = scope,
                                    .line = global_line,
                                    .column = global_column,
                                    .kind = ScopeKind::function,
                                },
                                .block = 0,
                                .attributes = function_attributes,
                            };
                            global->variable.storage->id = ValueId::function;

                            global->variable.storage->function.block = parse_block(module, &global->variable.storage->function.scope);
                            module->current_function = 0;
                        }
                    } break;
                case GlobalKeyword::macro:
                    {
                        ConstantArgument constant_argument_buffer[64];
                        u64 constant_argument_count = 0;

                        auto is_generic = consume_character_if_match(module, left_bracket);
                        auto macro_declaration = &arena_allocate<MacroDeclaration>(module->arena, 1)[0];

                        *macro_declaration = {
                            .arguments = {},
                            .constant_arguments = {},
                            .return_type = 0,
                            .block = 0,
                            .name = global_name,
                            .scope = {
                                .parent = scope,
                                .line = global_line,
                                .column = global_column,
                                .kind = ScopeKind::macro_declaration,
                            },
                        };

                        if (is_generic)
                        {
                            while (1)
                            {
                                skip_space(module);

                                if (consume_character_if_match(module, right_bracket))
                                {
                                    break;
                                }

                                auto argument_name = parse_identifier(module);

                                skip_space(module);

                                auto has_value = consume_character_if_match(module, ':');

                                auto constant_argument_index = constant_argument_count;

                                if (has_value)
                                {
                                    trap(); // TODO
                                }
                                else
                                {
                                    auto ty = type_allocate_init(module, {
                                        .id = TypeId::unresolved,
                                        .name = argument_name,
                                        .scope = &macro_declaration->scope,
                                    });

                                    constant_argument_buffer[constant_argument_index] = {
                                        .name = argument_name,
                                        .type = ty,
                                        .id = ConstantArgumentId::type,
                                    };
                                }

                                constant_argument_count += 1;
                            }

                            skip_space(module);
                        }

                        expect_character(module, left_parenthesis);

                        if (is_generic)
                        {
                            if (constant_argument_count == 0)
                            {
                                report_error();
                            }
                        }
                        else
                        {
                            assert(constant_argument_count == 0);
                        }

                        macro_declaration->constant_arguments = arena_allocate<ConstantArgument>(module->arena, constant_argument_count);
                        memcpy(macro_declaration->constant_arguments.pointer, constant_argument_buffer, sizeof(constant_argument_buffer[0]) * constant_argument_count);

                        if (module->last_macro_declaration)
                        {
                            assert(module->first_macro_declaration);
                            module->last_macro_declaration->next = macro_declaration;
                            module->last_macro_declaration = macro_declaration;
                        }
                        else
                        {
                            assert(!module->first_macro_declaration);
                            module->first_macro_declaration = macro_declaration;
                            module->last_macro_declaration = macro_declaration;
                        }

                        module->current_macro_declaration = macro_declaration;

                        auto scope = &macro_declaration->scope;

                        Argument argument_buffer[64];
                        u32 argument_count = 0;

                        while (1)
                        {
                            skip_space(module);

                            if (consume_character_if_match(module, right_parenthesis))
                            {
                                break;
                            }

                            auto argument_index = argument_count;
                            auto argument_line = get_line(module);
                            auto argument_column = get_column(module);

                            auto argument_name = parse_identifier(module);

                            skip_space(module);
                            expect_character(module, ':');
                            skip_space(module);

                            auto argument_type = parse_type(module, scope);

                            auto argument = &argument_buffer[argument_count];
                            *argument = {
                                .variable = {
                                    .storage = 0,
                                    .initial_value = 0,
                                    .type = argument_type,
                                    .scope = scope,
                                    .name = argument_name,
                                    .line = argument_line,
                                    .column = argument_column,
                                },
                                .index = argument_index + 1,
                            };
                            argument_count += 1;

                            skip_space(module);

                            consume_character_if_match(module, ',');
                        }

                        skip_space(module);

                        auto return_type = parse_type(module, scope);
                        macro_declaration->return_type = return_type;

                        auto arguments = arena_allocate<Argument>(module->arena, argument_count);
                        memcpy(arguments.pointer, argument_buffer, sizeof(argument_buffer[0]) * argument_count);
                        macro_declaration->arguments = arguments;

                        skip_space(module);

                        auto block = parse_block(module, scope);
                        macro_declaration->block = block;

                        // END OF SCOPE
                        module->current_macro_declaration = 0;
                    } break;
                case GlobalKeyword::structure:
                    {
                        skip_space(module);

                        Type* struct_type;
                        if (type_forward_declaration)
                        {
                            struct_type = type_forward_declaration;
                        }
                        else
                        {
                            struct_type = type_allocate_init(module, {
                                .id = TypeId::forward_declaration,
                                .name = global_name,
                                .scope = &module->scope,
                            });
                        }

                        if (consume_character_if_match(module, left_brace))
                        {
                            Field field_buffer[256];

                            u64 byte_size = 0;
                            u32 byte_alignment = 1;

                            u32 field_count = 0;

                            while (1)
                            {
                                skip_space(module);

                                if (consume_character_if_match(module, right_brace))
                                {
                                    break;
                                }

                                auto field_index = field_count;
                                auto field_line = get_line(module);
                                auto field_name = parse_identifier(module);

                                skip_space(module);
                                expect_character(module, ':');
                                skip_space(module);

                                auto field_type = parse_type(module, scope);

                                auto field_byte_alignment = get_byte_alignment(field_type);
                                auto field_byte_size = get_byte_size(field_type);
                                // Align struct size by field alignment
                                auto field_byte_offset = align_forward(byte_size, field_byte_alignment);

                                field_buffer[field_index] = {
                                    .name = field_name,
                                    .type = field_type,
                                    .offset = field_byte_offset,
                                    .line = field_line,
                                };

                                byte_size = field_byte_offset + field_byte_size;
                                byte_alignment = MAX(byte_alignment, field_byte_alignment);

                                skip_space(module);

                                consume_character_if_match(module, ',');

                                field_count += 1;
                            }

                            byte_size = align_forward(byte_size, byte_alignment);
                            assert(byte_size % byte_alignment == 0);

                            skip_space(module);
                            consume_character_if_match(module, ';');

                            auto fields = arena_allocate<Field>(module->arena, field_count);
                            memcpy(fields.pointer, field_buffer, sizeof(Field) * field_count);

                            struct_type->structure = {
                                .fields = fields,
                                .byte_size = byte_size,
                                .byte_alignment = byte_alignment,
                                .line = global_line,
                                .is_slice = false,
                                .next = 0,
                            };
                            struct_type->id = TypeId::structure;
                        }
                        else
                        {
                            expect_character(module, ';');
                        }
                    } break;
                case GlobalKeyword::typealias:
                    {
                        auto aliased_type = parse_type(module, scope);

                        if (!consume_character_if_match(module, ';'))
                        {
                            report_error();
                        }

                        auto alias_type = type_allocate_init(module, {
                            .alias = {
                                .type = aliased_type,
                                .scope = scope,
                                .line = global_line,
                            },
                            .id = TypeId::alias,
                            .name = global_name,
                            .scope = scope,
                        });
                        unused(alias_type);
                    } break;
                case GlobalKeyword::union_type:
                    {
                        skip_space(module);
                        expect_character(module, left_brace);

                        Type* union_type;
                        if (type_forward_declaration)
                        {
                            union_type = type_forward_declaration;
                        }
                        else
                        {
                            union_type = type_allocate_init(module, {
                                .id = TypeId::forward_declaration,
                                .name = global_name,
                                .scope = &module->scope,
                            });
                        }

                        u32 field_count = 0;
                        u32 biggest_field = 0;
                        u32 byte_alignment = 1;
                        u32 byte_size = 0;

                        UnionField field_buffer[64];

                        while (1)
                        {
                            skip_space(module);

                            if (consume_character_if_match(module, right_brace))
                            {
                                break;
                            }

                            auto field_index = field_count;
                            field_count += 1;

                            auto field_line = get_line(module);
                            auto field_name = parse_identifier(module);

                            skip_space(module);
                            expect_character(module, ':');
                            skip_space(module);

                            auto field_type = parse_type(module, scope);

                            auto field_byte_alignment = get_byte_alignment(field_type);
                            auto field_byte_size = get_byte_size(field_type);

                            field_buffer[field_index] = UnionField{
                                .type = field_type,
                                .name = field_name,
                                .line = field_line,
                            };

                            biggest_field = field_byte_size > byte_size ? field_index : biggest_field;
                            byte_alignment = MAX(byte_alignment, field_byte_alignment);
                            byte_size = MAX(byte_size, field_byte_size);

                            skip_space(module);

                            consume_character_if_match(module, ',');
                        }

                        skip_space(module);
                        consume_character_if_match(module, ';');

                        auto fields = arena_allocate<UnionField>(module->arena, field_count);
                        memcpy(fields.pointer, field_buffer, sizeof(field_buffer[0]) * field_count);

                        auto biggest_size = get_byte_size(fields[biggest_field].type);
                        assert(biggest_size == byte_size);

                        union_type->union_type = {
                            .fields = fields,
                            .byte_size = byte_size,
                            .byte_alignment = byte_alignment,
                            .line = global_line,
                            .biggest_field = biggest_field,
                        };
                        union_type->id = TypeId::union_type;
                    } break;
                case GlobalKeyword::opaque:
                    {
                        skip_space(module);
                        expect_character(module, ';');
                        auto opaque_type = type_allocate_init(module, {
                            .id = TypeId::opaque,
                            .name = global_name,
                            .scope = &module->scope,
                        });
                        unused(opaque_type);
                    } break;
                case GlobalKeyword::count:
                    {
                        set_checkpoint(module, checkpoint);
                    } break;
            }
        }

        if (i == (backing_type(GlobalKeyword))GlobalKeyword::count)
        {
            auto initial_value = parse_value(module, scope, {});
            skip_space(module);
            expect_character(module, ';');

            auto global_storage = new_value(module);
            *global_storage = {
                .id = ValueId::global,
            };

            auto global = new_global(module);
            *global = {
                .variable = {
                    .storage = global_storage,
                    .initial_value = initial_value,
                    .type = global_type,
                    .scope = scope,
                    .name = global_name,
                    .line = global_line,
                    .column = global_column,
                },
                .linkage = Linkage::internal, // TODO: linkage
            };
        }
    }
}
