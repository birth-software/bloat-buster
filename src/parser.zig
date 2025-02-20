const lib = @import("lib.zig");
const assert = lib.assert;

const LexerResult = struct {
    token: Token,
    offset: u32,
    character_count: u32,
};

const Token = enum {};

const left_bracket = '[';
const right_bracket = ']';
const left_brace = '{';
const right_brace = '}';
const left_parenthesis = '(';
const right_parenthesis = ')';

fn is_identifier_start_ch(ch: u8) bool {
    return (ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or ch == '_';
}

fn is_decimal_ch(ch: u8) bool {
    return ch >= '0' and ch <= '9';
}

fn is_identifier_ch(ch: u8) bool {
    return is_identifier_start_ch(ch) or is_decimal_ch(ch);
}

fn string_to_enum(comptime E: type, string: []const u8) ?E {
    inline for (@typeInfo(E).@"enum".fields) |e| {
        if (lib.string.equal(e.name, string)) {
            return @field(E, e.name);
        }
    } else return null;
}

const GlobalKeyword = enum {
    @"export",
    @"extern",
};

const GlobalKind = enum {
    @"fn",
    foo,
};

const FunctionKeyword = enum {
    cc,
    foo,
};

const CallingConvention = enum {
    unknown,
    c,
};

const Parser = struct {
    content: []const u8,
    offset: usize,

    fn report_error(noalias parser: *Parser) noreturn {
        @branchHint(.cold);
        _ = parser;
        lib.os.abort();
    }

    fn skip_space(noalias parser: *Parser) void {
        while (parser.offset < parser.content.len and is_space(parser.content[parser.offset])) {
            parser.offset += 1;
        }
    }

    pub fn parse_identifier(noalias parser: *Parser) []const u8 {
        const start = parser.offset;

        if (is_identifier_start_ch(parser.content[start])) {
            parser.offset += 1;

            while (parser.offset < parser.content.len) {
                if (is_identifier_ch(parser.content[parser.offset])) {
                    parser.offset += 1;
                } else {
                    break;
                }
            }
        }

        if (parser.offset - start == 0) {
            parser.report_error();
        }

        return parser.content[start..parser.offset];
    }

    fn parse_integer(noalias parser: *Parser) void {
        const start = parser.offset;
        const integer_start_ch = parser.content[start];
        assert(!is_space(integer_start_ch));
        assert(is_decimal_ch(integer_start_ch));

        switch (integer_start_ch) {
            '0' => {
                parser.offset += 1;

                switch (parser.content[parser.offset]) {
                    'x' => {
                        // TODO: parse hexadecimal
                        parser.report_error();
                    },
                    'o' => {
                        // TODO: parse octal
                        parser.report_error();
                    },
                    'b' => {
                        // TODO: parse binary
                        parser.report_error();
                    },
                    '0'...'9' => {
                        parser.report_error();
                    },
                    // Zero literal
                    else => {},
                }
            },
            // TODO: decimal number
            '1'...'9' => parser.report_error(),
            else => unreachable,
        }
    }

    fn parse_block(noalias parser: *Parser) void {
        parser.skip_space();

        const start = parser.offset;
        const is_left_brace = parser.content[start] == left_brace;
        parser.offset += @intFromBool(is_left_brace);

        if (!is_left_brace) {
            parser.report_error();
        }

        while (true) {
            parser.skip_space();

            if (parser.offset == parser.content.len) {
                break;
            }

            if (parser.content[parser.offset] == right_brace) {
                break;
            }

            const statement_start_ch = parser.content[parser.offset];
            if (is_identifier_start_ch(statement_start_ch)) {
                const statement_start_identifier = parser.parse_identifier();

                if (string_to_enum(StatementStartKeyword, statement_start_identifier)) |statement_start_keyword| {
                    switch (statement_start_keyword) {
                        .@"return" => {
                            parser.parse_value();
                        },
                        else => unreachable,
                    }

                    const require_semicolon = switch (statement_start_keyword) {
                        .@"return" => true,
                        else => parser.report_error(),
                    };

                    const is_semicolon = parser.content[parser.offset] == ';';
                    parser.offset += @intFromBool(is_semicolon);

                    if (require_semicolon and !is_semicolon) {
                        parser.report_error();
                    }
                } else {
                    parser.report_error();
                }
            } else {
                parser.report_error();
            }
        }

        // TODO: handle it in a better way
        assert(parser.content[parser.offset] == right_brace);
        parser.offset += 1;
    }

    fn parse_value(noalias parser: *Parser) void {
        parser.skip_space();

        const start = parser.offset;
        const value_start_ch = parser.content[start];
        if (is_identifier_start_ch(value_start_ch)) {
            parser.report_error();
        } else if (is_decimal_ch(value_start_ch)) {
            parser.parse_integer();
        } else {
            parser.report_error();
        }
    }
};

fn is_space(ch: u8) bool {
    return ((ch == ' ') or (ch == '\n')) or ((ch == '\t' or ch == '\r'));
}

const StatementStartKeyword = enum {
    @"return",
    foooooooooo,
};

pub noinline fn parse_file(_content: []const u8) void {
    var parser = Parser{
        .content = _content,
        .offset = 0,
    };

    while (true) {
        parser.skip_space();

        if (parser.offset == parser.content.len) {
            break;
        }

        var is_export = false;

        if (parser.content[parser.offset] == left_bracket) {
            parser.offset += 1;

            while (parser.offset < parser.content.len) {
                const global_keyword_string = parser.parse_identifier();

                const global_keyword = string_to_enum(GlobalKeyword, global_keyword_string) orelse parser.report_error();
                switch (global_keyword) {
                    .@"export" => is_export = false,
                    else => parser.report_error(),
                }

                switch (parser.content[parser.offset]) {
                    right_bracket => break,
                    else => parser.report_error(),
                }
            }

            const is_right_bracket = parser.content[parser.offset] == right_bracket;
            parser.offset += @intFromBool(is_right_bracket);

            if (!is_right_bracket) {
                parser.report_error();
            }

            parser.skip_space();
        }

        const global_name = parser.parse_identifier();
        _ = global_name;

        parser.skip_space();

        const is_equal_token = parser.content[parser.offset] == '=';
        parser.offset += @intFromBool(is_equal_token);

        if (!is_equal_token) {
            parser.report_error();
        }

        parser.skip_space();

        const global_kind_string = parser.parse_identifier();

        parser.skip_space();

        const global_kind = string_to_enum(GlobalKind, global_kind_string) orelse parser.report_error();

        switch (global_kind) {
            .@"fn" => {
                var calling_convention = CallingConvention.unknown;

                if (parser.content[parser.offset] == left_bracket) {
                    parser.offset += 1;

                    while (parser.offset < parser.content.len) {
                        const function_identifier = parser.parse_identifier();

                        const function_keyword = string_to_enum(FunctionKeyword, function_identifier) orelse parser.report_error();

                        parser.skip_space();

                        switch (function_keyword) {
                            .cc => {
                                const is_left_parenthesis = parser.content[parser.offset] == left_parenthesis;
                                parser.offset += @intFromBool(is_left_parenthesis);

                                if (!is_left_parenthesis) {
                                    parser.report_error();
                                }

                                parser.skip_space();

                                const calling_convention_string = parser.parse_identifier();

                                calling_convention = string_to_enum(CallingConvention, calling_convention_string) orelse parser.report_error();

                                parser.skip_space();

                                const is_right_parenthesis = parser.content[parser.offset] == right_parenthesis;
                                parser.offset += @intFromBool(is_right_parenthesis);

                                if (!is_right_parenthesis) {
                                    parser.report_error();
                                }
                            },
                            else => parser.report_error(),
                        }

                        parser.skip_space();

                        switch (parser.content[parser.offset]) {
                            right_bracket => break,
                            else => parser.report_error(),
                        }
                    }

                    const is_right_bracket = parser.content[parser.offset] == right_bracket;
                    parser.offset += @intFromBool(is_right_bracket);

                    if (!is_right_bracket) {
                        parser.report_error();
                    }
                }

                parser.skip_space();

                const is_left_parenthesis = parser.content[parser.offset] == left_parenthesis;
                parser.offset += @intFromBool(is_left_parenthesis);

                if (!is_left_parenthesis) {
                    parser.report_error();
                }

                while (parser.offset < parser.content.len and parser.content[parser.offset] != right_parenthesis) {
                    // TODO: arguments
                    parser.report_error();
                }

                // TODO: handle it in a better way
                assert(parser.content[parser.offset] == right_parenthesis);
                parser.offset += 1;

                parser.skip_space();

                const return_type = parser.parse_identifier();
                _ = return_type;

                parser.parse_block();
            },
            else => parser.report_error(),
        }
    }
}

pub fn parser_experiment() void {
    const strlit =
        \\[export] main = fn [cc(c)] () s32
        \\{
        \\    return 0;
        \\}
    ;
    parse_file(strlit);
}

test "parse" {
    parser_experiment();
}
