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

pub fn parse_identifier(content: []const u8, start: u32) []const u8 {
    var offset = start;

    if (is_identifier_start_ch(content[start])) {
        offset += 1;

        while (offset < content.len) {
            if (is_identifier_ch(content[offset])) {
                offset += 1;
            } else {
                break;
            }
        }
    }

    return content[start..offset];
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

fn report_error() noreturn {
    lib.os.abort();
}

fn is_space(ch: u8) bool {
    return ((ch == ' ') or (ch == '\n')) or ((ch == '\t' or ch == '\r'));
}

fn skip_space(content: []const u8, start: u32) u32 {
    var offset = start;
    while (offset < content.len and is_space(content[offset])) {
        offset += 1;
    }
    return offset;
}

const StatementStartKeyword = enum {
    @"return",
    foooooooooo,
};

fn parse_integer(content: []const u8, start: u32) u32 {
    const integer_start_ch = content[start];
    assert(!is_space(integer_start_ch));
    assert(is_decimal_ch(integer_start_ch));

    var offset = start;

    switch (integer_start_ch) {
        '0' => {
            offset += 1;

            switch (content[offset]) {
                'x' => {
                    // TODO: parse hexadecimal
                    report_error();
                },
                'o' => {
                    // TODO: parse octal
                    report_error();
                },
                'b' => {
                    // TODO: parse binary
                    report_error();
                },
                '0'...'9' => {
                    report_error();
                },
                // Zero literal
                else => {},
            }
        },
        // TODO: decimal number
        '1'...'9' => report_error(),
        else => unreachable,
    }

    return offset;
}

fn parse_value(content: []const u8, start: u32) u32 {
    var offset = start;
    offset = skip_space(content, start);

    const value_start_ch = content[offset];
    if (is_identifier_start_ch(value_start_ch)) {
        report_error();
    } else if (is_decimal_ch(value_start_ch)) {
        offset = parse_integer(content, offset);
    } else {
        report_error();
    }

    return offset;
}

fn parse_block(content: []const u8, start: u32) u32 {
    var offset = start;

    offset = skip_space(content, offset);

    const is_left_brace = content[offset] == left_brace;
    offset += @intFromBool(is_left_brace);

    if (!is_left_brace) {
        report_error();
    }

    while (true) {
        offset = skip_space(content, offset);

        if (offset == content.len) {
            break;
        }

        if (content[offset] == right_brace) {
            break;
        }

        const statement_start_ch = content[offset];
        if (is_identifier_start_ch(statement_start_ch)) {
            const statement_start_identifier = parse_identifier(content, offset);
            // Here, since we have a mandatory identifier start ch, we know at least we have a one-character identifier and an if check is not necessary
            offset += @intCast(statement_start_identifier.len);

            if (string_to_enum(StatementStartKeyword, statement_start_identifier)) |statement_start_keyword| {
                switch (statement_start_keyword) {
                    .@"return" => {
                        offset = parse_value(content, offset);
                    },
                    else => unreachable,
                }

                const require_semicolon = switch (statement_start_keyword) {
                    .@"return" => true,
                    else => report_error(),
                };

                const is_semicolon = content[offset] == ';';
                offset += @intFromBool(is_semicolon);

                if (require_semicolon and !is_semicolon) {
                    report_error();
                }
            } else {
                report_error();
            }
        } else {
            report_error();
        }
    }

    // TODO: handle it in a better way
    assert(content[offset] == right_brace);
    offset += 1;

    return offset;
}

pub noinline fn parse_file(content: []const u8) void {
    var offset: u32 = 0;

    while (true) {
        offset = skip_space(content, offset);

        if (offset == content.len) {
            break;
        }

        var is_export = false;

        if (content[offset] == left_bracket) {
            offset += 1;

            while (offset < content.len) {
                const global_keyword_string = parse_identifier(content, offset);
                offset += @intCast(global_keyword_string.len);

                if (global_keyword_string.len == 0) {
                    break;
                }

                const global_keyword = string_to_enum(GlobalKeyword, global_keyword_string) orelse report_error();
                switch (global_keyword) {
                    .@"export" => is_export = false,
                    else => report_error(),
                }

                switch (content[offset]) {
                    right_bracket => {},
                    else => report_error(),
                }
            }

            const is_right_bracket = content[offset] == right_bracket;
            offset += @intFromBool(is_right_bracket);

            if (!is_right_bracket) {
                report_error();
            }

            offset = skip_space(content, offset);
        }

        const global_name = parse_identifier(content, offset);
        offset += @intCast(global_name.len);

        if (global_name.len == 0) {
            report_error();
        }

        offset = skip_space(content, offset);

        const is_equal_token = content[offset] == '=';
        offset += @intFromBool(is_equal_token);

        if (!is_equal_token) {
            report_error();
        }

        offset = skip_space(content, offset);

        const global_kind_string = parse_identifier(content, offset);
        offset += @intCast(global_kind_string.len);

        offset = skip_space(content, offset);

        if (global_kind_string.len == 0) {
            report_error();
        }

        const global_kind = string_to_enum(GlobalKind, global_kind_string) orelse report_error();

        switch (global_kind) {
            .@"fn" => {
                var calling_convention = CallingConvention.unknown;

                if (content[offset] == left_bracket) {
                    offset += 1;

                    while (offset < content.len) {
                        const function_identifier = parse_identifier(content, offset);
                        offset += @intCast(function_identifier.len);

                        if (function_identifier.len == 0) {
                            break;
                        }

                        const function_keyword = string_to_enum(FunctionKeyword, function_identifier) orelse report_error();

                        offset = skip_space(content, offset);

                        switch (function_keyword) {
                            .cc => {
                                const is_left_parenthesis = content[offset] == left_parenthesis;
                                offset += @intFromBool(is_left_parenthesis);

                                if (!is_left_parenthesis) {
                                    report_error();
                                }

                                offset = skip_space(content, offset);

                                const calling_convention_string = parse_identifier(content, offset);
                                offset += @intCast(calling_convention_string.len);

                                if (calling_convention_string.len == 0) {
                                    report_error();
                                }

                                calling_convention = string_to_enum(CallingConvention, calling_convention_string) orelse report_error();

                                offset = skip_space(content, offset);

                                const is_right_parenthesis = content[offset] == right_parenthesis;
                                offset += @intFromBool(is_right_parenthesis);

                                if (!is_right_parenthesis) {
                                    report_error();
                                }

                                offset = skip_space(content, offset);
                            },
                            else => report_error(),
                        }

                        switch (content[offset]) {
                            right_bracket => {},
                            else => report_error(),
                        }
                    }

                    const is_right_bracket = content[offset] == right_bracket;
                    offset += @intFromBool(is_right_bracket);

                    if (!is_right_bracket) {
                        report_error();
                    }
                }

                offset = skip_space(content, offset);

                const is_left_parenthesis = content[offset] == left_parenthesis;
                offset += @intFromBool(is_left_parenthesis);

                if (!is_left_parenthesis) {
                    report_error();
                }

                while (offset < content.len and content[offset] != right_parenthesis) {
                    // TODO: arguments
                    report_error();
                }

                // TODO: handle it in a better way
                assert(content[offset] == right_parenthesis);
                offset += 1;

                offset = skip_space(content, offset);

                const return_type = parse_identifier(content, offset);
                offset += @intCast(return_type.len);

                if (return_type.len == 0) {
                    report_error();
                }

                offset = parse_block(content, offset);
            },
            else => report_error(),
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
