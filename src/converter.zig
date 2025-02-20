const lib = @import("lib.zig");
const llvm = @import("LLVM.zig");
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

const Converter = struct {
    content: []const u8,
    offset: usize,

    fn report_error(noalias converter: *Converter) noreturn {
        @branchHint(.cold);
        _ = converter;
        lib.os.abort();
    }

    fn skip_space(noalias converter: *Converter) void {
        while (converter.offset < converter.content.len and is_space(converter.content[converter.offset])) {
            converter.offset += 1;
        }
    }

    pub fn parse_identifier(noalias converter: *Converter) []const u8 {
        const start = converter.offset;

        if (is_identifier_start_ch(converter.content[start])) {
            converter.offset += 1;

            while (converter.offset < converter.content.len) {
                if (is_identifier_ch(converter.content[converter.offset])) {
                    converter.offset += 1;
                } else {
                    break;
                }
            }
        }

        if (converter.offset - start == 0) {
            converter.report_error();
        }

        return converter.content[start..converter.offset];
    }

    fn consume_character_if_match(noalias converter: *Converter, expected_ch: u8) bool {
        var is_ch = false;
        if (converter.offset < converter.content.len) {
            const ch = converter.content[converter.offset];
            is_ch = expected_ch == ch;
            converter.offset += @intFromBool(is_ch);
        }

        return is_ch;
    }

    fn expect_or_consume(noalias converter: *Converter, expected_ch: u8, is_required: bool) bool {
        if (is_required) {
            converter.expect_character(expected_ch);
            return true;
        } else {
            return converter.consume_character_if_match(expected_ch);
        }
    }

    fn parse_integer(noalias converter: *Converter) void {
        const start = converter.offset;
        const integer_start_ch = converter.content[start];
        assert(!is_space(integer_start_ch));
        assert(is_decimal_ch(integer_start_ch));

        switch (integer_start_ch) {
            '0' => {
                converter.offset += 1;

                switch (converter.content[converter.offset]) {
                    'x' => {
                        // TODO: parse hexadecimal
                        converter.report_error();
                    },
                    'o' => {
                        // TODO: parse octal
                        converter.report_error();
                    },
                    'b' => {
                        // TODO: parse binary
                        converter.report_error();
                    },
                    '0'...'9' => {
                        converter.report_error();
                    },
                    // Zero literal
                    else => {},
                }
            },
            // TODO: decimal number
            '1'...'9' => converter.report_error(),
            else => unreachable,
        }
    }

    fn expect_character(noalias converter: *Converter, expected_ch: u8) void {
        if (!converter.consume_character_if_match(expected_ch)) {
            converter.report_error();
        }
    }

    fn parse_block(noalias converter: *Converter) void {
        converter.skip_space();

        converter.expect_character(left_brace);

        while (true) {
            converter.skip_space();

            if (converter.offset == converter.content.len) {
                break;
            }

            if (converter.content[converter.offset] == right_brace) {
                break;
            }

            const statement_start_ch = converter.content[converter.offset];
            if (is_identifier_start_ch(statement_start_ch)) {
                const statement_start_identifier = converter.parse_identifier();

                if (string_to_enum(StatementStartKeyword, statement_start_identifier)) |statement_start_keyword| {
                    switch (statement_start_keyword) {
                        .@"return" => {
                            converter.parse_value();
                        },
                        else => unreachable,
                    }

                    const require_semicolon = switch (statement_start_keyword) {
                        .@"return" => true,
                        else => converter.report_error(),
                    };

                    _ = converter.expect_or_consume(';', require_semicolon);
                } else {
                    converter.report_error();
                }
            } else {
                converter.report_error();
            }
        }

        converter.expect_character(right_brace);
    }

    fn parse_value(noalias converter: *Converter) void {
        converter.skip_space();

        const start = converter.offset;
        const value_start_ch = converter.content[start];
        if (is_identifier_start_ch(value_start_ch)) {
            converter.report_error();
        } else if (is_decimal_ch(value_start_ch)) {
            converter.parse_integer();
        } else {
            converter.report_error();
        }
    }
};

fn is_space(ch: u8) bool {
    return ((@intFromBool(ch == ' ') | @intFromBool(ch == '\n')) | ((@intFromBool(ch == '\t') | @intFromBool(ch == '\r')))) != 0;
}

const StatementStartKeyword = enum {
    @"return",
    foooooooooo,
};

pub noinline fn convert(_content: []const u8) void {
    var converter = Converter{
        .content = _content,
        .offset = 0,
    };

    while (true) {
        converter.skip_space();

        if (converter.offset == converter.content.len) {
            break;
        }

        var is_export = false;

        if (converter.content[converter.offset] == left_bracket) {
            converter.offset += 1;

            while (converter.offset < converter.content.len) {
                const global_keyword_string = converter.parse_identifier();

                const global_keyword = string_to_enum(GlobalKeyword, global_keyword_string) orelse converter.report_error();
                switch (global_keyword) {
                    .@"export" => is_export = false,
                    else => converter.report_error(),
                }

                switch (converter.content[converter.offset]) {
                    right_bracket => break,
                    else => converter.report_error(),
                }
            }

            converter.expect_character(right_bracket);

            converter.skip_space();
        }

        const global_name = converter.parse_identifier();
        _ = global_name;

        converter.skip_space();

        converter.expect_character('=');

        converter.skip_space();

        const global_kind_string = converter.parse_identifier();

        converter.skip_space();

        const global_kind = string_to_enum(GlobalKind, global_kind_string) orelse converter.report_error();

        switch (global_kind) {
            .@"fn" => {
                var calling_convention = CallingConvention.unknown;

                if (converter.consume_character_if_match(left_bracket)) {
                    while (converter.offset < converter.content.len) {
                        const function_identifier = converter.parse_identifier();

                        const function_keyword = string_to_enum(FunctionKeyword, function_identifier) orelse converter.report_error();

                        converter.skip_space();

                        switch (function_keyword) {
                            .cc => {
                                converter.expect_character(left_parenthesis);

                                converter.skip_space();

                                const calling_convention_string = converter.parse_identifier();

                                calling_convention = string_to_enum(CallingConvention, calling_convention_string) orelse converter.report_error();

                                converter.skip_space();

                                converter.expect_character(right_parenthesis);
                            },
                            else => converter.report_error(),
                        }

                        converter.skip_space();

                        switch (converter.content[converter.offset]) {
                            right_bracket => break,
                            else => converter.report_error(),
                        }
                    }

                    converter.expect_character(right_bracket);
                }

                converter.skip_space();

                converter.expect_character(left_parenthesis);

                while (converter.offset < converter.content.len and converter.content[converter.offset] != right_parenthesis) {
                    // TODO: arguments
                    converter.report_error();
                }

                converter.expect_character(right_parenthesis);

                converter.skip_space();

                const return_type = converter.parse_identifier();
                _ = return_type;

                converter.parse_block();
            },
            else => converter.report_error(),
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
    convert(strlit);
}

test "parse" {
    parser_experiment();
}
