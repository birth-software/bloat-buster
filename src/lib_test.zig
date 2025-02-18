const lib = @import("lib.zig");

test "value_from_flag" {
    const std = @import("std");
    const expect = std.testing.expect;
    const value_from_flag = lib.value_from_flag;

    try expect(value_from_flag(1, 1) == 1);
    try expect(value_from_flag(2, true) == 2);
    try expect(value_from_flag(3, false) == 0);
    try expect(value_from_flag(3, true) == 3);
    try expect(value_from_flag(3, 1) == 3);

    try expect(value_from_flag(0xffff, 1) == 0xffff);
    try expect(value_from_flag(0xffff, 0) == 0);
    try expect(value_from_flag(0xffff, true) == 0xffff);
    try expect(value_from_flag(0xffff, false) == 0);

    try expect(value_from_flag(0xffffffff, 1) == 0xffffffff);
    try expect(value_from_flag(0xffffffff, 0) == 0);
    try expect(value_from_flag(0xffffffff, true) == 0xffffffff);
    try expect(value_from_flag(0xffffffff, false) == 0);

    try expect(value_from_flag(0xffffffffffffffff, 1) == 0xffffffffffffffff);
    try expect(value_from_flag(0xffffffffffffffff, 0) == 0);
    try expect(value_from_flag(0xffffffffffffffff, true) == 0xffffffffffffffff);
    try expect(value_from_flag(0xffffffffffffffff, false) == 0);

    const a: u32 = 1235;
    const b_true: bool = true;
    const b_false: bool = false;
    const u_true: u1 = 1;
    const u_false: u1 = 0;
    try expect(value_from_flag(a, b_true) == a);
    try expect(value_from_flag(a, b_false) == 0);
    try expect(value_from_flag(a, u_true) == a);
    try expect(value_from_flag(a, u_false) == 0);

    const b: u64 = 0xffffffffffffffff;
    try expect(value_from_flag(b, b_true) == b);
    try expect(value_from_flag(b, b_false) == 0);
    try expect(value_from_flag(b, u_true) == b);
    try expect(value_from_flag(b, u_false) == 0);
}
