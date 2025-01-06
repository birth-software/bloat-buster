#include <std/base.h>

#define STRING_NO_MATCH UINT64_MAX

fn u64 string_first_ch(String string, u8 ch);
fn u64 string_last_ch(String string, u8 ch);
fn u8 string_starts_with(String string, String start);
fn u8 string_ends_with(String string, String end);
fn u64 string_first_occurrence(String string, String substring);
fn u64 string_last_occurrence(String string, String substring);
