#pragma once

#include <lib.h>
#include <compiler.h>
#include <lexer.h>

void parse(CompileUnit* restrict unit, File* file, TokenList tl);

#if BB_INCLUDE_TESTS
bool parser_tests(TestArguments* restrict arguments);
#endif
