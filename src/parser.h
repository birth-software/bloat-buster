#pragma once

#include <lib.h>
#include <compiler.h>
#include <lexer.h>

PUB_DECL void parse(CompileUnit* restrict unit, File* file, TokenList tl);

#if BB_INCLUDE_TESTS
PUB_DECL bool parser_tests(TestArguments* restrict arguments);
#endif
