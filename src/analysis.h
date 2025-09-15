#pragma once
#include <compiler.h>

void analyze(CompileUnit* restrict unit);

#if BB_INCLUDE_TESTS
bool analysis_tests(TestArguments* restrict arguments);
#endif
