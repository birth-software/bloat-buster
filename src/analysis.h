#pragma once

#include <compiler.h>

PUB_DECL void analyze(CompileUnit* restrict unit);

#if BB_INCLUDE_TESTS
PUB_DECL bool analysis_tests(TestArguments* restrict arguments);
#endif
