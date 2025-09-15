#pragma once
#include <compiler.h>

STRUCT(GenerateIRResult)
{
    LLVMModuleRef module;
    LLVMTargetMachineRef target_machine;
    str error_message;
};

GenerateIRResult llvm_generate_ir(CompileUnit* restrict unit, bool verify);

#if BB_INCLUDE_TESTS
bool llvm_generation_tests(TestArguments* arguments);
#endif
