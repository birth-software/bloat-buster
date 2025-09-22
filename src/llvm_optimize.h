#pragma once

#include <compiler.h>

typedef enum LLVMOptimizationLevel
{
    LLVM_OPTIMIZATION_LEVEL_O0,
    LLVM_OPTIMIZATION_LEVEL_O1,
    LLVM_OPTIMIZATION_LEVEL_O2,
    LLVM_OPTIMIZATION_LEVEL_O3,
    LLVM_OPTIMIZATION_LEVEL_Os,
    LLVM_OPTIMIZATION_LEVEL_Oz,
} LLVMOptimizationLevel;

PUB_DECL LLVMErrorRef llvm_optimize(LLVMModuleRef module, LLVMTargetMachineRef target_machine, LLVMOptimizationLevel optimization_level, bool verify_each_pass, bool debug_logging);
