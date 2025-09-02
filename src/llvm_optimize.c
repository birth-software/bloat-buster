#include <llvm_optimize.h>
#include <llvm-c/Transforms/PassBuilder.h>

LLVMErrorRef llvm_optimize(LLVMModuleRef module, LLVMTargetMachineRef target_machine, LLVMOptimizationLevel optimization_level, bool verify_each_pass, bool debug_logging)
{
    let prefer_size = (optimization_level == LLVM_OPTIMIZATION_LEVEL_Os) | (optimization_level == LLVM_OPTIMIZATION_LEVEL_Oz);
    let prefer_speed = (optimization_level == LLVM_OPTIMIZATION_LEVEL_O2) | (optimization_level == LLVM_OPTIMIZATION_LEVEL_O3);
    let pass_builder_options = LLVMCreatePassBuilderOptions();
    LLVMPassBuilderOptionsSetVerifyEach(pass_builder_options, verify_each_pass);
    LLVMPassBuilderOptionsSetDebugLogging(pass_builder_options, debug_logging);
    LLVMPassBuilderOptionsSetLoopInterleaving(pass_builder_options, prefer_speed);
    LLVMPassBuilderOptionsSetLoopVectorization(pass_builder_options, prefer_speed);
    LLVMPassBuilderOptionsSetSLPVectorization(pass_builder_options, prefer_speed);
    LLVMPassBuilderOptionsSetLoopUnrolling(pass_builder_options, prefer_speed);
    LLVMPassBuilderOptionsSetMergeFunctions(pass_builder_options, prefer_speed | prefer_size);

    char* passes;

    switch (optimization_level)
    {
        break; case LLVM_OPTIMIZATION_LEVEL_O0: passes = "default<O0>";
        break; case LLVM_OPTIMIZATION_LEVEL_O1: passes = "default<O1>";
        break; case LLVM_OPTIMIZATION_LEVEL_O2: passes = "default<O2>";
        break; case LLVM_OPTIMIZATION_LEVEL_O3: passes = "default<O3>";
        break; case LLVM_OPTIMIZATION_LEVEL_Os: passes = "default<Os>";
        break; case LLVM_OPTIMIZATION_LEVEL_Oz: passes = "default<Oz>";
        break; default: UNREACHABLE();
    }

    let error = LLVMRunPasses(module, passes, target_machine, pass_builder_options);
    return error;
}
