#pragma once

#include <llvm_common.h>
#include <llvm-c/Target.h>
#include <stdatomic.h>
#include <llvm-c/Error.h>

PUB_IMPL void llvm_initialize()
{
    LLVMInitializeAllTargetInfos();
    LLVMInitializeAllTargets();
    LLVMInitializeAllTargetMCs();
    LLVMInitializeAllAsmPrinters();
    LLVMInitializeAllAsmParsers();
    LLVMInitializeAllDisassemblers();
}
