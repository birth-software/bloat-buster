#pragma once

#include <compiler.h>

PUB_DECL str llvm_emit(LLVMModuleRef module, LLVMTargetMachineRef target_machine, str file_path, LLVMCodeGenFileType type);
