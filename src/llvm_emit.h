#pragma once

#include <compiler.h>

str llvm_emit(LLVMModuleRef module, LLVMTargetMachineRef target_machine, str file_path, LLVMCodeGenFileType type);
