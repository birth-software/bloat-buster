#include <llvm_emit.h>
#include <llvm-c/TargetMachine.h>

str llvm_emit(LLVMModuleRef module, LLVMTargetMachineRef target_machine, str file_path, LLVMCodeGenFileType type)
{
    assert(str_is_zero_terminated(file_path));
    char* error_message = {};
    LLVMBool r = LLVMTargetMachineEmitToFile(target_machine, module, file_path.pointer, type, &error_message);
    assert(!!error_message == !!r);
    str result = {};
    if (error_message)
    {
        result = (str){error_message, strlen(error_message)};
    }
    return result;
}
