
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"

#define EXPORT extern "C"
#define fn static

using namespace llvm;

EXPORT Module* llvm_context_create_module(LLVMContext& context, const char* name_pointer, size_t name_length)
{
    auto name = StringRef(name_pointer, name_length);
    return new Module(name, context);
}

EXPORT Value* llvm_builder_create_add(IRBuilder<>& builder, Value* left, Value* right, bool nuw, bool nsw)
{
    auto* result = builder.CreateAdd(left, right, "", nuw, nsw);
    return result;
}

EXPORT Function* llvm_module_create_function(Module* module, FunctionType* function_type, GlobalValue::LinkageTypes linkage_type, unsigned address_space, const char* name_pointer, size_t name_length)
{
    auto name = StringRef(name_pointer, name_length);
    auto* function = Function::Create(function_type, linkage_type, address_space, name, module);
    return function;
}

EXPORT StructType* llvm_context_create_struct_type(LLVMContext& context, Type** type_pointer, size_t type_count, const char* name_pointer, size_t name_length, bool is_packed)
{
    auto types = ArrayRef<Type*>(type_pointer, type_count);
    auto name = StringRef(name_pointer, name_length);
    auto* struct_type = StructType::create(context, types, name, is_packed);
    return struct_type;
}

EXPORT StructType* llvm_context_get_struct_type(LLVMContext& context, Type** type_pointer, size_t type_count, bool is_packed)
{
    auto types = ArrayRef<Type*>(type_pointer, type_count);
    auto* struct_type = StructType::get(context, types, is_packed);
    return struct_type;
}

EXPORT BasicBlock* llvm_context_create_basic_block(LLVMContext& context, const char* name_pointer, size_t name_length, Function* parent)
{
    auto name = StringRef(name_pointer, name_length);
    auto* basic_block = BasicBlock::Create(context, name, parent);
    return basic_block;
}

fn void stream_to_string(raw_string_ostream& stream, const char** message_pointer, size_t* message_length)
{
    // No need to call stream.flush(); because it's string-based
    stream.flush();

    auto string = stream.str();
    auto length = string.length();

    char* result = 0;
    if (length)
    {
        result = new char[length];
        memcpy(result, string.c_str(), length);
    }

    *message_pointer = result;
    *message_length = length;
}

EXPORT bool llvm_function_verify(Function& function, const char** message_pointer, size_t* message_length)
{
    std::string message_buffer;
    raw_string_ostream message_stream(message_buffer);

    bool result = verifyFunction(function, &message_stream);
    auto size = message_stream.str().size();
    stream_to_string(message_stream, message_pointer, message_length);

    // We invert the condition because LLVM conventions are just stupid
    return !result;
}

EXPORT bool llvm_module_verify(const Module& module, const char** message_pointer, size_t* message_length)
{
    std::string message_buffer;
    raw_string_ostream message_stream(message_buffer);

    bool result = verifyModule(module, &message_stream);
    stream_to_string(message_stream, message_pointer, message_length);

    // We invert the condition because LLVM conventions are just stupid
    return !result;
}

EXPORT void llvm_module_to_string(Module* module, const char** module_pointer, size_t* module_length)
{
    std::string buffer;
    raw_string_ostream stream(buffer);
    module->print(stream, nullptr);

    stream_to_string(stream, module_pointer, module_length);
}

