#include <llvm.hpp>

#include "llvm/Config/llvm-config.h"

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/LegacyPassManager.h"

#include "llvm/Passes/PassBuilder.h"

#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/TargetTransformInfo.h"

#include "llvm/Frontend/Driver/CodeGenOptions.h"

#include "llvm/TargetParser/Host.h"
#include "llvm/TargetParser/SubtargetFeature.h"

#include "llvm/Target/TargetMachine.h"

#include "llvm/MC/TargetRegistry.h"

#include "llvm/Support/FileSystem.h"

#include "lld/Common/CommonLinkerContext.h"

fn llvm::StringRef string_ref(String string)
{
    return llvm::StringRef((char*)string.pointer, string.length);
}

EXPORT LLVMModuleRef llvm_context_create_module(LLVMContextRef context, String name)
{
    auto module = new llvm::Module(string_ref(name), *llvm::unwrap(context));
    return wrap(module);
}

EXPORT LLVMValueRef llvm_module_create_global_variable(LLVMModuleRef module, LLVMTypeRef type, bool is_constant, LLVMLinkage linkage_type, LLVMValueRef initial_value, String name, LLVMValueRef before, LLVMThreadLocalMode thread_local_mode, unsigned address_space, bool externally_initialized)
{
    llvm::GlobalValue::LinkageTypes linkage;
    switch (linkage_type)
    {
        case LLVMExternalLinkage: linkage = llvm::GlobalValue::ExternalLinkage; break;
        case LLVMInternalLinkage: linkage = llvm::GlobalValue::InternalLinkage; break;
        default: trap();
    }

    llvm::GlobalValue::ThreadLocalMode tlm;
    switch (thread_local_mode)
    {
        case LLVMNotThreadLocal: tlm = llvm::GlobalValue::NotThreadLocal; break;
        default: trap();
    }
    auto* global = new llvm::GlobalVariable(*llvm::unwrap(module), llvm::unwrap(type), is_constant, linkage, llvm::unwrap<llvm::Constant>(initial_value), string_ref(name), before ? llvm::unwrap<llvm::GlobalVariable>(before) : 0, tlm, address_space, externally_initialized);
    return wrap(global);
}

EXPORT void llvm_subprogram_replace_type(LLVMMetadataRef subprogram, LLVMMetadataRef subroutine_type)
{
    auto sp = llvm::unwrap<llvm::DISubprogram>(subprogram);
    sp->replaceType(llvm::unwrap<llvm::DISubroutineType>(subroutine_type));
}

EXPORT LLVMValueRef llvm_module_create_function(LLVMModuleRef module, LLVMTypeRef function_type, LLVMLinkage linkage_type, unsigned address_space, String name)
{
    llvm::GlobalValue::LinkageTypes llvm_linkage_type;
    switch (linkage_type)
    {
        case LLVMExternalLinkage:
            llvm_linkage_type = llvm::GlobalValue::LinkageTypes::ExternalLinkage; break;
        case LLVMAvailableExternallyLinkage:
            llvm_linkage_type = llvm::GlobalValue::LinkageTypes::AvailableExternallyLinkage; break;
        case LLVMLinkOnceAnyLinkage:
            llvm_linkage_type = llvm::GlobalValue::LinkageTypes::LinkOnceAnyLinkage; break;
        case LLVMLinkOnceODRLinkage:
            llvm_linkage_type = llvm::GlobalValue::LinkageTypes::LinkOnceODRLinkage; break;
        case LLVMWeakAnyLinkage:
            llvm_linkage_type = llvm::GlobalValue::LinkageTypes::WeakAnyLinkage; break;
        case LLVMWeakODRLinkage:
            llvm_linkage_type = llvm::GlobalValue::LinkageTypes::WeakODRLinkage; break;
        case LLVMAppendingLinkage:
            llvm_linkage_type = llvm::GlobalValue::LinkageTypes::AppendingLinkage; break;
        case LLVMInternalLinkage:
            llvm_linkage_type = llvm::GlobalValue::LinkageTypes::InternalLinkage; break;
        case LLVMPrivateLinkage:
            llvm_linkage_type = llvm::GlobalValue::LinkageTypes::PrivateLinkage; break;
        case LLVMExternalWeakLinkage:
            llvm_linkage_type = llvm::GlobalValue::LinkageTypes::ExternalWeakLinkage; break;
        case LLVMCommonLinkage:
            llvm_linkage_type = llvm::GlobalValue::LinkageTypes::CommonLinkage; break;
        default:
            trap();
    }
    auto* function = llvm::Function::Create(llvm::unwrap<llvm::FunctionType>(function_type), llvm_linkage_type, address_space, string_ref(name), llvm::unwrap(module));
    return wrap(function);
}

EXPORT LLVMBasicBlockRef llvm_context_create_basic_block(LLVMContextRef context, String name, LLVMValueRef parent_function)
{
    auto* basic_block = llvm::BasicBlock::Create(*llvm::unwrap(context), string_ref(name), parent_function ? llvm::unwrap<llvm::Function>(parent_function) : 0);
    return wrap(basic_block);
}

// If there are multiple uses of the return-value slot, just check
// for something immediately preceding the IP.  Sometimes this can
// happen with how we generate implicit-returns; it can also happen
// with noreturn cleanups.
fn llvm::StoreInst* get_store_if_valid(llvm::User* user, llvm::Value* return_alloca, llvm::Type* element_type)
{
    auto *SI = dyn_cast<llvm::StoreInst>(user);
    if (!SI || SI->getPointerOperand() != return_alloca ||
        SI->getValueOperand()->getType() != element_type)
      return nullptr;
    // These aren't actually possible for non-coerced returns, and we
    // only care about non-coerced returns on this code path.
    // All memory instructions inside __try block are volatile.
    assert(!SI->isAtomic() &&
           (!SI->isVolatile()
            //|| CGF.currentFunctionUsesSEHTry())
          ));
    return SI;
}

// copy of static llvm::StoreInst *findDominatingStoreToReturnValue(CodeGenFunction &CGF) {
// in clang/lib/CodeGen/CGCall.cpp:3526 in LLVM 19
EXPORT LLVMValueRef llvm_find_return_value_dominating_store(LLVMBuilderRef b, LLVMValueRef ra, LLVMTypeRef et)
{
    auto builder = llvm::unwrap(b);
    auto return_alloca = llvm::unwrap(ra);
    auto element_type = llvm::unwrap(et);
    // Check if a User is a store which pointerOperand is the ReturnValue.
    // We are looking for stores to the ReturnValue, not for stores of the
    // ReturnValue to some other location.
    if (!return_alloca->hasOneUse()) {
        llvm::BasicBlock *IP = builder->GetInsertBlock();
        if (IP->empty()) return nullptr;

        // Look at directly preceding instruction, skipping bitcasts and lifetime
        // markers.
        for (llvm::Instruction &I : make_range(IP->rbegin(), IP->rend())) {
            if (isa<llvm::BitCastInst>(&I))
                continue;
            if (auto *II = dyn_cast<llvm::IntrinsicInst>(&I))
                if (II->getIntrinsicID() == llvm::Intrinsic::lifetime_end)
                    continue;

            return wrap(get_store_if_valid(&I, return_alloca, element_type));
        }
        return nullptr;
    }

    llvm::StoreInst *store = get_store_if_valid(return_alloca->user_back(), return_alloca, element_type);
    if (!store) return nullptr;

    // Now do a first-and-dirty dominance check: just walk up the
    // single-predecessors chain from the current insertion point.
    llvm::BasicBlock *StoreBB = store->getParent();
    llvm::BasicBlock *IP = builder->GetInsertBlock();
    llvm::SmallPtrSet<llvm::BasicBlock *, 4> SeenBBs;
    while (IP != StoreBB) {
        if (!SeenBBs.insert(IP).second || !(IP = IP->getSinglePredecessor()))
            return nullptr;
    }

    // Okay, the store's basic block dominates the insertion point; we
    // can do our thing.
    return wrap(store);
}

EXPORT bool llvm_value_use_empty(LLVMValueRef value)
{
    return llvm::unwrap(value)->use_empty();
}

EXPORT bool llvm_basic_block_is_empty(LLVMBasicBlockRef basic_block)
{
    return llvm::unwrap(basic_block)->empty();
}

EXPORT LLVMValueRef llvm_builder_create_alloca(LLVMBuilderRef b, LLVMTypeRef type, unsigned address_space, u32 alignment, String name)
{   
    auto& builder = *llvm::unwrap(b);
    auto llvm_alignment = llvm::Align(alignment);
    return wrap(builder.Insert(new llvm::AllocaInst(llvm::unwrap(type), address_space, 0, llvm_alignment), string_ref(name)));
}

fn String stream_to_string(llvm::raw_string_ostream& stream)
{
    // No need to call stream.flush(); because it's string-based
    stream.flush();

    auto string = stream.str();
    auto length = string.length();

    u8* result = 0;
    if (length)
    {
        result = new u8[length + 1];
        memcpy(result, string.c_str(), length);
        result[length] = 0;
    }

    return String{ result, length };
}

EXPORT String llvm_function_to_string(llvm::Function& function)
{
    std::string buffer;
    llvm::raw_string_ostream os(buffer);
    function.print(os);
    os.flush();
    auto result = stream_to_string(os);
    return result;
}

EXPORT bool llvm_function_verify(LLVMValueRef function_value, String* error_message)
{
    std::string message_buffer;
    llvm::raw_string_ostream message_stream(message_buffer);

    auto& function = *llvm::unwrap<llvm::Function>(function_value);
    bool result = verifyFunction(function, &message_stream);
    *error_message = stream_to_string(message_stream);

    // We invert the condition because LLVM conventions are just stupid
    return !result;
}

EXPORT bool llvm_module_verify(LLVMModuleRef m, String* error_message)
{
    std::string message_buffer;
    llvm::raw_string_ostream message_stream(message_buffer);

    const auto& module = *llvm::unwrap(m);
    bool result = llvm::verifyModule(module, &message_stream);
    *error_message = stream_to_string(message_stream);

    // We invert the condition because LLVM conventions are just stupid
    return !result;
}

EXPORT String llvm_module_to_string(LLVMModuleRef module)
{
    std::string buffer;
    llvm::raw_string_ostream stream(buffer);
    llvm::unwrap(module)->print(stream, 0);

    return stream_to_string(stream);
}

EXPORT String llvm_default_target_triple()
{
    auto triple = llvm::sys::getDefaultTargetTriple();
    auto length = triple.length();

    u8* pointer = 0;
    if (length)
    {
        pointer = new u8[length + 1];
        memcpy(pointer, triple.c_str(), length);
        pointer[length] = 0;
    }

    return { pointer, length };
}

EXPORT String llvm_host_cpu_name()
{
    auto cpu = llvm::sys::getHostCPUName();
    auto result = String { (u8*)cpu.data(), cpu.size() };
    assert(result.pointer[result.length] == 0);
    return result;
}

EXPORT String llvm_host_cpu_features()
{
    llvm::SubtargetFeatures Features;
#if LLVM_VERSION_MAJOR >= 19
    auto host_cpu_features = llvm::sys::getHostCPUFeatures();
#else
    StringMap<bool> host_cpu_features;
    if (!sys::getHostCPUFeatures(host_cpu_features)) {
        return {};
    }
#endif

    for (const auto &[Feature, IsEnabled] : host_cpu_features)
    {
        Features.AddFeature(Feature, IsEnabled);
    }

    auto feature_string = Features.getString();
    auto length = feature_string.length();

    u8* result = 0;
    if (length)
    {
        result = new u8[length + 1];
        memcpy(result, feature_string.c_str(), length + 1);
        result[length] = 0;
    }

    return { result, length };
}

EXPORT void llvm_module_run_optimization_pipeline(LLVMModuleRef m, LLVMTargetMachineRef tm, BBLLVMOptimizationPipelineOptions options)
{
    auto module = llvm::unwrap(m);
    auto target_machine = (llvm::TargetMachine*)tm;
    // TODO: PGO
    // TODO: CS profile
    
    llvm::PipelineTuningOptions pipeline_tuning_options;
    pipeline_tuning_options.LoopUnrolling = options.loop_unrolling;
    pipeline_tuning_options.LoopInterleaving = options.loop_interleaving;
    pipeline_tuning_options.LoopVectorization = options.loop_vectorization;
    pipeline_tuning_options.SLPVectorization = options.slp_vectorization;
    pipeline_tuning_options.MergeFunctions = options.merge_functions;
    pipeline_tuning_options.CallGraphProfile = options.call_graph_profile;
    pipeline_tuning_options.UnifiedLTO = options.unified_lto;
    
    // TODO: instrumentation

    llvm::LoopAnalysisManager loop_analysis_manager;
    llvm::FunctionAnalysisManager function_analysis_manager;
    llvm::CGSCCAnalysisManager cgscc_analysis_manager;
    llvm::ModuleAnalysisManager module_analysis_manager;

    llvm::PassBuilder pass_builder(target_machine, pipeline_tuning_options); 

    if (options.assignment_tracking && options.debug_info != 0)
    {
        pass_builder.registerPipelineStartEPCallback([&](llvm::ModulePassManager& MPM, llvm::OptimizationLevel Level) {
                unused(Level);
                MPM.addPass(llvm::AssignmentTrackingPass());
            });
    }
    
    llvm::Triple target_triple = target_machine->getTargetTriple(); // Need to make a copy, incoming bugfix: https://github.com/llvm/llvm-project/pull/127718
    // TODO: add library (?)
    std::unique_ptr<llvm::TargetLibraryInfoImpl> TLII(llvm::driver::createTLII(target_triple, llvm::driver::VectorLibrary::NoLibrary));
    function_analysis_manager.registerPass([&] { return llvm::TargetLibraryAnalysis(*TLII); });

    pass_builder.registerModuleAnalyses(module_analysis_manager);
    pass_builder.registerCGSCCAnalyses(cgscc_analysis_manager);
    pass_builder.registerFunctionAnalyses(function_analysis_manager);
    pass_builder.registerLoopAnalyses(loop_analysis_manager);
    pass_builder.crossRegisterProxies(loop_analysis_manager, function_analysis_manager, cgscc_analysis_manager, module_analysis_manager);

    llvm::ModulePassManager module_pass_manager;

    if (options.verify_module)
    {
        module_pass_manager.addPass(llvm::VerifierPass());
    }

    bool thin_lto = false;
    bool lto = false;

    llvm::OptimizationLevel optimization_level;
    switch ((BBLLVMOptimizationLevel)options.optimization_level)
    {
        case BBLLVMOptimizationLevel::O0: optimization_level = llvm::OptimizationLevel::O0; break;
        case BBLLVMOptimizationLevel::O1: optimization_level = llvm::OptimizationLevel::O1; break;
        case BBLLVMOptimizationLevel::O2: optimization_level = llvm::OptimizationLevel::O2; break;
        case BBLLVMOptimizationLevel::O3: optimization_level = llvm::OptimizationLevel::O3; break;
        case BBLLVMOptimizationLevel::Os: optimization_level = llvm::OptimizationLevel::Os; break;
        case BBLLVMOptimizationLevel::Oz: optimization_level = llvm::OptimizationLevel::Oz; break;
    }

    // TODO: thin lto post-link
    // TODO: instrument
    if (thin_lto) {
        __builtin_trap(); // TODO
    } else if (lto) {
        __builtin_trap(); // TODO
    } else if (lto) {
        __builtin_trap(); // TODO
    } else {
         module_pass_manager.addPass(pass_builder.buildPerModuleDefaultPipeline(optimization_level));
    }

    // TODO: if emit bitcode/IR

    module_pass_manager.run(*module, module_analysis_manager);
}

EXPORT BBLLVMCodeGenerationPipelineResult llvm_module_run_code_generation_pipeline(LLVMModuleRef m, LLVMTargetMachineRef tm, const BBLLVMCodeGenerationPipelineOptions* options)
{
    auto module = llvm::unwrap(m);
    auto target_machine = (llvm::TargetMachine*)tm;

    // We still use the legacy PM to run the codegen pipeline since the new PM
    // does not work with the codegen pipeline.
    // FIXME: make the new PM work with the codegen pipeline.
    llvm::legacy::PassManager CodeGenPasses;
#if LLVM_VERSION_MAJOR >= 19
    if (options->optimize_when_possible)
    {
        CodeGenPasses.add(createTargetTransformInfoWrapperPass(target_machine->getTargetIRAnalysis()));
    }
#endif

    llvm::raw_pwrite_stream* dwarf_object_file = 0;
    if (options->output_dwarf_file_path.length)
    {
        __builtin_trap();
    }

    if (options->optimize_when_possible)
    {
        llvm::Triple target_triple = target_machine->getTargetTriple(); // Need to make a copy, incoming bugfix: https://github.com/llvm/llvm-project/pull/127718
        // TODO: add library (?)
        std::unique_ptr<llvm::TargetLibraryInfoImpl> TLII(llvm::driver::createTLII(target_triple, llvm::driver::VectorLibrary::NoLibrary));
        CodeGenPasses.add(new llvm::TargetLibraryInfoWrapperPass(*TLII));
    }

    std::unique_ptr<llvm::raw_pwrite_stream> stream;

    if (options->output_file_path.length)
    {
        std::error_code error_code;
        
        stream = std::make_unique<llvm::raw_fd_ostream>(string_ref(options->output_file_path), error_code, llvm::sys::fs::OF_None);

        if (error_code)
        {
            return BBLLVMCodeGenerationPipelineResult::failed_to_create_file;
        }
    }
    else
    {
        stream = std::make_unique<llvm::raw_null_ostream>();
    }

    llvm::CodeGenFileType file_type;
    switch (options->file_type)
    {
        case BBLLVMCodeGenerationFileType::assembly_file: file_type = llvm::CodeGenFileType::AssemblyFile; break;
        case BBLLVMCodeGenerationFileType::object_file: file_type = llvm::CodeGenFileType::ObjectFile; break;
        case BBLLVMCodeGenerationFileType::null: file_type = llvm::CodeGenFileType::Null; break;
    }

    auto disable_verify = !options->verify_module;
    if (target_machine->addPassesToEmitFile(CodeGenPasses, *stream, dwarf_object_file, file_type, disable_verify))
    {
        return BBLLVMCodeGenerationPipelineResult::failed_to_add_emit_passes;
    }

    CodeGenPasses.run(*module);

    return BBLLVMCodeGenerationPipelineResult::success;
}

#define lld_api_function_signature(name) bool name(llvm::ArrayRef<const char *> args, llvm::raw_ostream &stdoutOS, llvm::raw_ostream &stderrOS, bool exitEarly, bool disableOutput)

#define lld_link_decl(link_name) \
namespace link_name \
{\
    lld_api_function_signature(link);\
}

typedef lld_api_function_signature(LinkerFunction);

namespace lld
{
    lld_link_decl(coff);
    lld_link_decl(elf);
    lld_link_decl(mingw);
    lld_link_decl(macho);
    lld_link_decl(wasm);
}

fn LLDResult lld_api_generic(lld_api_args(), LinkerFunction linker_function)
{
    LLDResult result = {};
    auto arguments = llvm::ArrayRef(argument_pointer, argument_count);

    std::string stdout_string;
    llvm::raw_string_ostream stdout_stream(stdout_string);

    std::string stderr_string;
    llvm::raw_string_ostream stderr_stream(stderr_string);

    result.success = linker_function(arguments, stdout_stream, stderr_stream, exit_early, disable_output);

    auto stdout_length = stdout_string.length();
    if (stdout_length)
    {
        auto* stdout_pointer = new u8[stdout_length + 1];
        memcpy(stdout_pointer, stdout_string.data(), stdout_length);
        result.stdout_string = { stdout_pointer, stdout_length };
        stdout_pointer[stdout_length] = 0;
    }

    auto stderr_length = stderr_string.length();
    if (stderr_length)
    {
        auto* stderr_pointer = new u8[stderr_length + 1];
        memcpy(stderr_pointer, stderr_string.data(), stderr_length);
        result.stderr_string = { stderr_pointer, stderr_length };
        stderr_pointer[stderr_length] = 0;
    }

    // TODO: should we only call it on success?
    lld::CommonLinkerContext::destroy();

    return result;
}

#define lld_api_function_impl(link_name) \
EXPORT lld_api_function_decl(link_name)\
{\
    return lld_api_generic(argument_pointer, argument_count, exit_early, disable_output, lld::link_name::link);\
}

// lld_api_function_impl(coff)
lld_api_function_impl(elf)
// lld_api_function_impl(mingw)
// lld_api_function_impl(macho)
// lld_api_function_impl(wasm)
