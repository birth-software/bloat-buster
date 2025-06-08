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

EXPORT void llvm_subprogram_replace_type(LLVMMetadataRef subprogram, LLVMMetadataRef subroutine_type)
{
    auto sp = llvm::unwrap<llvm::DISubprogram>(subprogram);
    sp->replaceType(llvm::unwrap<llvm::DISubroutineType>(subroutine_type));
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
        
        stream = std::make_unique<llvm::raw_fd_ostream>(llvm::StringRef((char*)options->output_file_path.pointer, options->output_file_path.length), error_code, llvm::sys::fs::OF_None);

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
