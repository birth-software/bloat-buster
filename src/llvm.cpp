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

EXPORT unsigned llvm_integer_type_get_bit_count(const llvm::IntegerType& integer_type)
{
    auto result = integer_type.getBitWidth();
    return result;
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

EXPORT void llvm_global_variable_add_debug_info(llvm::GlobalVariable& global, llvm::DIGlobalVariableExpression* debug_global_variable)
{
    global.addDebugInfo(debug_global_variable);
}

EXPORT void llvm_global_variable_delete(llvm::GlobalVariable* global)
{
    delete global;
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

EXPORT bool llvm_value_has_one_use(LLVMValueRef value)
{
    auto v = llvm::unwrap(value);
    auto result = v->hasOneUse();
    return result;
}

EXPORT LLVMValueRef llvm_basic_block_user_begin(LLVMBasicBlockRef basic_block)
{
    llvm::Value* value = *llvm::unwrap(basic_block)->user_begin();
    return wrap(value);
}

EXPORT void llvm_basic_block_delete(LLVMBasicBlockRef basic_block)
{
    delete llvm::unwrap(basic_block);
}

EXPORT llvm::BranchInst* llvm_value_to_branch(llvm::Value* value)
{
    auto* result = dyn_cast<llvm::BranchInst>(value);
    return result;
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

enum class BBLLVMAttributeFramePointerKind : u8
{
    None = 0,
    Reserved = 1,
    NonLeaf = 2,
    All = 3,
};

const unsigned BB_LLVM_ONLY_USED = 1U << 1;
const unsigned BB_LLVM_ONLY_GPR = 1U << 2;
const unsigned BB_LLVM_ONLY_ARG = 1U << 3;

enum class BBLLVMZeroCallUsedRegsKind : unsigned int
{
    // Don't zero any call-used regs.
    Skip = 1U << 0,
    // Only zeros call-used GPRs used in the fn and pass args.
    UsedGPRArg = BB_LLVM_ONLY_USED | BB_LLVM_ONLY_GPR | BB_LLVM_ONLY_ARG,
    // Only zeros call-used GPRs used in the fn.
    UsedGPR = BB_LLVM_ONLY_USED | BB_LLVM_ONLY_GPR,
    // Only zeros call-used regs used in the fn and pass args.
    UsedArg = BB_LLVM_ONLY_USED | BB_LLVM_ONLY_ARG,
    // Only zeros call-used regs used in the fn.
    Used = BB_LLVM_ONLY_USED,
    // Zeros all call-used GPRs that pass args.
    AllGPRArg = BB_LLVM_ONLY_GPR | BB_LLVM_ONLY_ARG,
    // Zeros all call-used GPRs.
    AllGPR = BB_LLVM_ONLY_GPR,
    // Zeros all call-used regs that pass args.
    AllArg = BB_LLVM_ONLY_ARG,
    // Zeros all call-used regs.
    All = 0,
};

enum class BBLLVMFPClassTest : unsigned
{
    None = 0,

    SNan = 0x0001,
    QNan = 0x0002,
    NegInf = 0x0004,
    NegNormal = 0x0008,
    NegSubnormal = 0x0010,
    NegZero = 0x0020,
    PosZero = 0x0040,
    PosSubnormal = 0x0080,
    PosNormal = 0x0100,
    PosInf = 0x0200,

    Nan = SNan | QNan,
    Inf = PosInf | NegInf,
    Normal = PosNormal | NegNormal,
    Subnormal = PosSubnormal | NegSubnormal,
    Zero = PosZero | NegZero,
    PosFinite = PosNormal | PosSubnormal | PosZero,
    NegFinite = NegNormal | NegSubnormal | NegZero,
    Finite = PosFinite | NegFinite,
    Positive = PosFinite | PosInf,
    Negative = NegFinite | NegInf,

    AllFlags = Nan | Inf | Finite,
};

fn llvm::AttributeSet build_argument_attributes(LLVMContextRef context, BBLLVMArgumentAttributes* attributes)
{
    llvm::AttrBuilder builder(*llvm::unwrap(context));

    if (attributes->alignment)
    {
        builder.addAlignmentAttr(attributes->alignment);
    }

    if (attributes->no_alias)
    {
        builder.addAttribute(llvm::Attribute::NoAlias);
    }

    if (attributes->non_null)
    {
        builder.addAttribute(llvm::Attribute::NonNull);
    }

    if (attributes->no_undef)
    {
        builder.addAttribute(llvm::Attribute::NoUndef);
    }

    if (attributes->sign_extend)
    {
        builder.addAttribute(llvm::Attribute::SExt);
    }

    if (attributes->zero_extend)
    {
        builder.addAttribute(llvm::Attribute::ZExt);
    }

    if (attributes->in_reg)
    {
        builder.addAttribute(llvm::Attribute::InReg);
    }

    if (attributes->no_fp_class)
    {
        __builtin_trap(); // TODO
    }

    if (attributes->struct_return)
    {
        builder.addStructRetAttr(llvm::unwrap(attributes->semantic_type));
    }

    if (attributes->writable)
    {
        builder.addAttribute(llvm::Attribute::Writable);
    }

    if (attributes->dead_on_unwind)
    {
        builder.addAttribute(llvm::Attribute::DeadOnUnwind);
    }

    if (attributes->in_alloca)
    {
        __builtin_trap(); // TODO
    }

    if (attributes->dereferenceable)
    {
        builder.addDereferenceableAttr(attributes->dereferenceable_bytes);
    }

    if (attributes->dereferenceable_or_null)
    {
        builder.addDereferenceableOrNullAttr(attributes->dereferenceable_bytes);
    }

    if (attributes->nest)
    {
        builder.addAttribute(llvm::Attribute::Nest);
    }

    if (attributes->by_value)
    {
        builder.addByValAttr(llvm::unwrap(attributes->semantic_type));
    }

    if (attributes->by_reference)
    {
        builder.addByRefAttr(llvm::unwrap(attributes->semantic_type));
    }

    if (attributes->no_capture)
    {
        builder.addAttribute(llvm::Attribute::NoCapture);
    }

    auto attribute_set = llvm::AttributeSet::get(*llvm::unwrap(context), builder);
    return attribute_set;
}

inline fn BBLLVMAttributeList llvm_attribute_list_to_abi(llvm::AttributeList list)
{
    static_assert(sizeof(llvm::AttributeList) == sizeof(uintptr_t));
    static_assert(sizeof(BBLLVMAttributeList) == sizeof(uintptr_t));

    return list.getRawPointer();
}

inline fn llvm::AttributeList abi_attribute_list_to_llvm(BBLLVMAttributeList list)
{
    static_assert(sizeof(llvm::AttributeList) == sizeof(uintptr_t));
    static_assert(sizeof(BBLLVMAttributeList) == sizeof(uintptr_t));
    auto attribute_list = *(llvm::AttributeList*)&list;
    return attribute_list;
}

EXPORT BBLLVMAttributeList llvm_attribute_list_build(LLVMContextRef context, BBLLVMAttributeListOptions* attributes, bool call_site)
{
    llvm::AttrBuilder function_attribute_builder(*llvm::unwrap(context));

    if (attributes->function.prefer_vector_width.length)
    {
        function_attribute_builder.addAttribute("prefer-vector-width", string_ref(attributes->function.prefer_vector_width));
    }

    if (attributes->function.stack_protector_buffer_size.length)
    {
        function_attribute_builder.addAttribute("stack-protector-buffer-size", string_ref(attributes->function.stack_protector_buffer_size));
    }

    if (attributes->function.flags0.noreturn)
    {
        function_attribute_builder.addAttribute(llvm::Attribute::NoReturn);
    }

    if (attributes->function.flags0.cmse_ns_call)
    {
        function_attribute_builder.addAttribute("cmse_nonsecure_call");
    }

    if (attributes->function.flags0.nounwind)
    {
        function_attribute_builder.addAttribute(llvm::Attribute::NoUnwind);
    }

    if (attributes->function.flags0.returns_twice)
    {
        function_attribute_builder.addAttribute(llvm::Attribute::ReturnsTwice);
    }

    if (attributes->function.flags0.cold)
    {
        function_attribute_builder.addAttribute(llvm::Attribute::Cold);
    }

    if (attributes->function.flags0.hot)
    {
        function_attribute_builder.addAttribute(llvm::Attribute::Hot);
    }

    if (attributes->function.flags0.no_duplicate)
    {
        function_attribute_builder.addAttribute(llvm::Attribute::NoDuplicate);
    }

    if (attributes->function.flags0.convergent)
    {
        function_attribute_builder.addAttribute(llvm::Attribute::Convergent);
    }

    if (attributes->function.flags0.no_merge)
    {
        function_attribute_builder.addAttribute(llvm::Attribute::NoMerge);
    }

    if (attributes->function.flags0.will_return)
    {
        function_attribute_builder.addAttribute(llvm::Attribute::WillReturn);
    }

    if (attributes->function.flags0.no_caller_saved_registers)
    {
        function_attribute_builder.addAttribute("no-caller-saved-registers");
    }

    if (attributes->function.flags0.no_cf_check)
    {
        function_attribute_builder.addAttribute(llvm::Attribute::NoCfCheck);
    }

    if (attributes->function.flags0.no_callback)
    {
        function_attribute_builder.addAttribute(llvm::Attribute::NoCallback);
    }

    if (attributes->function.flags0.alloc_size)
    {
        __builtin_trap(); // TODO
    }

    if (attributes->function.flags0.uniform_work_group_size)
    {
        __builtin_trap(); // TODO
    }

    if (attributes->function.flags0.aarch64_pstate_sm_body)
    {
        function_attribute_builder.addAttribute("aarch64_pstate_sm_body");
    }

    if (attributes->function.flags0.aarch64_pstate_sm_enabled)
    {
        function_attribute_builder.addAttribute("aarch64_pstate_sm_enabled");
    }

    if (attributes->function.flags0.aarch64_pstate_sm_compatible)
    {
        function_attribute_builder.addAttribute("aarch64_pstate_sm_compatible");
    }

    if (attributes->function.flags0.aarch64_preserves_za)
    {
        function_attribute_builder.addAttribute("aarch64_preserves_za");
    }

    if (attributes->function.flags0.aarch64_in_za)
    {
        function_attribute_builder.addAttribute("aarch64_in_za");
    }

    if (attributes->function.flags0.aarch64_out_za)
    {
        function_attribute_builder.addAttribute("aarch64_out_za");
    }

    if (attributes->function.flags0.aarch64_inout_za)
    {
        function_attribute_builder.addAttribute("aarch64_inout_za");
    }

    if (attributes->function.flags0.aarch64_preserves_zt0)
    {
        function_attribute_builder.addAttribute("aarch64_preserves_zt0");
    }

    if (attributes->function.flags0.aarch64_in_zt0)
    {
        function_attribute_builder.addAttribute("aarch64_in_zt0");
    }

    if (attributes->function.flags0.aarch64_out_zt0)
    {
        function_attribute_builder.addAttribute("aarch64_out_zt0");
    }

    if (attributes->function.flags0.aarch64_inout_zt0)
    {
        function_attribute_builder.addAttribute("aarch64_inout_zt0");
    }

    if (attributes->function.flags0.optimize_for_size)
    {
        function_attribute_builder.addAttribute(llvm::Attribute::OptimizeForSize);
    }

    if (attributes->function.flags0.min_size)
    {
        function_attribute_builder.addAttribute(llvm::Attribute::MinSize);
    }

    if (attributes->function.flags0.no_red_zone)
    {
        function_attribute_builder.addAttribute(llvm::Attribute::NoRedZone);
    }

    if (attributes->function.flags0.indirect_tls_seg_refs)
    {
        function_attribute_builder.addAttribute("indirect-tls-seg-refs");
    }

    if (attributes->function.flags0.no_implicit_floats)
    {
        function_attribute_builder.addAttribute(llvm::Attribute::NoImplicitFloat);
    }
    
    if (attributes->function.flags0.sample_profile_suffix_elision_policy)
    {
        function_attribute_builder.addAttribute("sample-profile-suffix-elision-policy", "selected");
    }

    if (attributes->function.flags0.memory_none)
    {
        function_attribute_builder.addMemoryAttr(llvm::MemoryEffects::none());
    }

    if (attributes->function.flags0.memory_readonly)
    {
        function_attribute_builder.addMemoryAttr(llvm::MemoryEffects::readOnly());
    }
    
    if (attributes->function.flags0.memory_inaccessible_or_arg_memory_only)
    {
        function_attribute_builder.addMemoryAttr(llvm::MemoryEffects::inaccessibleOrArgMemOnly());
    }

    if (attributes->function.flags0.memory_arg_memory_only)
    {
        llvm::Attribute attribute = function_attribute_builder.getAttribute(llvm::Attribute::Memory);
        function_attribute_builder.addMemoryAttr(attribute.getMemoryEffects() | llvm::MemoryEffects::argMemOnly());
    }
    
    // TODO: branch protection function attributes
    
    // TODO: cpu features

    if (call_site)
    {
        if (attributes->function.flags0.call_no_builtins)
        {
            function_attribute_builder.addAttribute(llvm::Attribute::NoBuiltin);
        }
    }
    else
    {
        if (attributes->function.definition_probe_stack.length)
        {
            function_attribute_builder.addAttribute("probe-stack", string_ref(attributes->function.definition_probe_stack));
        }

        if (attributes->function.definition_stack_probe_size.length)
        {
            function_attribute_builder.addAttribute("stack-probe-size", string_ref(attributes->function.definition_stack_probe_size));
        }

        llvm::StringRef frame_pointer_kind_name;
        switch ((BBLLVMAttributeFramePointerKind) attributes->function.flags0.definition_frame_pointer_kind)
        {
            case BBLLVMAttributeFramePointerKind::None: frame_pointer_kind_name = "none"; break;
            case BBLLVMAttributeFramePointerKind::Reserved: frame_pointer_kind_name = "reserved"; break;
            case BBLLVMAttributeFramePointerKind::NonLeaf: frame_pointer_kind_name = "non-leaf"; break;
            case BBLLVMAttributeFramePointerKind::All: frame_pointer_kind_name = "all"; break;
        }
        function_attribute_builder.addAttribute("frame-pointer", frame_pointer_kind_name);

        if (attributes->function.flags0.definition_less_precise_fpmad)
        {
            function_attribute_builder.addAttribute("less-precise-fp-mad", "true");
        }

        if (attributes->function.flags0.definition_null_pointer_is_valid)
        {
            function_attribute_builder.addAttribute(llvm::Attribute::NullPointerIsValid);
        }

        if (attributes->function.flags0.definition_no_trapping_fp_math)
        {
            function_attribute_builder.addAttribute("no-trapping-math", "true");
        }

        if (attributes->function.flags0.definition_no_infs_fp_math)
        {
            function_attribute_builder.addAttribute("no-infs-fp-math", "true");
        }

        if (attributes->function.flags0.definition_no_nans_fp_math)
        {
            function_attribute_builder.addAttribute("no-nans-fp-math", "true");
        }

        if (attributes->function.flags0.definition_approx_func_fp_math)
        {
            function_attribute_builder.addAttribute("approx-func-fp-math", "true");
        }

        if (attributes->function.flags0.definition_unsafe_fp_math)
        {
            function_attribute_builder.addAttribute("unsafe-fp-math", "true");
        }

        if (attributes->function.flags0.definition_use_soft_float)
        {
            function_attribute_builder.addAttribute("use-soft-float", "true");
        }

        if (attributes->function.flags0.definition_no_signed_zeroes_fp_math)
        {
            function_attribute_builder.addAttribute("no-signed-zeros-fp-math", "true");
        }

        if (attributes->function.flags0.definition_stack_realignment)
        {
            function_attribute_builder.addAttribute("stackrealign");
        }

        if (attributes->function.flags0.definition_backchain)
        {
            function_attribute_builder.addAttribute("backchain");
        }

        if (attributes->function.flags0.definition_split_stack)
        {
            function_attribute_builder.addAttribute("split-stack");
        }

        if (attributes->function.flags0.definition_speculative_load_hardening)
        {
            function_attribute_builder.addAttribute("split-stack");
        }

        if (attributes->function.flags0.definition_zero_call_used_registers != ZeroCallUsedRegsKind::all)
        {
            __builtin_trap(); // TODO
        }

        // TODO: denormal builtins

        if (attributes->function.flags0.definition_non_lazy_bind)
        {
            function_attribute_builder.addAttribute(llvm::Attribute::NonLazyBind);
        }

        if (attributes->function.flags0.definition_cmse_nonsecure_entry)
        {
            function_attribute_builder.addAttribute("cmse_nonsecure_entry");
        }

        llvm::UWTableKind unwind_table_kind;
        switch ((BBLLVMUWTableKind)attributes->function.flags0.definition_unwind_table_kind)
        {
            case BBLLVMUWTableKind::None: unwind_table_kind = llvm::UWTableKind::None; break;
            case BBLLVMUWTableKind::Sync: unwind_table_kind = llvm::UWTableKind::Sync; break;
            case BBLLVMUWTableKind::Async: unwind_table_kind = llvm::UWTableKind::Async; break;
        }

        function_attribute_builder.addUWTableAttr(unwind_table_kind);

        if (attributes->function.flags1.definition_disable_tail_calls)
        {
            function_attribute_builder.addAttribute("disable-tail-calls", "true");
        }

        if (attributes->function.flags1.definition_stack_protect_strong)
        {
            function_attribute_builder.addAttribute(llvm::Attribute::StackProtectStrong);
        }

        if (attributes->function.flags1.definition_stack_protect)
        {
            function_attribute_builder.addAttribute(llvm::Attribute::StackProtect);
        }

        if (attributes->function.flags1.definition_stack_protect_req)
        {
            function_attribute_builder.addAttribute(llvm::Attribute::StackProtectReq);
        }

        if (attributes->function.flags1.definition_aarch64_new_za)
        {
            function_attribute_builder.addAttribute("aarch64_new_za");
        }

        if (attributes->function.flags1.definition_aarch64_new_zt0)
        {
            function_attribute_builder.addAttribute("aarch64_new_zt0");
        }

        if (attributes->function.flags1.definition_optimize_none)
        {
            function_attribute_builder.addAttribute(llvm::Attribute::OptimizeNone);
        }

        if (attributes->function.flags1.definition_naked)
        {
            function_attribute_builder.addAttribute(llvm::Attribute::Naked);
        }

        if (attributes->function.flags1.definition_inline_hint)
        {
            function_attribute_builder.addAttribute(llvm::Attribute::InlineHint);
        }
    }

    auto function_attributes = llvm::AttributeSet::get(*llvm::unwrap(context), function_attribute_builder);

    auto return_attributes = build_argument_attributes(context, &attributes->return_);

    llvm::AttributeSet argument_attribute_buffer[128];
    assert(attributes->argument_count < array_length(argument_attribute_buffer));

    for (u64 i = 0; i < attributes->argument_count; i += 1)
    {
        auto attribute_set = build_argument_attributes(context, &attributes->argument_pointer[i]);
        argument_attribute_buffer[i] = attribute_set;
    }

    llvm::ArrayRef<llvm::AttributeSet> argument_attributes = llvm::ArrayRef(argument_attribute_buffer, attributes->argument_count);

    auto attribute_list = llvm::AttributeList::get(*llvm::unwrap(context), function_attributes, return_attributes, argument_attributes);

    return llvm_attribute_list_to_abi(attribute_list);
}

EXPORT bool llvm_instruction_is_call_base(llvm::Instruction* instruction)
{
    return isa<llvm::CallBase>(instruction);
}

EXPORT void llvm_function_set_attributes(LLVMValueRef f, BBLLVMAttributeList attribute_list_handle)
{
    auto* function = llvm::unwrap<llvm::Function>(f);
    auto attribute_list = abi_attribute_list_to_llvm(attribute_list_handle);
    function->setAttributes(attribute_list);
}

EXPORT void llvm_call_base_set_attributes(LLVMValueRef call_value, BBLLVMAttributeList attribute_list_handle)
{
    auto call = llvm::unwrap<llvm::CallBase>(call_value);
    auto attribute_list = abi_attribute_list_to_llvm(attribute_list_handle);
    call->setAttributes(attribute_list);
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
        result = new u8[length];
        memcpy(result, string.c_str(), length);
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
        pointer = new u8[length];
        memcpy(pointer, triple.c_str(), length);
    }

    return { pointer, length };
}

EXPORT String llvm_host_cpu_name()
{
    auto cpu = llvm::sys::getHostCPUName();
    return { (u8*)cpu.data(), cpu.size() };
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
        result = new u8[length];
        memcpy(result, feature_string.c_str(), length);
    }

    return { result, length };
}

EXPORT LLVMTargetMachineRef llvm_create_target_machine(const BBLLVMTargetMachineCreate* create, String* error_message)
{
    std::string error_message_string;
    const llvm::Target* target = llvm::TargetRegistry::lookupTarget(string_ref(create->target_triple), error_message_string);

    if (target)
    {
        std::optional<llvm::CodeModel::Model> code_model;
        switch (create->code_model)
        {
            case BBLLVMCodeModel::none: code_model = std::nullopt; break;
            case BBLLVMCodeModel::tiny: code_model = llvm::CodeModel::Tiny; break;
            case BBLLVMCodeModel::small: code_model = llvm::CodeModel::Small; break;
            case BBLLVMCodeModel::kernel: code_model = llvm::CodeModel::Kernel; break;
            case BBLLVMCodeModel::medium: code_model = llvm::CodeModel::Medium; break;
            case BBLLVMCodeModel::large: code_model = llvm::CodeModel::Large; break;
        }

        std::optional<llvm::Reloc::Model> relocation_model;

        switch (create->relocation_model)
        {
            case BBLLVMRelocationModel::default_relocation: relocation_model = std::nullopt; break;
            case BBLLVMRelocationModel::static_relocation: relocation_model = llvm::Reloc::Static; break;
            case BBLLVMRelocationModel::pic: relocation_model = llvm::Reloc::PIC_; break;
            case BBLLVMRelocationModel::dynamic_no_pic: relocation_model = llvm::Reloc::DynamicNoPIC; break;
            case BBLLVMRelocationModel::ropi: relocation_model = llvm::Reloc::ROPI; break;
            case BBLLVMRelocationModel::rwpi: relocation_model = llvm::Reloc::RWPI; break;
            case BBLLVMRelocationModel::ropi_rwpi: relocation_model = llvm::Reloc::ROPI_RWPI; break;
        }

        llvm::CodeGenOptLevel optimization_level;
        switch (create->optimization_level)
        {
            case BBLLVMCodeGenerationOptimizationLevel::none: optimization_level = llvm::CodeGenOptLevel::None; break;
            case BBLLVMCodeGenerationOptimizationLevel::less: optimization_level = llvm::CodeGenOptLevel::Less; break;
            case BBLLVMCodeGenerationOptimizationLevel::normal: optimization_level = llvm::CodeGenOptLevel::Default; break;
            case BBLLVMCodeGenerationOptimizationLevel::aggressive: optimization_level = llvm::CodeGenOptLevel::Aggressive; break;
        }

        // INFO: This calls the default constructor, so all LLVM defaults are set and we only override what we control
        llvm::TargetOptions target_options;

        target_options.UnsafeFPMath = create->target_options.unsafe_fp_math;
        target_options.NoInfsFPMath = create->target_options.no_infs_fp_math;
        target_options.NoNaNsFPMath = create->target_options.no_nans_fp_math;
        target_options.NoTrappingFPMath = create->target_options.no_trapping_fp_math;
        target_options.NoSignedZerosFPMath = create->target_options.no_signed_zeroes_fp_math;
        target_options.ApproxFuncFPMath = create->target_options.approx_func_fp_math;
        target_options.EnableAIXExtendedAltivecABI = create->target_options.enable_aix_extended_altivec_abi;
        target_options.HonorSignDependentRoundingFPMathOption = create->target_options.honor_sign_dependent_rounding_fp_math;
        target_options.NoZerosInBSS = create->target_options.no_zeroes_in_bss;
        target_options.GuaranteedTailCallOpt = create->target_options.guaranteed_tail_call_optimization;
        target_options.StackSymbolOrdering = create->target_options.stack_symbol_ordering;
        target_options.EnableFastISel = create->target_options.enable_fast_isel;
        target_options.EnableGlobalISel = create->target_options.enable_global_isel;

        auto global_isel_abort_mode = (BBLLVMGlobalISelAbortMode)create->target_options.global_isel_abort_mode;
        switch (global_isel_abort_mode)
        {
            case BBLLVMGlobalISelAbortMode::disable: target_options.GlobalISelAbort = llvm::GlobalISelAbortMode::Disable; break;
            case BBLLVMGlobalISelAbortMode::enable: target_options.GlobalISelAbort = llvm::GlobalISelAbortMode::Enable; break;
            case BBLLVMGlobalISelAbortMode::disable_with_diag: target_options.GlobalISelAbort = llvm::GlobalISelAbortMode::DisableWithDiag; break;
        }
        auto swift_async_frame_pointer = (BBLLVMSwiftAsyncFramePointerMode)create->target_options.swift_async_frame_pointer;
        switch (swift_async_frame_pointer)
        {
            case BBLLVMSwiftAsyncFramePointerMode::deployment_based: target_options.SwiftAsyncFramePointer = llvm::SwiftAsyncFramePointerMode::DeploymentBased; break;
            case BBLLVMSwiftAsyncFramePointerMode::always: target_options.SwiftAsyncFramePointer = llvm::SwiftAsyncFramePointerMode::Always; break;
            case BBLLVMSwiftAsyncFramePointerMode::never: target_options.SwiftAsyncFramePointer = llvm::SwiftAsyncFramePointerMode::Never; break;
        }

        target_options.UseInitArray = create->target_options.use_init_array;
        target_options.DisableIntegratedAS = create->target_options.disable_integrated_assembler;
        target_options.FunctionSections = create->target_options.function_sections;
        target_options.DataSections = create->target_options.data_sections;
        target_options.IgnoreXCOFFVisibility = create->target_options.ignore_xcoff_visibility;
        target_options.XCOFFTracebackTable = create->target_options.xcoff_traceback_table;
        target_options.UniqueSectionNames = create->target_options.unique_section_names;
        target_options.UniqueBasicBlockSectionNames = create->target_options.unique_basic_block_section_names;
#if LLVM_VERSION_MAJOR >= 19
        target_options.SeparateNamedSections = create->target_options.separate_named_sections;
#endif
        target_options.TrapUnreachable = create->target_options.trap_unreachable;
        target_options.NoTrapAfterNoreturn = create->target_options.no_trap_after_noreturn;
        target_options.TLSSize = create->target_options.tls_size;
        target_options.EmulatedTLS = create->target_options.emulated_tls;
        target_options.EnableTLSDESC = create->target_options.enable_tls_descriptors;
        target_options.EnableIPRA = create->target_options.enable_ipra;
        target_options.EmitStackSizeSection = create->target_options.emit_stack_size_section;
        target_options.EnableMachineOutliner = create->target_options.enable_machine_outliner;
        target_options.EnableMachineFunctionSplitter = create->target_options.enable_machine_function_splitter;
        target_options.SupportsDefaultOutlining = create->target_options.supports_default_outlining;
        target_options.EmitAddrsig = create->target_options.emit_address_significance_table;
#if LLVM_VERSION_MAJOR >= 19
        target_options.BBAddrMap = create->target_options.bb_address_map;
#endif

        auto bb_sections = (BBLLVMBasicBlockSection) create->target_options.bb_sections;
        switch (bb_sections)
        {
            case BBLLVMBasicBlockSection::all: target_options.BBSections = llvm::BasicBlockSection::All; break;
            case BBLLVMBasicBlockSection::list: target_options.BBSections = llvm::BasicBlockSection::List; break;
            case BBLLVMBasicBlockSection::preset: target_options.BBSections = llvm::BasicBlockSection::Preset; break;
            case BBLLVMBasicBlockSection::none: target_options.BBSections = llvm::BasicBlockSection::None; break;
        }

        target_options.EmitCallSiteInfo = create->target_options.emit_call_site_information;
        target_options.SupportsDebugEntryValues = create->target_options.supports_debug_entry_values;
        target_options.EnableDebugEntryValues = create->target_options.enable_debug_entry_values;
        target_options.ValueTrackingVariableLocations = create->target_options.value_tracking_variable_locations;
        target_options.ForceDwarfFrameSection = create->target_options.force_dwarf_frame_section;
        target_options.XRayFunctionIndex = create->target_options.xray_function_index;
        target_options.DebugStrictDwarf = create->target_options.debug_strict_dwarf;
        target_options.Hotpatch = create->target_options.hotpatch;
        target_options.PPCGenScalarMASSEntries = create->target_options.ppc_gen_scalar_mass_entries;
        target_options.JMCInstrument = create->target_options.jmc_instrument;
        target_options.EnableCFIFixup = create->target_options.enable_cfi_fixup;
        target_options.MisExpect = create->target_options.mis_expect;
        target_options.XCOFFReadOnlyPointers = create->target_options.xcoff_read_only_pointers;

        auto float_abi = (BBLLVMFloatAbi) create->target_options.float_abi;
        switch (float_abi)
        {
            case BBLLVMFloatAbi::normal: target_options.FloatABIType = llvm::FloatABI::Default; break;
            case BBLLVMFloatAbi::soft: target_options.FloatABIType = llvm::FloatABI::Soft; break;
            case BBLLVMFloatAbi::hard: target_options.FloatABIType = llvm::FloatABI::Hard; break;
        }

        auto thread_model = (BBLLVMThreadModel) create->target_options.thread_model;
        switch (thread_model)
        {
            case BBLLVMThreadModel::posix: target_options.ThreadModel = llvm::ThreadModel::POSIX; break;
            case BBLLVMThreadModel::single: target_options.ThreadModel = llvm::ThreadModel::Single; break;
        }

        auto fp_op_fusion_mode = (BBLLVMFPOpFusion) create->target_options.fp_op_fusion_mode;
        switch (fp_op_fusion_mode)
        {
            case BBLLVMFPOpFusion::fast: target_options.AllowFPOpFusion = llvm::FPOpFusion::Fast; break;
            case BBLLVMFPOpFusion::standard: target_options.AllowFPOpFusion = llvm::FPOpFusion::Standard; break;
            case BBLLVMFPOpFusion::strict: target_options.AllowFPOpFusion = llvm::FPOpFusion::Strict; break;
        }

        auto eabi_version = (BBLLVMEAbi) create->target_options.eabi_version;
        switch (eabi_version)
        {
            case BBLLVMEAbi::unknown: target_options.EABIVersion = llvm::EABI::Unknown; break;
            case BBLLVMEAbi::normal: target_options.EABIVersion = llvm::EABI::Default; break;
            case BBLLVMEAbi::eabi4: target_options.EABIVersion = llvm::EABI::EABI4; break;
            case BBLLVMEAbi::eabi5: target_options.EABIVersion = llvm::EABI::EABI5; break;
            case BBLLVMEAbi::gnu: target_options.EABIVersion = llvm::EABI::GNU; break;
        }

        auto debugger_kind = (BBLLVMDebuggerKind) create->target_options.debugger_kind;
        switch (debugger_kind)
        {
            case BBLLVMDebuggerKind::normal: target_options.DebuggerTuning = llvm::DebuggerKind::Default; break;
            case BBLLVMDebuggerKind::gdb: target_options.DebuggerTuning = llvm::DebuggerKind::GDB; break;
            case BBLLVMDebuggerKind::lldb: target_options.DebuggerTuning = llvm::DebuggerKind::LLDB; break;
            case BBLLVMDebuggerKind::sce: target_options.DebuggerTuning = llvm::DebuggerKind::SCE; break;
            case BBLLVMDebuggerKind::dbx: target_options.DebuggerTuning = llvm::DebuggerKind::DBX; break;
        }
        
        auto exception_handling = (BBLLVMExceptionHandling) create->target_options.exception_handling;
        switch (exception_handling)
        {
            case BBLLVMExceptionHandling::none: target_options.ExceptionModel = llvm::ExceptionHandling::None; break;
            case BBLLVMExceptionHandling::dwarf_cfi: target_options.ExceptionModel = llvm::ExceptionHandling::DwarfCFI; break;
            case BBLLVMExceptionHandling::setjmp_longjmp: target_options.ExceptionModel = llvm::ExceptionHandling::SjLj; break;
            case BBLLVMExceptionHandling::arm: target_options.ExceptionModel = llvm::ExceptionHandling::ARM; break;
            case BBLLVMExceptionHandling::win_eh: target_options.ExceptionModel = llvm::ExceptionHandling::WinEH; break;
            case BBLLVMExceptionHandling::wasm: target_options.ExceptionModel = llvm::ExceptionHandling::Wasm; break;
            case BBLLVMExceptionHandling::aix: target_options.ExceptionModel = llvm::ExceptionHandling::AIX; break;
            case BBLLVMExceptionHandling::zos: target_options.ExceptionModel = llvm::ExceptionHandling::ZOS; break;
        }

        target_options.LoopAlignment = create->target_options.loop_alignment;
        target_options.BinutilsVersion = { create->target_options.binutils_version[0], create->target_options.binutils_version[1] };

        if (create->target_options.mc.abi_name.length)
        {
            target_options.MCOptions.ABIName = { (char*)create->target_options.mc.abi_name.pointer, create->target_options.mc.abi_name.length };
        }

        if (create->target_options.mc.assembly_language.length)
        {
            target_options.MCOptions.AssemblyLanguage = { (char*)create->target_options.mc.assembly_language.pointer, create->target_options.mc.assembly_language.length };
        }

        if (create->target_options.mc.split_dwarf_file.length)
        {
            target_options.MCOptions.SplitDwarfFile = { (char*)create->target_options.mc.split_dwarf_file.pointer, create->target_options.mc.split_dwarf_file.length };
        }

        if (create->target_options.mc.as_secure_log_file.length)
        {
            target_options.MCOptions.AsSecureLogFile = { (char*)create->target_options.mc.as_secure_log_file.pointer, create->target_options.mc.as_secure_log_file.length };
        }

        if (create->target_options.mc.argv_count)
        {
            target_options.MCOptions.Argv0 = create->target_options.mc.argv0;

            // TODO:
            __builtin_trap();
        }

        if (create->target_options.mc.integrated_assembler_search_path_count)
        {
            // TODO:
            __builtin_trap();
        }

        target_options.MCOptions.MCRelaxAll = create->target_options.mc.relax_all;
        target_options.MCOptions.MCNoExecStack = create->target_options.mc.no_exec_stack;
        target_options.MCOptions.MCFatalWarnings = create->target_options.mc.fatal_warnings;
        target_options.MCOptions.MCNoWarn = create->target_options.mc.no_warn;
        target_options.MCOptions.MCNoDeprecatedWarn = create->target_options.mc.no_deprecated_warn;
        target_options.MCOptions.MCNoTypeCheck = create->target_options.mc.no_type_check;
        target_options.MCOptions.MCSaveTempLabels = create->target_options.mc.save_temp_labels;
        target_options.MCOptions.MCIncrementalLinkerCompatible = create->target_options.mc.incremental_linker_compatible;
#if LLVM_VERSION_MAJOR >= 19
        target_options.MCOptions.FDPIC = create->target_options.mc.fdpic;
#endif
        target_options.MCOptions.ShowMCEncoding = create->target_options.mc.show_mc_encoding;
        target_options.MCOptions.ShowMCInst = create->target_options.mc.show_mc_inst;
        target_options.MCOptions.AsmVerbose = create->target_options.mc.asm_verbose;
        target_options.MCOptions.PreserveAsmComments = create->target_options.mc.preserve_asm_comments;
        target_options.MCOptions.Dwarf64 = create->target_options.mc.dwarf64;
#if LLVM_VERSION_MAJOR >= 19
        target_options.MCOptions.Crel = create->target_options.mc.crel;
        target_options.MCOptions.X86RelaxRelocations = create->target_options.mc.x86_relax_relocations;
        target_options.MCOptions.X86Sse2Avx = create->target_options.mc.x86_sse2_avx;
#endif

        auto emit_dwarf_unwind = (BBLLVMEmitDwarfUnwindType) create->target_options.mc.emit_dwarf_unwind;
        switch (emit_dwarf_unwind)
        {
            case BBLLVMEmitDwarfUnwindType::always: target_options.MCOptions.EmitDwarfUnwind = llvm::EmitDwarfUnwindType::Always; break;
            case BBLLVMEmitDwarfUnwindType::no_compact_unwind: target_options.MCOptions.EmitDwarfUnwind = llvm::EmitDwarfUnwindType::NoCompactUnwind; break;
            case BBLLVMEmitDwarfUnwindType::normal: target_options.MCOptions.EmitDwarfUnwind = llvm::EmitDwarfUnwindType::Default; break;
        }

        auto use_dwarf_directory = (BBLLVMDwarfDirectory) create->target_options.mc.use_dwarf_directory;
        switch (use_dwarf_directory)
        {
            case BBLLVMDwarfDirectory::disable: target_options.MCOptions.MCUseDwarfDirectory = llvm::MCTargetOptions::DwarfDirectory::DisableDwarfDirectory; break;
            case BBLLVMDwarfDirectory::enable: target_options.MCOptions.MCUseDwarfDirectory = llvm::MCTargetOptions::DwarfDirectory::EnableDwarfDirectory; break;
            case BBLLVMDwarfDirectory::normal: target_options.MCOptions.MCUseDwarfDirectory = llvm::MCTargetOptions::DwarfDirectory::DefaultDwarfDirectory; break;
        }

#if LLVM_VERSION_MAJOR >= 19
        auto debug_compression_type = (BBLLVMDebugCompressionType) create->target_options.mc.debug_compression_type;
        switch (debug_compression_type)
        {
            case BBLLVMDebugCompressionType::none: target_options.MCOptions.CompressDebugSections = llvm::DebugCompressionType::None; break;
            case BBLLVMDebugCompressionType::zlib: target_options.MCOptions.CompressDebugSections = llvm::DebugCompressionType::Zlib; break;
            case BBLLVMDebugCompressionType::zstd: target_options.MCOptions.CompressDebugSections = llvm::DebugCompressionType::Zstd; break;
        }
#endif

        target_options.MCOptions.EmitCompactUnwindNonCanonical = create->target_options.mc.emit_compact_unwind_non_canonical;
        target_options.MCOptions.PPCUseFullRegisterNames = create->target_options.mc.ppc_use_full_register_names;

        return reinterpret_cast<LLVMTargetMachineRef>(const_cast<llvm::TargetMachine*>(target->createTargetMachine(string_ref(create->target_triple), string_ref(create->cpu_model), string_ref(create->cpu_features), target_options, relocation_model, code_model, optimization_level, create->jit)));
    }
    else
    {
        auto length = error_message_string.length();
        auto* result = new u8[length];
        memcpy(result, error_message_string.c_str(), length);

        *error_message = { result, length };
        return 0;
    }
}

EXPORT void llvm_module_set_target(LLVMModuleRef m, LLVMTargetMachineRef tm)
{
    auto module = llvm::unwrap(m);
    auto target_machine = (llvm::TargetMachine*)tm;
    module->setDataLayout(target_machine->createDataLayout());
    auto& triple_string = target_machine->getTargetTriple().getTriple();
    module->setTargetTriple(llvm::StringRef(triple_string));
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
    switch ((BBLLVMCodeGenerationFileType)options->code_generation_file_type)
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
        auto* stdout_pointer = new u8[stdout_length];
        memcpy(stdout_pointer, stdout_string.data(), stdout_length);
        result.stdout_string = { stdout_pointer, stdout_length };
    }

    auto stderr_length = stderr_string.length();
    if (stderr_length)
    {
        auto* stderr_pointer = new u8[stderr_length];
        memcpy(stderr_pointer, stderr_string.data(), stderr_length);
        result.stderr_string = { stderr_pointer, stderr_length };
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
