#include <llvm_common.h>
#include <llvm-c/Target.h>
#include <stdatomic.h>
#include <llvm-c/Error.h>

STRUCT(AtomicCacheLineBool)
{
    _Atomic(bool) b[CACHE_LINE_GUESS];
};

static bool activate(AtomicCacheLineBool* b)
{
    bool expected = 0;
    bool desired = 1;
    return atomic_compare_exchange_strong(&b->b[0], &expected, desired);
}

static alignas(CACHE_LINE_GUESS) AtomicCacheLineBool target_infos;
static alignas(CACHE_LINE_GUESS) AtomicCacheLineBool targets;
static alignas(CACHE_LINE_GUESS) AtomicCacheLineBool target_mcs;
static alignas(CACHE_LINE_GUESS) AtomicCacheLineBool asm_printers;
static alignas(CACHE_LINE_GUESS) AtomicCacheLineBool asm_parsers;
static alignas(CACHE_LINE_GUESS) AtomicCacheLineBool disassemblers;

void llvm_initialize()
{
    if (activate(&target_infos))
    {
        LLVMInitializeAllTargetInfos();
    }

    if (activate(&targets))
    {
        LLVMInitializeAllTargets();
    }

    if (activate(&target_mcs))
    {
        LLVMInitializeAllTargetMCs();
    }

    if (activate(&asm_printers))
    {
        LLVMInitializeAllAsmPrinters();
    }

    if (activate(&asm_parsers))
    {
        LLVMInitializeAllAsmParsers();
    }

    if (activate(&disassemblers))
    {
        LLVMInitializeAllDisassemblers();
    }
}

bool llvm_is_initialized()
{
    let ti = atomic_load(&target_infos.b[0]);
    let t = atomic_load(&targets.b[0]);
    let tmcs = atomic_load(&target_mcs.b[0]);
    let asmpr = atomic_load(&asm_printers.b[0]);
    let asmpa = atomic_load(&asm_parsers.b[0]);
    let dis = atomic_load(&disassemblers.b[0]);

    return ((ti & t) & (tmcs & asmpr)) & (asmpa & dis);
}
