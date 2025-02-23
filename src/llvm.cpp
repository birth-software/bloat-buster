#include <stdint.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define EXPORT extern "C"
#define fn static

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


using namespace llvm;

struct BBLLVMString
{
    const char* pointer;
    size_t length;

    inline StringRef string_ref() const
    {
        return { pointer, length };
    }
};

EXPORT Module* llvm_context_create_module(LLVMContext& context, BBLLVMString name)
{
    return new Module(name.string_ref(), context);
}

EXPORT bool llvm_type_is_function(const Type& type)
{
    auto result = type.isFunctionTy();
    return result;
}

EXPORT bool llvm_type_is_integer(const Type& type)
{
    auto result = type.isIntegerTy();
    return result;
}

EXPORT unsigned llvm_integer_type_get_bit_count(const IntegerType& integer_type)
{
    auto result = integer_type.getBitWidth();
    return result;
}

EXPORT GlobalVariable* llvm_module_create_global_variable(Module& module, Type* type, bool is_constant, GlobalValue::LinkageTypes linkage_type, Constant* initial_value, BBLLVMString name, GlobalVariable* before, GlobalValue::ThreadLocalMode thread_local_mode, unsigned address_space, bool externally_initialized)
{
    auto* global_variable = new GlobalVariable(module, type, is_constant, linkage_type, initial_value, name.string_ref(), before, thread_local_mode, address_space, externally_initialized);
    return global_variable;
}

EXPORT void llvm_global_variable_add_debug_info(GlobalVariable& global_variable, DIGlobalVariableExpression* debug_global_variable)
{
    global_variable.addDebugInfo(debug_global_variable);
}

EXPORT Function* llvm_module_create_function(Module* module, FunctionType* function_type, GlobalValue::LinkageTypes linkage_type, unsigned address_space, BBLLVMString name)
{
    auto* function = Function::Create(function_type, linkage_type, address_space, name.string_ref(), module);
    return function;
}

EXPORT StructType* llvm_context_create_struct_type(LLVMContext& context, Type** type_pointer, size_t type_count, BBLLVMString name, bool is_packed)
{
    auto types = ArrayRef<Type*>(type_pointer, type_count);
    auto* struct_type = StructType::create(context, types, name.string_ref(), is_packed);
    return struct_type;
}

EXPORT StructType* llvm_context_get_struct_type(LLVMContext& context, Type** type_pointer, size_t type_count, bool is_packed)
{
    auto types = ArrayRef<Type*>(type_pointer, type_count);
    auto* struct_type = StructType::get(context, types, is_packed);
    return struct_type;
}

EXPORT BasicBlock* llvm_context_create_basic_block(LLVMContext& context, BBLLVMString name, Function* parent)
{
    auto* basic_block = BasicBlock::Create(context, name.string_ref(), parent);
    return basic_block;
}

EXPORT AllocaInst* llvm_builder_create_alloca(IRBuilder<>& builder, Type* type, unsigned address_space, BBLLVMString name)
{   
    const DataLayout &data_layout = builder.GetInsertBlock()->getDataLayout();
    Align alignment = data_layout.getABITypeAlign(type);
    return builder.Insert(new AllocaInst(type, address_space, 0, alignment), name.string_ref());
}

fn BBLLVMString stream_to_string(raw_string_ostream& stream)
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

    return { result, length };
}

EXPORT BBLLVMString llvm_function_to_string(Function& function)
{
    std::string buffer;
    raw_string_ostream os(buffer);
    function.print(os);
    os.flush();
    auto result = stream_to_string(os);
    return result;
}

EXPORT bool llvm_function_verify(Function& function, BBLLVMString* error_message)
{
    std::string message_buffer;
    raw_string_ostream message_stream(message_buffer);

    bool result = verifyFunction(function, &message_stream);
    auto size = message_stream.str().size();
    *error_message = stream_to_string(message_stream);

    // We invert the condition because LLVM conventions are just stupid
    return !result;
}


EXPORT bool llvm_module_verify(const Module& module, BBLLVMString* error_message)
{
    std::string message_buffer;
    raw_string_ostream message_stream(message_buffer);

    bool result = verifyModule(module, &message_stream);
    *error_message = stream_to_string(message_stream);

    // We invert the condition because LLVM conventions are just stupid
    return !result;
}

EXPORT BBLLVMString llvm_module_to_string(Module* module)
{
    std::string buffer;
    raw_string_ostream stream(buffer);
    module->print(stream, 0);

    return stream_to_string(stream);
}

EXPORT BBLLVMString llvm_default_target_triple()
{
    auto triple = llvm::sys::getDefaultTargetTriple();
    auto length = triple.length();

    char* pointer = 0;
    if (length)
    {
        pointer = new char[length];
        memcpy(pointer, triple.c_str(), length);
    }

    return { pointer, length };
}

EXPORT BBLLVMString llvm_host_cpu_name()
{
    auto cpu = llvm::sys::getHostCPUName();
    return { cpu.data(), cpu.size() };
}

EXPORT BBLLVMString llvm_host_cpu_features()
{
    SubtargetFeatures Features;
#if LLVM_VERSION_MAJOR >= 19
    auto host_cpu_features = sys::getHostCPUFeatures();
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

    char* result = 0;
    if (length)
    {
        result = new char[length];
        memcpy(result, feature_string.c_str(), length);
    }

    return { result, length };
}

enum class BBLLVMEmitDwarfUnwindType : u8
{
    always = 0,
    no_compact_unwind = 1,
    normal = 2,
};

enum class BBLLVMDwarfDirectory : u8
{
    disable = 0,
    enable = 1,
    normal = 2,
};

enum class BBLLVMDebugCompressionType : u8
{
    none = 0,
    zlib = 1,
    zstd = 2,
};

#define BB_LLVM_MC_TARGET_OPTIONS_PADDING_BIT_COUNT (7)

struct BBLLVMMCTargetOptions
{
    BBLLVMString abi_name;
    BBLLVMString assembly_language;
    BBLLVMString split_dwarf_file;
    BBLLVMString as_secure_log_file;
    const char* argv0;
    BBLLVMString* argv_pointer;
    u64 argv_count;
    BBLLVMString* integrated_assembler_search_path_pointer;
    u64 integrated_assembler_search_path_count;
    u32 relax_all:1;
    u32 no_exec_stack:1;
    u32 fatal_warnings:1;
    u32 no_warn:1;
    u32 no_deprecated_warn:1;
    u32 no_type_check:1;
    u32 save_temp_labels:1;
    u32 incremental_linker_compatible:1;
    u32 fdpic:1;
    u32 show_mc_encoding:1;
    u32 show_mc_inst:1;
    u32 asm_verbose:1;
    u32 preserve_asm_comments:1;
    u32 dwarf64:1;
    u32 crel:1;
    u32 x86_relax_relocations:1;
    u32 x86_sse2_avx:1;
    u32 emit_dwarf_unwind:2;
    u32 use_dwarf_directory:2;
    u32 debug_compression_type:2;
    u32 emit_compact_unwind_non_canonical:1;
    u32 ppc_use_full_register_names:1;
    u32 reserved:BB_LLVM_MC_TARGET_OPTIONS_PADDING_BIT_COUNT;
};

static_assert(sizeof(BBLLVMMCTargetOptions) == 112);
static_assert(BB_LLVM_MC_TARGET_OPTIONS_PADDING_BIT_COUNT == 7);

enum class BBLLVMCodeModel : u8
{
    none = 0,
    tiny = 1,
    small = 2,
    kernel = 3,
    medium = 4,
    large = 5,
};

enum class BBLLVMRelocationModel : u8
{
    default_relocation = 0,
    static_relocation = 1,
    pic = 2,
    dynamic_no_pic = 3,
    ropi = 4,
    rwpi = 5,
    ropi_rwpi = 6,
};

enum class BBLLVMCodeGenerationOptimizationLevel : u8
{
    none = 0,      // -O0
    less = 1,      // -O1
    normal = 2,   // -O2, -Os
    aggressive = 3 // -O3
};

enum class BBLLVMGlobalISelAbortMode : u8
{
    disable = 0,
    enable = 1,
    disable_with_diag = 2,
};

enum class BBLLVMSwiftAsyncFramePointerMode : u8
{
    deployment_based = 0,
    always = 1,
    never = 2,
};

enum class BBLLVMBasicBlockSection : u8
{
    all = 0,
    list = 1,
    labels = 2,
    preset = 3,
    none = 4,
};

enum class BBLLVMFloatAbi : u8
{
    normal = 0,
    soft = 1,
    hard = 2,
};

enum class BBLLVMFPOpFusion : u8
{
    fast = 0,
    standard = 1,
    strict = 2,
};

enum class BBLLVMThreadModel : u8
{
    posix = 0,
    single = 1,
};

enum class BBLLVMEAbi : u8
{
    unknown = 0,
    normal = 1,
    eabi4 = 2,
    eabi5 = 3,
    gnu = 4,
};

enum class BBLLVMDebuggerKind : u8
{
    normal = 0,
    gdb = 1,
    lldb = 2,
    sce = 3,
    dbx = 4,
};

enum class BBLLVMExceptionHandling : u8
{
    none = 0,
    dwarf_cfi = 1,
    setjmp_longjmp = 2,
    arm = 3,
    win_eh = 4,
    wasm = 5,
    aix = 6,
    zos = 7,
};

#define BB_LLVM_TARGET_OPTIONS_PADDING_BIT_COUNT (21)

struct BBLLVMTargetOptions
{
    u64 unsafe_fp_math:1;
    u64 no_infs_fp_math:1;
    u64 no_nans_fp_math:1;
    u64 no_trapping_fp_math:1;
    u64 no_signed_zeroes_fp_math:1;
    u64 approx_func_fp_match:1;
    u64 enable_aix_extended_altivec_abi:1;
    u64 honor_sign_dependent_rounding_fp_math:1;
    u64 no_zeroes_in_bss:1;
    u64 guaranteed_tail_call_optimization:1;
    u64 stack_symbol_ordering:1;
    u64 enable_fast_isel:1;
    u64 enable_global_isel:1;
    u64 global_isel_abort_mode:2;
    u64 swift_async_frame_pointer:2;
    u64 use_init_array:1;
    u64 disable_integrated_assembler:1;
    u64 function_sections:1;
    u64 data_sections:1;
    u64 ignore_xcoff_visibility:1;
    u64 xcoff_traceback_table:1;
    u64 unique_section_names:1;
    u64 unique_basic_block_section_names:1;
    u64 separate_named_sections:1;
    u64 trap_unreachable:1;
    u64 no_trap_after_noreturn:1;
    u64 tls_size:8;
    u64 emulated_tls:1;
    u64 enable_tls_descriptors:1;
    u64 enable_ipra:1;
    u64 emit_stack_size_section:1;
    u64 enable_machine_outliner:1;
    u64 enable_machine_function_splitter:1;
    u64 supports_default_outlining:1;
    u64 emit_address_significance_table:1;
    u64 bb_address_map:1;
    u64 bb_sections:3;
    u64 emit_call_site_information:1;
    u64 supports_debug_entry_values:1;
    u64 enable_debug_entry_values:1;
    u64 value_tracking_variable_locations:1;
    u64 force_dwarf_frame_section:1;
    u64 xray_function_index:1;
    u64 debug_strict_dwarf:1;
    u64 hotpatch:1;
    u64 ppc_gen_scalar_mass_entries:1;
    u64 jmc_instrument:1;
    u64 enable_cfi_fixup:1;
    u64 mis_expect:1;
    u64 xcoff_read_only_pointers:1;
    u64 float_abi:2;
    u64 thread_model:1;
    u32 fp_op_fusion_mode:2;
    u32 eabi_version:3;
    u32 debugger_kind:3;
    u32 exception_handling:3;
    u32 reserved:BB_LLVM_TARGET_OPTIONS_PADDING_BIT_COUNT;
    unsigned loop_alignment;
    int binutils_version[2];

    BBLLVMMCTargetOptions mc;
};

static_assert(sizeof(BBLLVMTargetOptions) == 136);
static_assert(BB_LLVM_TARGET_OPTIONS_PADDING_BIT_COUNT == 21);

#define BB_LLVM_TARGET_MACHINE_CREATE_PADDING_BYTE_COUNT (4)

struct BBLLVMTargetMachineCreate
{
    BBLLVMTargetOptions target_options;
    BBLLVMString target_triple;
    BBLLVMString cpu_model;
    BBLLVMString cpu_features;
    BBLLVMRelocationModel relocation_model;
    BBLLVMCodeModel code_model;
    BBLLVMCodeGenerationOptimizationLevel optimization_level;
    bool jit;
    u8 reserved[BB_LLVM_TARGET_MACHINE_CREATE_PADDING_BYTE_COUNT];
};

static_assert(sizeof(BBLLVMTargetMachineCreate) == 192);
static_assert(BB_LLVM_TARGET_MACHINE_CREATE_PADDING_BYTE_COUNT == 4);

EXPORT TargetMachine* llvm_create_target_machine(const BBLLVMTargetMachineCreate& create, BBLLVMString* error_message)
{
    std::string error_message_string;
    const Target* target = TargetRegistry::lookupTarget(create.target_triple.string_ref(), error_message_string);

    TargetMachine* target_machine;

    if (target)
    {
        std::optional<CodeModel::Model> code_model;
        switch (create.code_model)
        {
            case BBLLVMCodeModel::none: code_model = std::nullopt; break;
            case BBLLVMCodeModel::tiny: code_model = CodeModel::Tiny; break;
            case BBLLVMCodeModel::small: code_model = CodeModel::Small; break;
            case BBLLVMCodeModel::kernel: code_model = CodeModel::Kernel; break;
            case BBLLVMCodeModel::medium: code_model = CodeModel::Medium; break;
            case BBLLVMCodeModel::large: code_model = CodeModel::Large; break;
        }

        std::optional<Reloc::Model> relocation_model;

        switch (create.relocation_model)
        {
            case BBLLVMRelocationModel::default_relocation: relocation_model = std::nullopt; break;
            case BBLLVMRelocationModel::static_relocation: relocation_model = Reloc::Static; break;
            case BBLLVMRelocationModel::pic: relocation_model = Reloc::PIC_; break;
            case BBLLVMRelocationModel::dynamic_no_pic: relocation_model = Reloc::DynamicNoPIC; break;
            case BBLLVMRelocationModel::ropi: relocation_model = Reloc::ROPI; break;
            case BBLLVMRelocationModel::rwpi: relocation_model = Reloc::RWPI; break;
            case BBLLVMRelocationModel::ropi_rwpi: relocation_model = Reloc::ROPI_RWPI; break;
        }

        CodeGenOptLevel optimization_level;
        switch (create.optimization_level)
        {
            case BBLLVMCodeGenerationOptimizationLevel::none: optimization_level = CodeGenOptLevel::None; break;
            case BBLLVMCodeGenerationOptimizationLevel::less: optimization_level = CodeGenOptLevel::Less; break;
            case BBLLVMCodeGenerationOptimizationLevel::normal: optimization_level = CodeGenOptLevel::Default; break;
            case BBLLVMCodeGenerationOptimizationLevel::aggressive: optimization_level = CodeGenOptLevel::Aggressive; break;
        }

        // INFO: This calls the default constructor, so all LLVM defaults are set and we only override what we control
        TargetOptions target_options;

        target_options.UnsafeFPMath = create.target_options.unsafe_fp_math;
        target_options.NoInfsFPMath = create.target_options.no_infs_fp_math;
        target_options.NoNaNsFPMath = create.target_options.no_nans_fp_math;
        target_options.NoTrappingFPMath = create.target_options.no_trapping_fp_math;
        target_options.NoSignedZerosFPMath = create.target_options.no_signed_zeroes_fp_math;
        target_options.ApproxFuncFPMath = create.target_options.approx_func_fp_match;
        target_options.EnableAIXExtendedAltivecABI = create.target_options.enable_aix_extended_altivec_abi;
        target_options.HonorSignDependentRoundingFPMathOption = create.target_options.honor_sign_dependent_rounding_fp_math;
        target_options.NoZerosInBSS = create.target_options.no_zeroes_in_bss;
        target_options.GuaranteedTailCallOpt = create.target_options.guaranteed_tail_call_optimization;
        target_options.StackSymbolOrdering = create.target_options.stack_symbol_ordering;
        target_options.EnableFastISel = create.target_options.enable_fast_isel;
        target_options.EnableGlobalISel = create.target_options.enable_global_isel;

        auto global_isel_abort_mode = (BBLLVMGlobalISelAbortMode)create.target_options.global_isel_abort_mode;
        switch (global_isel_abort_mode)
        {
            case BBLLVMGlobalISelAbortMode::disable: target_options.GlobalISelAbort = GlobalISelAbortMode::Disable; break;
            case BBLLVMGlobalISelAbortMode::enable: target_options.GlobalISelAbort = GlobalISelAbortMode::Enable; break;
            case BBLLVMGlobalISelAbortMode::disable_with_diag: target_options.GlobalISelAbort = GlobalISelAbortMode::DisableWithDiag; break;
        }
        auto swift_async_frame_pointer = (BBLLVMSwiftAsyncFramePointerMode)create.target_options.swift_async_frame_pointer;
        switch (swift_async_frame_pointer)
        {
            case BBLLVMSwiftAsyncFramePointerMode::deployment_based: target_options.SwiftAsyncFramePointer = SwiftAsyncFramePointerMode::DeploymentBased; break;
            case BBLLVMSwiftAsyncFramePointerMode::always: target_options.SwiftAsyncFramePointer = SwiftAsyncFramePointerMode::Always; break;
            case BBLLVMSwiftAsyncFramePointerMode::never: target_options.SwiftAsyncFramePointer = SwiftAsyncFramePointerMode::Never; break;
        }

        target_options.UseInitArray = create.target_options.use_init_array;
        target_options.DisableIntegratedAS = create.target_options.disable_integrated_assembler;
        target_options.FunctionSections = create.target_options.function_sections;
        target_options.DataSections = create.target_options.data_sections;
        target_options.IgnoreXCOFFVisibility = create.target_options.ignore_xcoff_visibility;
        target_options.XCOFFTracebackTable = create.target_options.xcoff_traceback_table;
        target_options.UniqueSectionNames = create.target_options.unique_section_names;
        target_options.UniqueBasicBlockSectionNames = create.target_options.unique_basic_block_section_names;
#if LLVM_VERSION_MAJOR >= 19
        target_options.SeparateNamedSections = create.target_options.separate_named_sections;
#endif
        target_options.TrapUnreachable = create.target_options.trap_unreachable;
        target_options.NoTrapAfterNoreturn = create.target_options.no_trap_after_noreturn;
        target_options.TLSSize = create.target_options.tls_size;
        target_options.EmulatedTLS = create.target_options.emulated_tls;
        target_options.EnableTLSDESC = create.target_options.enable_tls_descriptors;
        target_options.EnableIPRA = create.target_options.enable_ipra;
        target_options.EmitStackSizeSection = create.target_options.emit_stack_size_section;
        target_options.EnableMachineOutliner = create.target_options.enable_machine_outliner;
        target_options.EnableMachineFunctionSplitter = create.target_options.enable_machine_function_splitter;
        target_options.SupportsDefaultOutlining = create.target_options.supports_default_outlining;
        target_options.EmitAddrsig = create.target_options.emit_address_significance_table;
#if LLVM_VERSION_MAJOR >= 19
        target_options.BBAddrMap = create.target_options.bb_address_map;
#endif

        auto bb_sections = (BBLLVMBasicBlockSection) create.target_options.bb_sections;
        switch (bb_sections)
        {
            case BBLLVMBasicBlockSection::all: target_options.BBSections = BasicBlockSection::All; break;
            case BBLLVMBasicBlockSection::list: target_options.BBSections = BasicBlockSection::List; break;
            case BBLLVMBasicBlockSection::labels: target_options.BBSections = BasicBlockSection::Labels; break;
            case BBLLVMBasicBlockSection::preset: target_options.BBSections = BasicBlockSection::Preset; break;
            case BBLLVMBasicBlockSection::none: target_options.BBSections = BasicBlockSection::None; break;
        }

        target_options.EmitCallSiteInfo = create.target_options.emit_call_site_information;
        target_options.SupportsDebugEntryValues = create.target_options.supports_debug_entry_values;
        target_options.EnableDebugEntryValues = create.target_options.enable_debug_entry_values;
        target_options.ValueTrackingVariableLocations = create.target_options.value_tracking_variable_locations;
        target_options.ForceDwarfFrameSection = create.target_options.force_dwarf_frame_section;
        target_options.XRayFunctionIndex = create.target_options.xray_function_index;
        target_options.DebugStrictDwarf = create.target_options.debug_strict_dwarf;
        target_options.Hotpatch = create.target_options.hotpatch;
        target_options.PPCGenScalarMASSEntries = create.target_options.ppc_gen_scalar_mass_entries;
        target_options.JMCInstrument = create.target_options.jmc_instrument;
        target_options.EnableCFIFixup = create.target_options.enable_cfi_fixup;
        target_options.MisExpect = create.target_options.mis_expect;
        target_options.XCOFFReadOnlyPointers = create.target_options.xcoff_read_only_pointers;

        auto float_abi = (BBLLVMFloatAbi) create.target_options.float_abi;
        switch (float_abi)
        {
            case BBLLVMFloatAbi::normal: target_options.FloatABIType = FloatABI::Default; break;
            case BBLLVMFloatAbi::soft: target_options.FloatABIType = FloatABI::Soft; break;
            case BBLLVMFloatAbi::hard: target_options.FloatABIType = FloatABI::Hard; break;
        }

        auto thread_model = (BBLLVMThreadModel) create.target_options.thread_model;
        switch (thread_model)
        {
            case BBLLVMThreadModel::posix: target_options.ThreadModel = ThreadModel::POSIX; break;
            case BBLLVMThreadModel::single: target_options.ThreadModel = ThreadModel::Single; break;
        }

        auto fp_op_fusion_mode = (BBLLVMFPOpFusion) create.target_options.fp_op_fusion_mode;
        switch (fp_op_fusion_mode)
        {
            case BBLLVMFPOpFusion::fast: target_options.AllowFPOpFusion = FPOpFusion::Fast; break;
            case BBLLVMFPOpFusion::standard: target_options.AllowFPOpFusion = FPOpFusion::Standard; break;
            case BBLLVMFPOpFusion::strict: target_options.AllowFPOpFusion = FPOpFusion::Strict; break;
        }

        auto eabi_version = (BBLLVMEAbi) create.target_options.eabi_version;
        switch (eabi_version)
        {
            case BBLLVMEAbi::unknown: target_options.EABIVersion = EABI::Unknown; break;
            case BBLLVMEAbi::normal: target_options.EABIVersion = EABI::Default; break;
            case BBLLVMEAbi::eabi4: target_options.EABIVersion = EABI::EABI4; break;
            case BBLLVMEAbi::eabi5: target_options.EABIVersion = EABI::EABI5; break;
            case BBLLVMEAbi::gnu: target_options.EABIVersion = EABI::GNU; break;
        }

        auto debugger_kind = (BBLLVMDebuggerKind) create.target_options.debugger_kind;
        switch (debugger_kind)
        {
            case BBLLVMDebuggerKind::normal: target_options.DebuggerTuning = DebuggerKind::Default; break;
            case BBLLVMDebuggerKind::gdb: target_options.DebuggerTuning = DebuggerKind::GDB; break;
            case BBLLVMDebuggerKind::lldb: target_options.DebuggerTuning = DebuggerKind::LLDB; break;
            case BBLLVMDebuggerKind::sce: target_options.DebuggerTuning = DebuggerKind::SCE; break;
            case BBLLVMDebuggerKind::dbx: target_options.DebuggerTuning = DebuggerKind::DBX; break;
        }
        
        auto exception_handling = (BBLLVMExceptionHandling) create.target_options.exception_handling;
        switch (exception_handling)
        {
            case BBLLVMExceptionHandling::none: target_options.ExceptionModel = ExceptionHandling::None; break;
            case BBLLVMExceptionHandling::dwarf_cfi: target_options.ExceptionModel = ExceptionHandling::DwarfCFI; break;
            case BBLLVMExceptionHandling::setjmp_longjmp: target_options.ExceptionModel = ExceptionHandling::SjLj; break;
            case BBLLVMExceptionHandling::arm: target_options.ExceptionModel = ExceptionHandling::ARM; break;
            case BBLLVMExceptionHandling::win_eh: target_options.ExceptionModel = ExceptionHandling::WinEH; break;
            case BBLLVMExceptionHandling::wasm: target_options.ExceptionModel = ExceptionHandling::Wasm; break;
            case BBLLVMExceptionHandling::aix: target_options.ExceptionModel = ExceptionHandling::AIX; break;
            case BBLLVMExceptionHandling::zos: target_options.ExceptionModel = ExceptionHandling::ZOS; break;
        }

        target_options.LoopAlignment = create.target_options.loop_alignment;
        target_options.BinutilsVersion = { create.target_options.binutils_version[0], create.target_options.binutils_version[1] };

        if (create.target_options.mc.abi_name.length)
        {
            target_options.MCOptions.ABIName = { create.target_options.mc.abi_name.pointer, create.target_options.mc.abi_name.length };
        }

        if (create.target_options.mc.assembly_language.length)
        {
            target_options.MCOptions.AssemblyLanguage = { create.target_options.mc.assembly_language.pointer, create.target_options.mc.assembly_language.length };
        }

        if (create.target_options.mc.split_dwarf_file.length)
        {
            target_options.MCOptions.SplitDwarfFile = { create.target_options.mc.split_dwarf_file.pointer, create.target_options.mc.split_dwarf_file.length };
        }

        if (create.target_options.mc.as_secure_log_file.length)
        {
            target_options.MCOptions.AsSecureLogFile = { create.target_options.mc.as_secure_log_file.pointer, create.target_options.mc.as_secure_log_file.length };
        }

        target_options.MCOptions.Argv0 = create.target_options.mc.argv0;

        if (create.target_options.mc.argv_count)
        {
            // TODO:
            __builtin_trap();
        }

        if (create.target_options.mc.integrated_assembler_search_path_count)
        {
            // TODO:
            __builtin_trap();
        }

        target_options.MCOptions.MCRelaxAll = create.target_options.mc.relax_all;
        target_options.MCOptions.MCNoExecStack = create.target_options.mc.no_exec_stack;
        target_options.MCOptions.MCFatalWarnings = create.target_options.mc.fatal_warnings;
        target_options.MCOptions.MCNoWarn = create.target_options.mc.no_warn;
        target_options.MCOptions.MCNoDeprecatedWarn = create.target_options.mc.no_deprecated_warn;
        target_options.MCOptions.MCNoTypeCheck = create.target_options.mc.no_type_check;
        target_options.MCOptions.MCSaveTempLabels = create.target_options.mc.save_temp_labels;
        target_options.MCOptions.MCIncrementalLinkerCompatible = create.target_options.mc.incremental_linker_compatible;
#if LLVM_VERSION_MAJOR >= 19
        target_options.MCOptions.FDPIC = create.target_options.mc.fdpic;
#endif
        target_options.MCOptions.ShowMCEncoding = create.target_options.mc.show_mc_encoding;
        target_options.MCOptions.ShowMCInst = create.target_options.mc.show_mc_inst;
        target_options.MCOptions.AsmVerbose = create.target_options.mc.asm_verbose;
        target_options.MCOptions.PreserveAsmComments = create.target_options.mc.preserve_asm_comments;
        target_options.MCOptions.Dwarf64 = create.target_options.mc.dwarf64;
#if LLVM_VERSION_MAJOR >= 19
        target_options.MCOptions.Crel = create.target_options.mc.crel;
        target_options.MCOptions.X86RelaxRelocations = create.target_options.mc.x86_relax_relocations;
        target_options.MCOptions.X86Sse2Avx = create.target_options.mc.x86_sse2_avx;
#endif

        auto emit_dwarf_unwind = (BBLLVMEmitDwarfUnwindType) create.target_options.mc.emit_dwarf_unwind;
        switch (emit_dwarf_unwind)
        {
            case BBLLVMEmitDwarfUnwindType::always: target_options.MCOptions.EmitDwarfUnwind = EmitDwarfUnwindType::Always; break;
            case BBLLVMEmitDwarfUnwindType::no_compact_unwind: target_options.MCOptions.EmitDwarfUnwind = EmitDwarfUnwindType::NoCompactUnwind; break;
            case BBLLVMEmitDwarfUnwindType::normal: target_options.MCOptions.EmitDwarfUnwind = EmitDwarfUnwindType::Default; break;
        }

        auto use_dwarf_directory = (BBLLVMDwarfDirectory) create.target_options.mc.use_dwarf_directory;
        switch (use_dwarf_directory)
        {
            case BBLLVMDwarfDirectory::disable: target_options.MCOptions.MCUseDwarfDirectory = MCTargetOptions::DwarfDirectory::DisableDwarfDirectory; break;
            case BBLLVMDwarfDirectory::enable: target_options.MCOptions.MCUseDwarfDirectory = MCTargetOptions::DwarfDirectory::EnableDwarfDirectory; break;
            case BBLLVMDwarfDirectory::normal: target_options.MCOptions.MCUseDwarfDirectory = MCTargetOptions::DwarfDirectory::DefaultDwarfDirectory; break;
        }

#if LLVM_VERSION_MAJOR >= 19
        auto debug_compression_type = (BBLLVMDebugCompressionType) create.target_options.mc.debug_compression_type;
        switch (debug_compression_type)
        {
            case BBLLVMDebugCompressionType::none: target_options.MCOptions.CompressDebugSections = DebugCompressionType::None; break;
            case BBLLVMDebugCompressionType::zlib: target_options.MCOptions.CompressDebugSections = DebugCompressionType::Zlib; break;
            case BBLLVMDebugCompressionType::zstd: target_options.MCOptions.CompressDebugSections = DebugCompressionType::Zstd; break;
        }
#endif

        target_options.MCOptions.EmitCompactUnwindNonCanonical = create.target_options.mc.emit_compact_unwind_non_canonical;
        target_options.MCOptions.PPCUseFullRegisterNames = create.target_options.mc.ppc_use_full_register_names;

        target_machine = target->createTargetMachine(create.target_triple.string_ref(), create.cpu_model.string_ref(), create.cpu_features.string_ref(), target_options, relocation_model, code_model, optimization_level, create.jit);
    }
    else
    {
        auto length = error_message_string.length();
        char* result = new char[length];
        memcpy(result, error_message_string.c_str(), length);

        *error_message = { result, length };

        target_machine = 0;
    }

    return target_machine;
}

EXPORT void llvm_module_set_target(Module& module, TargetMachine& target_machine)
{
    module.setDataLayout(target_machine.createDataLayout());
    auto& triple_string = target_machine.getTargetTriple().getTriple();
    module.setTargetTriple(StringRef(triple_string));
}

enum class BBLLVMOptimizationLevel : u8
{
    O0 = 0,
    O1 = 1,
    O2 = 2,
    O3 = 3,
    Os = 4,
    Oz = 5,
};

#define BB_LLVM_OPTIMIZATION_PIPELINE_OPTIONS_PADDING_BIT_COUNT (51)
struct BBLLVMOptimizationPipelineOptions
{
    u64 optimization_level:3;
    u64 debug_info:1;
    u64 loop_unrolling:1;
    u64 loop_interleaving:1;
    u64 loop_vectorization:1;
    u64 slp_vectorization:1;
    u64 merge_functions:1;
    u64 call_graph_profile:1;
    u64 unified_lto:1;
    u64 assignment_tracking:1;
    u64 verify_module:1;
    u64 reserved:BB_LLVM_OPTIMIZATION_PIPELINE_OPTIONS_PADDING_BIT_COUNT;
};

static_assert(sizeof(BBLLVMOptimizationPipelineOptions) == sizeof(u64));
static_assert(BB_LLVM_OPTIMIZATION_PIPELINE_OPTIONS_PADDING_BIT_COUNT == 51);

EXPORT void llvm_module_run_optimization_pipeline(Module& module, TargetMachine& target_machine, BBLLVMOptimizationPipelineOptions options)
{
    // TODO: PGO
    // TODO: CS profile
    
    PipelineTuningOptions pipeline_tuning_options;
    pipeline_tuning_options.LoopUnrolling = options.loop_unrolling;
    pipeline_tuning_options.LoopInterleaving = options.loop_interleaving;
    pipeline_tuning_options.LoopVectorization = options.loop_vectorization;
    pipeline_tuning_options.SLPVectorization = options.slp_vectorization;
    pipeline_tuning_options.MergeFunctions = options.merge_functions;
    pipeline_tuning_options.CallGraphProfile = options.call_graph_profile;
    pipeline_tuning_options.UnifiedLTO = options.unified_lto;
    
    // TODO: instrumentation

    LoopAnalysisManager loop_analysis_manager;
    FunctionAnalysisManager function_analysis_manager;
    CGSCCAnalysisManager cgscc_analysis_manager;
    ModuleAnalysisManager module_analysis_manager;

    PassBuilder pass_builder(&target_machine, pipeline_tuning_options); 

    if (options.assignment_tracking && options.debug_info != 0)
    {
        pass_builder.registerPipelineStartEPCallback([&](ModulePassManager& MPM, OptimizationLevel Level) {
                MPM.addPass(AssignmentTrackingPass());
            });
    }
    
    Triple target_triple = target_machine.getTargetTriple(); // Need to make a copy, incoming bugfix: https://github.com/llvm/llvm-project/pull/127718
    // TODO: add library (?)
    std::unique_ptr<TargetLibraryInfoImpl> TLII(llvm::driver::createTLII(target_triple, driver::VectorLibrary::NoLibrary));
    function_analysis_manager.registerPass([&] { return TargetLibraryAnalysis(*TLII); });

    pass_builder.registerModuleAnalyses(module_analysis_manager);
    pass_builder.registerCGSCCAnalyses(cgscc_analysis_manager);
    pass_builder.registerFunctionAnalyses(function_analysis_manager);
    pass_builder.registerLoopAnalyses(loop_analysis_manager);
    pass_builder.crossRegisterProxies(loop_analysis_manager, function_analysis_manager, cgscc_analysis_manager, module_analysis_manager);

    ModulePassManager module_pass_manager;

    if (options.verify_module)
    {
        module_pass_manager.addPass(VerifierPass());
    }

    bool thin_lto = false;
    bool lto = false;

    OptimizationLevel optimization_level;
    switch ((BBLLVMOptimizationLevel)options.optimization_level)
    {
        case BBLLVMOptimizationLevel::O0: optimization_level = OptimizationLevel::O0; break;
        case BBLLVMOptimizationLevel::O1: optimization_level = OptimizationLevel::O1; break;
        case BBLLVMOptimizationLevel::O2: optimization_level = OptimizationLevel::O2; break;
        case BBLLVMOptimizationLevel::O3: optimization_level = OptimizationLevel::O3; break;
        case BBLLVMOptimizationLevel::Os: optimization_level = OptimizationLevel::Os; break;
        case BBLLVMOptimizationLevel::Oz: optimization_level = OptimizationLevel::Oz; break;
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
         module_pass_manager.addPass(pass_builder.buildPerModuleDefaultPipeline(optimization_level, lto));
    }

    // TODO: if emit bitcode/IR

    module_pass_manager.run(module, module_analysis_manager);
}

enum class BBLLVMCodeGenerationFileType : u8
{
    assembly_file = 0,
    object_file = 1,
    null = 2,
};

#define BB_LLVM_CODE_GENERATION_PIPELINE_OPTIONS_PADDING_BIT_COUNT (60)

struct BBLLVMCodeGenerationPipelineOptions
{
    BBLLVMString output_dwarf_file_path;
    BBLLVMString output_file_path;
    u64 code_generation_file_type:2;
    u64 optimize_when_possible:1;
    u64 verify_module:1;
    u64 reserved: BB_LLVM_CODE_GENERATION_PIPELINE_OPTIONS_PADDING_BIT_COUNT;
};

static_assert(sizeof(BBLLVMCodeGenerationPipelineOptions) == 5 * sizeof(u64));
static_assert(BB_LLVM_CODE_GENERATION_PIPELINE_OPTIONS_PADDING_BIT_COUNT == 60);

enum class BBLLVMCodeGenerationPipelineResult : u8
{
    success = 0,
    failed_to_create_file = 1,
    failed_to_add_emit_passes = 2,
};

EXPORT BBLLVMCodeGenerationPipelineResult llvm_module_run_code_generation_pipeline(Module& module, TargetMachine& target_machine, BBLLVMCodeGenerationPipelineOptions options)
{
    // We still use the legacy PM to run the codegen pipeline since the new PM
    // does not work with the codegen pipeline.
    // FIXME: make the new PM work with the codegen pipeline.
    legacy::PassManager CodeGenPasses;
#if LLVM_VERSION_MAJOR >= 19
    if (options.optimize_when_possible)
    {
        CodeGenPasses.add(createTargetTransformInfoWrapperPass(target_machine.getTargetIRAnalysis()));
    }
#endif

    raw_pwrite_stream* dwarf_object_file = 0;
    if (options.output_dwarf_file_path.length)
    {
        __builtin_trap();
    }

    if (options.optimize_when_possible)
    {
        Triple target_triple = target_machine.getTargetTriple(); // Need to make a copy, incoming bugfix: https://github.com/llvm/llvm-project/pull/127718
        // TODO: add library (?)
        std::unique_ptr<TargetLibraryInfoImpl> TLII(llvm::driver::createTLII(target_triple, driver::VectorLibrary::NoLibrary));
        CodeGenPasses.add(new TargetLibraryInfoWrapperPass(*TLII));
    }

    std::unique_ptr<raw_pwrite_stream> stream;

    if (options.output_file_path.length)
    {
        std::error_code error_code;
        
        stream = std::make_unique<llvm::raw_fd_ostream>(options.output_file_path.string_ref(), error_code, sys::fs::OF_None);

        if (error_code)
        {
            return BBLLVMCodeGenerationPipelineResult::failed_to_create_file;
        }
    }
    else
    {
        stream = std::make_unique<llvm::raw_null_ostream>();
    }

    CodeGenFileType file_type;
    switch ((BBLLVMCodeGenerationFileType)options.code_generation_file_type)
    {
        case BBLLVMCodeGenerationFileType::assembly_file: file_type = CodeGenFileType::AssemblyFile; break;
        case BBLLVMCodeGenerationFileType::object_file: file_type = CodeGenFileType::ObjectFile; break;
        case BBLLVMCodeGenerationFileType::null: file_type = CodeGenFileType::Null; break;
    }

    auto disable_verify = !options.verify_module;
    if (target_machine.addPassesToEmitFile(CodeGenPasses, *stream, dwarf_object_file, file_type, disable_verify))
    {
        return BBLLVMCodeGenerationPipelineResult::failed_to_add_emit_passes;
    }

    CodeGenPasses.run(module);

    return BBLLVMCodeGenerationPipelineResult::success;
}

struct LLDResult
{
    BBLLVMString stdout_string;
    BBLLVMString stderr_string;
    bool success;
};

#define lld_api_args() const char** argument_pointer, u64 argument_count, bool exit_early, bool disable_output
#define lld_api_function_decl(link_name) LLDResult lld_ ## link_name ## _link(lld_api_args())
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
        auto* stdout_pointer = new char[stdout_length];
        memcpy(stdout_pointer, stdout_string.data(), stdout_length);
        result.stdout_string = { stdout_pointer, stdout_length };
    }

    auto stderr_length = stderr_string.length();
    if (stderr_length)
    {
        auto* stderr_pointer = new char[stderr_length];
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

lld_api_function_impl(coff)
lld_api_function_impl(elf)
lld_api_function_impl(mingw)
lld_api_function_impl(macho)
lld_api_function_impl(wasm)
