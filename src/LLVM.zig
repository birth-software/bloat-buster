const lib = @import("lib.zig");
const Arena = lib.Arena;
const api = @import("llvm_api.zig");

/// This is a String which ABI-compatible with C++
pub const String = extern struct {
    pointer: [*]const u8,
    length: usize,

    pub fn from_slice(slice: []const u8) String {
        return String{
            .pointer = slice.ptr,
            .length = slice.len,
        };
    }

    pub fn to_slice(string: String) []const u8 {
        return string.pointer[0..string.length];
    }
};

pub const CodeModel = enum(u8) {
    none = 0,
    tiny = 1,
    small = 2,
    kernel = 3,
    medium = 4,
    large = 5,
};

pub const RelocationModel = enum(u8) {
    default_relocation = 0,
    static_relocation = 1,
    pic = 2,
    dynamic_no_pic = 3,
    ropi = 4,
    rwpi = 5,
    ropi_rwpi = 6,
};

pub const CodeGenerationOptimizationLevel = enum(u8) {
    none = 0, // -O0
    less = 1, // -O1
    normal = 2, // -O2, -Os
    aggressive = 3, // -O3
};

/// This is ABI-compatible with C++
pub const TargetOptions = extern struct {
    reserved: u32,
};

/// This is ABI-compatible with C++
pub const TargetMachineCreate = extern struct {
    target_options: TargetOptions,
    cpu_triple: String,
    cpu_model: String,
    cpu_features: String,
    code_model: CodeModel,
    relocation_model: RelocationModel,
    optimization_level: CodeGenerationOptimizationLevel,
    jit: bool,
    reserved: u32,
};

pub const Architecture = enum {
    X86,
};

pub const TargetInitializerOptions = struct {
    asm_parser: bool = true,
    asm_printer: bool = true,
    disassembler: bool = false,
};

const targets = [@typeInfo(Architecture).@"enum".fields.len]type{
    api.get_initializer(.X86),
};

pub const Context = opaque {
    pub const create = api.LLVMContextCreate;
    pub fn create_module(context: *Context, name: [:0]const u8) *Module {
        return api.llvm_context_create_module(context, String.from_slice(name));
    }
    pub const create_builder = api.LLVMCreateBuilderInContext;
    pub fn create_basic_block(context: *Context, name: []const u8, parent: *Function) *BasicBlock {
        return api.llvm_context_create_basic_block(context, String.from_slice(name), parent);
    }
};

pub const BasicBlock = opaque {};

pub const Module = opaque {
    pub const create_di_builder = api.LLVMCreateDIBuilder;

    pub fn to_string(module: *Module) []const u8 {
        return api.llvm_module_to_string(module).to_slice();
    }

    const FunctionCreate = struct {
        type: *Type.Function,
        linkage: LinkageType,
        address_space: c_uint = 0,
        name: []const u8,
    };

    pub fn create_function(module: *Module, create: FunctionCreate) *Function {
        return api.llvm_module_create_function(module, create.type, create.linkage, create.address_space, String.from_slice(create.name));
    }

    pub fn verify(module: *Module) VerifyResult {
        var result: VerifyResult = undefined;
        var string: String = undefined;
        result.success = api.llvm_module_verify(module, &string);
        result.error_message = string.to_slice();
        return result;
    }
};

pub const VerifyResult = struct {
    error_message: []const u8,
    success: bool,
};

pub const Builder = opaque {
    pub const position_at_end = api.LLVMPositionBuilderAtEnd;

    pub const create_ret = api.LLVMBuildRet;

    pub fn create_ret_void(builder: *Builder) void {
        builder.create_ret(null);
    }
};

pub const Function = opaque {
    pub fn verify(function: *Function) VerifyResult {
        var result: VerifyResult = undefined;
        var string: String = undefined;
        result.success = api.llvm_function_verify(function, &string);
        result.error_message = string.to_slice();
        return result;
    }
};

pub const Constant = opaque {
    pub fn to_value(constant: *Constant) *Value {
        return @ptrCast(constant);
    }

    pub const Integer = opaque {
        pub fn to_value(constant: *Constant.Integer) *Value {
            return @ptrCast(constant);
        }
    };
};

pub const Value = opaque {};

pub const DI = struct {
    pub const Builder = opaque {
        pub fn create_file(builder: *DI.Builder, file_name: []const u8, directory_name: []const u8) *File {
            return api.LLVMCreateDIBuilder(builder, file_name.ptr, file_name.len, directory_name.ptr, directory_name.len);
        }
    };
    pub const File = opaque {};

    const Flags = enum(c_int) {
        _,
        const Zero = 0;
        const Private = 1;
        const Protected = 2;
        const Public = 3;
        const FwdDecl = 1 << 2;
        const AppleBlock = 1 << 3;
        const ReservedBit4 = 1 << 4;
        const Virtual = 1 << 5;
        const Artificial = 1 << 6;
        const Explicit = 1 << 7;
        const Prototyped = 1 << 8;
        const ObjcClassComplete = 1 << 9;
        const ObjectPointer = 1 << 10;
        const Vector = 1 << 11;
        const StaticMember = 1 << 12;
        const LValueReference = 1 << 13;
        const RValueReference = 1 << 14;
        const Reserved = 1 << 15;
        const SingleInheritance = 1 << 16;
        const MultipleInheritance = 2 << 16;
        const VirtualInheritance = 3 << 16;
        const IntroducedVirtual = 1 << 18;
        const BitField = 1 << 19;
        const NoReturn = 1 << 20;
        const TypePassByValue = 1 << 22;
        const TypePassByReference = 1 << 23;
        const EnumClass = 1 << 24;
        const Thunk = 1 << 25;
        const NonTrivial = 1 << 26;
        const BigEndian = 1 << 27;
        const LittleEndian = 1 << 28;
        const IndirectVirtualBase = (1 << 2) | (1 << 5);
        const Accessibility = Private | Protected | Public;
        const PtrToMemberRep = SingleInheritance | MultipleInheritance | VirtualInheritance;
    };
};

pub const Type = opaque {
    pub const Function = opaque {
        pub fn get(return_type: *Type, parameter_types: []const *Type, is_var_args: c_int) *Type.Function {
            return api.LLVMFunctionType(return_type, parameter_types.ptr, @intCast(parameter_types.len), is_var_args);
        }
    };

    pub const Integer = opaque {
        pub const get_constant = api.LLVMConstInt;
        pub fn to_type(integer: *Type.Integer) *Type {
            return @ptrCast(integer);
        }
    };
};

pub const LinkageType = enum(c_int) {
    ExternalLinkage,
    AvailableExternallyLinkage,
    LinkOnceAnyLinkage,
    LinkOnceODRLinkage,
    WeakAnyLinkage,
    WeakODRLinkage,
    AppendingLinkage,
    InternalLinkage,
    PrivateLinkage,
    ExternalWeakLinkage,
    CommonLinkage,
};

pub const DwarfSourceLanguage = enum(c_int) {
    c17 = 0x2c,
};
pub const DwarfEmissionKind = enum(c_int) {
    none,
    full,
    line_tables_only,
};

pub const Thread = struct {
    context: *Context,
    i1: Integer,
    i8: Integer,
    i16: Integer,
    i32: Integer,
    i64: Integer,
    i128: Integer,

    pub const Integer = struct {
        type: *Type.Integer,
        zero: *Constant.Integer,
    };

    pub fn initialize(thread: *Thread) void {
        const context = Context.create();
        const type_i1 = api.LLVMInt1TypeInContext(context);
        const type_i8 = api.LLVMInt8TypeInContext(context);
        const type_i16 = api.LLVMInt16TypeInContext(context);
        const type_i32 = api.LLVMInt32TypeInContext(context);
        const type_i64 = api.LLVMInt64TypeInContext(context);
        const type_i128 = api.LLVMInt128TypeInContext(context);
        const zero_i1 = type_i1.get_constant(0, 0);
        const zero_i8 = type_i8.get_constant(0, 0);
        const zero_i16 = type_i16.get_constant(0, 0);
        const zero_i32 = type_i32.get_constant(0, 0);
        const zero_i64 = type_i64.get_constant(0, 0);
        const zero_i128 = type_i128.get_constant(0, 0);

        thread.* = .{
            .context = context,
            .i1 = .{
                .type = type_i1,
                .zero = zero_i1,
            },
            .i8 = .{
                .type = type_i8,
                .zero = zero_i8,
            },
            .i16 = .{
                .type = type_i16,
                .zero = zero_i16,
            },
            .i32 = .{
                .type = type_i32,
                .zero = zero_i32,
            },
            .i64 = .{
                .type = type_i64,
                .zero = zero_i64,
            },
            .i128 = .{
                .type = type_i128,
                .zero = zero_i128,
            },
        };
    }
};

const Global = struct {
    threads: []Thread,
    host_triple: []const u8,
    host_cpu_model: []const u8,
    host_cpu_features: []const u8,
};
pub var global: Global = undefined;

// This is meant to call globally, only once per execution
pub fn initialize_all() void {
    inline for (targets) |target| {
        target.initialize(.{});
    }

    global = .{
        .threads = lib.global.arena.allocate(Thread, lib.global.thread_count),
        .host_triple = api.llvm_default_target_triple().to_slice(),
        .host_cpu_model = api.llvm_host_cpu_name().to_slice(),
        .host_cpu_features = api.llvm_host_cpu_features().to_slice(),
    };
}

pub fn experiment() void {
    const thread = &global.threads[0];
    thread.initialize();
    const module = thread.context.create_module("first_module");
    const builder = thread.context.create_builder();
    // const di_builder = module.create_di_builder();
    const return_type = thread.i32.type;
    const return_value = thread.i32.zero;
    // const return_value = thread.
    const function_type = Type.Function.get(return_type.to_type(), &.{}, 0);
    const function = module.create_function(.{
        .type = function_type,
        .linkage = .ExternalLinkage,
        .name = "main",
    });
    const entry_basic_block = thread.context.create_basic_block("entry", function);
    builder.position_at_end(entry_basic_block);
    builder.create_ret(return_value.to_value());
    const function_verify = function.verify();
    if (!function_verify.success) {
        unreachable;
    }
    const module_verify = module.verify();
    if (!module_verify.success) {
        unreachable;
    }

    const module_string = module.to_string();
    lib.print_string(module_string);
}
