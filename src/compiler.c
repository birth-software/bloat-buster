#pragma once

#include <compiler.h>
#include <lexer.h>
#include <parser.h>
#include <analysis.h>
#include <llvm_common.h>
#include <llvm_generate.h>
#include <llvm_optimize.h>
#include <llvm_emit.h>
#include <llvm_link.h>

#if UNITY_BUILD
#include <lib.c>
#include <lexer.c>
#include <parser.c>
#include <analysis.c>
#include <abi.c>
#include <abi_aarch64.c>
#include <abi_system_v.c>
#include <abi_win64.c>
#include <llvm_common.c>
#include <llvm_generate.c>
#include <llvm_optimize.c>
#include <llvm_emit.c>
#include <llvm_link.c>
#endif

#include <llvm-c/Core.h>

#include <stdatomic.h>
#if defined (__linux__) || defined(__APPLE__)
#include <unistd.h>
#include <pthread.h>

#define USE_IO_URING 0
#else
#define USE_IO_URING 0
#endif

#if USE_IO_URING
#include <liburing.h>
#endif

STRUCT(CompileUnitSlice)
{
    CompileUnit* pointer;
    u64 length;
};

typedef enum CompilerBackend
{
    COMPILER_BACKEND_LLVM,
    COMPILER_BACKEND_BB,
    COMPILER_BACKEND_COUNT,
} CompilerBackend;

typedef enum LinkerBackend
{
    LINKER_BACKEND_LLD,
    LINKER_BACKEND_BB,
} LinkerBackend;

typedef enum CompilationResultId
{
    COMPILATION_RESULT_FILE_ERROR,
    COMPILATION_RESULT_LEXER_ERROR,
    COMPILATION_RESULT_PARSER_ERROR,
    COMPILATION_RESULT_SEMANTIC_ERROR,
    COMPILATION_RESULT_LLVM_IR_ERROR,
    COMPILATION_RESULT_LLVM_OPTIMIZATION_ERROR,
    COMPILATION_RESULT_LLVM_CODEGEN_ERROR,
    COMPILATION_RESULT_LINKER_ERROR,
} CompilationResultId;

STRUCT(CompilationResult)
{
    CompilationResultId id;
};

// static_assert(sizeof(CompileUnit) % CACHE_LINE_GUESS == 0);

LOCAL bool is_single_threaded = true;
LOCAL CompileUnitSlice global_compile_units;
LOCAL _Atomic(u64) global_completed_compile_unit_count = 0;

LOCAL str generate_path_internal(Arena* arena, str directory, str name, str extension)
{
    check(name.pointer);
    str strings[] = {
        directory.pointer ? directory : S("./"),
        name,
        extension.pointer ? extension : S(""),
    };
    str file_path = arena_join_string(arena, string_array_to_slice(strings), true);
    return file_path;
}

LOCAL str generate_artifact_path(CompileUnit* unit, str extension)
{
    let original_directory_artifact_path = unit->artifact_directory_path;
    let artifact_path = original_directory_artifact_path.pointer ? original_directory_artifact_path : S("build/");
    let first_file = file_pointer_from_reference(unit, unit->first_file);
    str result = generate_path_internal(get_default_arena(unit), artifact_path, first_file->name, extension);
    return result;
}

LOCAL str generate_object_path(CompileUnit* unit)
{
    let extension = unit->target.os == OPERATING_SYSTEM_WINDOWS ? S(".obj") : S(".o");
    return generate_artifact_path(unit, extension);
}

LOCAL str generate_executable_path(CompileUnit* unit)
{
    let extension = unit->target.os == OPERATING_SYSTEM_WINDOWS ? S(".exe") : (str){};
    let result = generate_artifact_path(unit, extension);
    unit->artifact_path = result;
    return result;
}

LOCAL CompilationResult llvm_compile_file(CompileUnit* unit, str path)
{
    return (CompilationResult){};
}

LOCAL void llvm_compile_unit(StringSlice paths)
{
    //let arena_init_start = take_timestamp();
    let arena = arena_create((ArenaInitialization){});
    //let arena_init_end = take_timestamp();
    //let arena_init_ns = ns_between(arena_init_start, arena_init_end);
    //printf("Arena initialization time: %lu ns\n", arena_init_ns);

    let unit = arena_allocate(arena, CompileUnit, 1);
    memset(unit, 0, sizeof(CompileUnit));

    for (u64 i = 0; i < paths.length; i += 1)
    {
        str path = paths.pointer[i];
        llvm_compile_file(unit, path);
    }

    let index = atomic_fetch_add(&global_completed_compile_unit_count, 1);
    memcpy(&global_compile_units.pointer[index], unit, sizeof(*unit));
}

LOCAL u64 classic_integer_type_count = 64 * 2;
LOCAL u64 big_integer_type_count = (
        1 +  // 128
        1 +  // 256
        1    // 512
        ) * 2;
LOCAL u64 float_type_count = 5;
LOCAL u64 void_noreturn_type_count = 2;

PUB_IMPL u64 get_base_type_count()
{
    return classic_integer_type_count + big_integer_type_count + float_type_count + void_noreturn_type_count;
}

LOCAL void default_show_callback(void* context, str message)
{
    unused(context);
    os_file_write(os_get_stdout(), message);
}

LOCAL CompileUnit* compile_unit_create()
{
    let arena = arena_create((ArenaInitialization) {
        .count = UNIT_ARENA_COUNT,
    });

    let unit = arena_allocate(arena, CompileUnit, 1);
    *unit = (CompileUnit) {};
    let global_scope = unit->scope;
    let type_arena = unit_arena(unit, UNIT_ARENA_TYPE);
    check(type_arena->position == sizeof(Arena));

    let base_type_count = get_base_type_count();
    let base_type_allocation = arena_allocate(type_arena, Type, base_type_count);

    let type = base_type_allocation;

    for (u8 is_signed = 0; is_signed < 2; is_signed += 1)
    {
        for (u64 bit_count = 1; bit_count <= 64; bit_count += 1)
        {
            char first_digit = bit_count < 10 ? bit_count % 10 + '0' : bit_count / 10 + '0';
            char second_digit = bit_count > 9 ? bit_count % 10 + '0' : 0;
            char buffer[] = { is_signed ? 's' : 'u', first_digit, second_digit };
            u64 name_length = 2 + (bit_count > 9);

            let name = allocate_string(unit, (str){ buffer, name_length });
            
            *type = (Type){
                .integer = {
                    .bit_count = bit_count,
                    .is_signed = is_signed,
                },
                .name = name,
                .scope = global_scope,
                .id = TYPE_ID_INTEGER,
                .analyzed = 1,
                .use_count = UINT32_MAX,
            };
            type += 1;
        }
    }

    const static str names[] = { S("u128"), S("s128"), S("u256"), S("s256"), S("u512"), S("s512") };
    check(array_length(names) == big_integer_type_count);
    for (u64 i = 0; i < (big_integer_type_count / 2); i += 1)
    {
        for (u8 is_signed = 0; is_signed < 2; is_signed += 1)
        {
            let bit_count = 128ULL << i;
            let name = allocate_string(unit, names[i * 2 + is_signed]);
            *type = (Type) {
                .integer = {
                    .bit_count = bit_count,
                    .is_signed = is_signed,
                },
                .name = name,
                .scope = global_scope,
                .id = TYPE_ID_INTEGER,
                .analyzed = 1,
                .use_count = UINT32_MAX,
            };
            type += 1;
        }
    }

    let f16_type = type;
    type += 1;

    let bf16_type = type;
    type += 1;

    let f32_type = type;
    type += 1;

    let f64_type = type;
    type += 1;

    let f128_type = type;
    type += 1;

    let void_type = type;
    type += 1;

    let noreturn_type = type;
    type += 1;

    check(type == base_type_allocation + base_type_count);

    *f16_type = (Type) {
        .fp = TYPE_FLOAT_F16,
        .name = allocate_string(unit, S("f16")),
        .scope = global_scope,
        .id = TYPE_ID_FLOAT,
        .analyzed = 1,
        .use_count = UINT32_MAX,
    };

    *bf16_type = (Type) {
        .fp = TYPE_FLOAT_BF16,
        .name = allocate_string(unit, S("bf16")),
        .scope = global_scope,
        .id = TYPE_ID_FLOAT,
        .analyzed = 1,
        .use_count = UINT32_MAX,
    };

    *f32_type = (Type) {
        .fp = TYPE_FLOAT_F32,
        .name = allocate_string(unit, S("f32")),
        .scope = global_scope,
        .id = TYPE_ID_FLOAT,
        .analyzed = 1,
        .use_count = UINT32_MAX,
    };

    *f64_type = (Type) {
        .fp = TYPE_FLOAT_F64,
        .name = allocate_string(unit, S("f64")),
        .scope = global_scope,
        .id = TYPE_ID_FLOAT,
        .analyzed = 1,
        .use_count = UINT32_MAX,
    };

    *f128_type = (Type) {
        .fp = TYPE_FLOAT_F128,
        .name = allocate_string(unit, S("f128")),
        .scope = global_scope,
        .id = TYPE_ID_FLOAT,
        .analyzed = 1,
        .use_count = UINT32_MAX,
    };

    *void_type = (Type) {
        .name = allocate_string(unit, S("void")),
        .scope = global_scope,
        .id = TYPE_ID_VOID,
        .analyzed = 1,
        .use_count = UINT32_MAX,
    };

    *noreturn_type = (Type) {
        .name = allocate_string(unit, S("noreturn")),
        .scope = global_scope,
        .id = TYPE_ID_NORETURN,
        .analyzed = 1,
        .use_count = UINT32_MAX,
    };

    let void_value = arena_allocate(unit_arena(unit, UNIT_ARENA_VALUE), Value, 1);
    *void_value = (Value) {
        .type = get_void_type(unit),
        .id = VALUE_ID_DISCARD,
    };

    unit->pointer_size = sizeof(void*);
    unit->pointer_alignment = alignof(void*);
    unit->has_debug_info = true;
    unit->show_callback = &default_show_callback;
    unit->verbose = true;
    unit->target = (Target) {
#ifdef __x86_64__
        .cpu = CPU_ARCH_X86_64,
#endif
#ifdef __aarch64__
        .cpu = CPU_ARCH_AARCH64,
#endif
#ifdef __linux__
        .os = OPERATING_SYSTEM_LINUX,
#endif
#ifdef __APPLE__
        .os = OPERATING_SYSTEM_MACOS,
#endif
#ifdef _WIN32
        .os = OPERATING_SYSTEM_WINDOWS,
#endif
    };

    if (unit->target.cpu == CPU_ARCH_UNKNOWN)
    {
        str parts[] = {\
            S("TODO at: "),
            S(__FILE__),
            S(":"),
            S(__FUNCTION__),
            S(":"),
            format_integer(arena, (FormatIntegerOptions) {
                    .format = INTEGER_FORMAT_DECIMAL,
                    .value = __LINE__,
                    }, false)
        };\
        unit_show(unit, arena_join_string(arena, string_array_to_slice(parts), true));
        fail();
    }

    if (unit->target.os == OPERATING_SYSTEM_UNKNOWN)
    {
        str parts[] = {\
            S("TODO at: "),
            S(__FILE__),
            S(":"),
            S(__FUNCTION__),
            S(":"),
            format_integer(arena, (FormatIntegerOptions) {
                    .format = INTEGER_FORMAT_DECIMAL,
                    .value = __LINE__,
                    }, false)
        };\
        unit_show(unit, arena_join_string(arena, string_array_to_slice(parts), true));
        fail();
    }

    return unit;
}

PUB_IMPL TypeReference get_void_type(CompileUnit* restrict unit)
{
    let void_offset = classic_integer_type_count + big_integer_type_count + float_type_count;
    let void_type_index = type_reference_from_index(unit, void_offset);
    let void_type = type_pointer_from_reference(unit, void_type_index);
    check(void_type->id == TYPE_ID_VOID);
    return void_type_index;
}

PUB_IMPL TypeReference get_noreturn_type(CompileUnit* restrict unit)
{
    let noreturn_type_index = get_void_type(unit);
    noreturn_type_index.v += 1;
    let noreturn_type = type_pointer_from_reference(unit, noreturn_type_index);
    check(noreturn_type->id == TYPE_ID_NORETURN);
    return noreturn_type_index;
}

PUB_IMPL TypeReference get_integer_type(CompileUnit* restrict unit, u64 bit_count, bool is_signed)
{
    check(bit_count != 0);
    check(bit_count <= 64 || bit_count == 128 || bit_count == 256 || bit_count == 512);
    let type_index = bit_count > 64 ? (1ULL << __builtin_ctzg(bit_count - 128)) * 2 + is_signed : is_signed * 64 + (bit_count - 1);
    let result_index = type_reference_from_index(unit, type_index);
    let result = type_pointer_from_reference(unit, result_index);
    check(result->id == TYPE_ID_INTEGER);
    return result_index;
}

PUB_IMPL StringReference allocate_string(CompileUnit* restrict unit, str s)
{
    str slices[] = { s };
    return allocate_and_join_string(unit, string_array_to_slice(slices));
}

PUB_IMPL StringReference allocate_and_join_string(CompileUnit* restrict unit, StringSlice slice)
{
    let arena = unit_arena(unit, UNIT_ARENA_STRING);
    let arena_byte_pointer = (char*)arena;
    let arena_bottom = arena_byte_pointer;
    let arena_position = arena->position;
    let arena_top = arena_byte_pointer + arena_position;

    u64 string_length = 0;

    for (u64 i = 0; i < slice.length; i += 1)
    {
        let string = slice.pointer[i];
        check((!((string.pointer > arena_bottom) & (string.pointer < arena_top))) || slice.length != 1); // Repeated string
        check(string.length <= UINT32_MAX);
        string_length += string.length;
    }

    StringReference result = {};

    u64 i = sizeof(Arena);
    static_assert(alignof(Arena) >= alignof(u32));
    while (i < arena_position)
    {
        let byte_pointer = arena_byte_pointer + i;
        let length = *(u32*)byte_pointer;

        if (length == string_length)
        {
            u64 offset = sizeof(u32);
            bool is_equal = true;
            for (u64 string_i = 0; string_i < slice.length; string_i += 1)
            {
                let string = slice.pointer[string_i];
                is_equal = memcmp(string.pointer, byte_pointer + offset, string.length) == 0;
                offset += string.length;
                if (!is_equal)
                {
                    break;
                }
            }

            if (is_equal)
            {
                result = (StringReference) {
                    .v = (u32)(i + 1),
                };
                break;
            }
        }

        i += align_forward(length + 1 + sizeof(u32), alignof(u32));
    }

    if (!is_ref_valid(result))
    {
        let allocation_size = string_length + sizeof(u32) + 1;
        let string = (char* restrict) arena_allocate_bytes(arena, allocation_size, alignof(u32));
        check(string_length < UINT32_MAX);
        *(u32*)string = (u32)string_length;
        let pointer = string + 4;

        for (u64 i = 0; i < slice.length; i += 1)
        {
            let string = slice.pointer[i];
            memcpy(pointer, string.pointer, string.length);
            pointer += string.length;
        }

        *pointer = 0;

        let big_offset = string - arena_byte_pointer;
        check(big_offset + 1 < UINT32_MAX);
        let offset = (u32)big_offset;
        result = (StringReference) {
            .v = offset + 1,
        };
    }

    return result;
}

PUB_IMPL StringReference allocate_string_if_needed(CompileUnit* restrict unit, str s)
{
    let arena = unit_arena(unit, UNIT_ARENA_STRING);
    let arena_byte_pointer = (char*)arena;
    let arena_bottom = arena_byte_pointer;
    let arena_top = arena_byte_pointer + arena->position;

    if ((s.pointer > arena_bottom) & (s.pointer < arena_top))
    {
        // let string_reference = string_reference_from_string(unit, s);
        todo();
    }
    else
    {
        return allocate_string(unit, s);
    }
}

LOCAL void crunch_file(CompileUnit* restrict unit, str path)
{
    let default_arena = get_default_arena(unit);
    let absolute_path = path_absolute(default_arena, path.pointer);
    str content = file_read(unit_arena(unit, UNIT_ARENA_FILE_CONTENT), absolute_path, (FileReadOptions){
        .start_padding = sizeof(u32),
        .start_alignment = alignof(u32),
    });
    check(content.length < UINT32_MAX);
    *((u32*)content.pointer - 1) = content.length;

    u8 path_separator;
#if defined(_WIN32)
    path_separator = '\\';
#else
    path_separator = '/';
#endif

    let last_slash_index = str_last_ch(absolute_path, path_separator);

    check(last_slash_index != string_no_match);
    let directory_path = (str){ absolute_path.pointer, last_slash_index };
    let file_name = (str){ absolute_path.pointer + last_slash_index + 1, absolute_path.length - last_slash_index - 1 };
    let name_nz = (str) { file_name.pointer, file_name.length - strlen(".bbb") };
    let name = arena_duplicate_string(default_arena, name_nz, true);

    let scope = new_scope(unit);
    let file = arena_allocate(default_arena, File, 1);
    let file_reference = file_reference_from_pointer(unit, file);

    if (is_ref_valid(unit->last_file))
    {
        todo();
    }
    else
    {
        check(!is_ref_valid(unit->first_file));
        unit->first_file = file_reference;
    }

    unit->last_file = file_reference;

    *scope = (Scope)
    {
        .parent = unit->scope,
        .id = SCOPE_ID_FILE,
        .file = file_reference,
    };

    *file = (File) {
        .content = content,
        .path = absolute_path,
        .directory = directory_path,
        .file_name = file_name,
        .name = name,
        .scope = scope_reference_from_pointer(unit, scope),
    };

    let tl = lex(unit, file);
    unit_show(unit, S("Lexing done!"));
    parse(unit, file, tl);
    unit_show(unit, S("Parsing done!"));
}

LOCAL void print_llvm_message(CompileUnit* restrict unit, str message)
{
    check(message.pointer);
    unit_show(unit, message);
    LLVMDisposeMessage(message.pointer);
}

LOCAL bool compile_unit_internal(CompileUnit* unit, str path)
{
    bool result_code = 1;
    crunch_file(unit, path);
    analyze(unit);
    unit_show(unit, S("Analysis done!"));
    let generate = llvm_generate_ir(unit, true);
    unit_show(unit, S("LLVM generation done!"));

    if (unit->verbose & !!generate.module)
    {
        char* s = LLVMPrintModuleToString(generate.module);
        str module_str = { s, strlen(s) };
        print_llvm_message(unit, module_str);
    }

    if (generate.error_message.pointer)
    {
        print_llvm_message(unit, generate.error_message);
        result_code = 0;
    }
    else
    {
        LLVMOptimizationLevel llvm_optimization_level;
        switch (unit->build_mode)
        {
            break; case BUILD_MODE_DEBUG: llvm_optimization_level = LLVM_OPTIMIZATION_LEVEL_O0;
            break; case BUILD_MODE_SIZE: llvm_optimization_level = LLVM_OPTIMIZATION_LEVEL_Oz;
            break; case BUILD_MODE_SPEED: llvm_optimization_level = LLVM_OPTIMIZATION_LEVEL_O3;
            break; default: UNREACHABLE();
        }

        bool verify_each_pass = true;
        bool debug_logging = false;

        let error_message = llvm_optimize(generate.module, generate.target_machine, llvm_optimization_level, verify_each_pass, debug_logging);
        if (error_message)
        {
            todo();
        }
        else
        {
            unit_show(unit, S("LLVM optimization done!"));
            let object_path = generate_object_path(unit);
            unit->object_path = object_path;
            LLVMCodeGenFileType type = LLVMObjectFile;
            let error_message = llvm_emit(generate.module, generate.target_machine, object_path, type);
            if (error_message.pointer)
            {
                todo();
            }
            unit_show(unit, S("LLVM object done!"));
        }
    }

    return result_code;
}

LOCAL bool compile_unit(str path)
{
    let unit = compile_unit_create();
    return compile_unit_internal(unit, path);
}

LOCAL bool compile_and_link_single_unit_internal(CompileUnit* unit, str path)
{
    bool result = compile_unit_internal(unit, path);
    if (result)
    {
        CompileUnit* units[] = {
            unit,
        };
        let first_file = file_pointer_from_reference(unit, unit->first_file);

        str output_artifact_path = generate_executable_path(unit);
        str result_string = llvm_link_machine_code(get_default_arena(unit), unit_arena(unit, UNIT_ARENA_STRING), units, array_length(units), (LinkOptions) {
            .output_artifact_path = output_artifact_path,
        });

        result = !result_string.pointer;
        if (!result)
        {
            unit_show(unit, result_string);
        }
        unit_show(unit, S("Linking done!"));
    }

    return result;
}

LOCAL CompileUnit* compile_and_link_single_unit(str path)
{
    let unit = compile_unit_create();
    if (compile_and_link_single_unit_internal(unit, path))
    {
        return unit;
    }
    else
    {
        return 0;
    }
}

LOCAL let test_source_path = S("tests/tests.bbb");

LOCAL CompileUnit* compile_tests()
{
    let result = compile_and_link_single_unit(test_source_path);
    return result;
}

LOCAL void* thread_worker(void* arg)
{
    return (void*)(u64)!compile_tests();
}

LOCAL ThreadReturnType llvm_initialization_thread(void*)
{
    llvm_initialize();
    return (ThreadReturnType)0;
}

typedef enum CompilerCommand : u8
{
    COMPILER_COMMAND_TEST,
} CompilerCommand;

LOCAL CompilerCommand default_command = COMPILER_COMMAND_TEST;

LOCAL void compiler_test_log(void* context, str string)
{
}

LOCAL bool compiler_tests()
{
    let arena_init = (ArenaInitialization){};
    TestArguments test_arguments = {
        .arena = arena_create(arena_init),
        .show = &compiler_test_log,
    };
    let result = 
        lib_tests(&test_arguments) &
        parser_tests(&test_arguments) &
        analysis_tests(&test_arguments) &
        llvm_generation_tests(&test_arguments) &
        arena_destroy(test_arguments.arena, arena_init.count);
    return result;
}

LOCAL bool unit_run(CompileUnit* restrict unit, StringSlice slice, char** envp)
{
    char* arg_buffer[64];
    
    char** arguments = {};
    if (slice.length)
    {
        todo();
    }
    else
    {
        arguments = arg_buffer;
        arguments[0] = unit->artifact_path.pointer;
        arguments[1] = 0;
    }
    let result = os_execute(get_default_arena(unit), arguments, envp, (ExecutionOptions) {});
    return (result.termination_kind == TERMINATION_KIND_EXIT) & (result.termination_code == 0);
}

LOCAL bool process_command_line(int argc, const char* argv[], char** envp)
{
    check(is_single_threaded);

    bool result = 1;
    let command = default_command;

    if ((argc != 0) & (argc != 1))
    {
        exit(1);
    }

    switch (command)
    {
        break; case COMPILER_COMMAND_TEST:
        {
#if BB_INCLUDE_TESTS
            result = compiler_tests();
            if (!result)
            {
                os_file_write(os_get_stdout(), S("Compiler unit tests failed to run!"));
                fail();
            }
#endif
            if (result)
            {
                let llvm_thread = os_thread_create(&llvm_initialization_thread, (ThreadCreateOptions){});

                if (result)
                {
                    let unit = compile_tests();
                    bool run_result = 0;
                    if (unit)
                    {
                        run_result = unit_run(unit, (StringSlice){}, envp);
                        if (!run_result)
                        {
                            unit_show(unit, S("Test executable did not exit properly!"));
                        }
                    }
                    else
                    {
                        print(S("Unit failed to compile!\n"));
                    }

                    let return_value = os_thread_join(llvm_thread);
                    if (return_value != 0)
                    {
                        print(S("LLVM initialization thread failed!\n"));
                    }
                    result = (unit != 0) & (return_value == 0) & (run_result);
                }
            }
        }
        break; default:
        {
            result = 0;
        }
    }

    return result;
}

PUB_IMPL Aarch64AbiKind get_aarch64_abi_kind(OperatingSystem os)
{
    switch (os)
    {
        break; case OPERATING_SYSTEM_UNKNOWN: UNREACHABLE();
        break; case OPERATING_SYSTEM_LINUX: return AARCH64_ABI_KIND_AAPCS;
        break; case OPERATING_SYSTEM_MACOS: return AARCH64_ABI_KIND_DARWIN_PCS;
        break; case OPERATING_SYSTEM_WINDOWS: return AARCH64_ABI_KIND_WIN64;
    }
}

PUB_IMPL TypeEvaluationKind get_type_evaluation_kind(CompileUnit* restrict unit, Type* type)
{
    switch (type->id)
    {
        case TYPE_ID_VOID:
        case TYPE_ID_NORETURN:
        case TYPE_ID_FUNCTION:
        case TYPE_ID_OPAQUE:
            UNREACHABLE();
        case TYPE_ID_INTEGER:
        case TYPE_ID_FLOAT:
        case TYPE_ID_ENUM:
        case TYPE_ID_POINTER:
        case TYPE_ID_BITS:
        case TYPE_ID_VECTOR:
            return TYPE_EVALUATION_KIND_SCALAR;
        case TYPE_ID_ARRAY:
        case TYPE_ID_STRUCT:
        case TYPE_ID_UNION:
        case TYPE_ID_ENUM_ARRAY:
            return TYPE_EVALUATION_KIND_AGGREGATE;
        case TYPE_ID_COUNT:
            UNREACHABLE();
    }
}

PUB_IMPL bool type_is_aggregate_for_abi (CompileUnit* restrict unit, Type* type)
{
    let evaluation_kind = get_type_evaluation_kind(unit, type);
    bool is_member_function_pointer_type = false; // TODO
    return (evaluation_kind != TYPE_EVALUATION_KIND_SCALAR) | is_member_function_pointer_type;
}

PUB_IMPL bool type_is_promotable_integer_for_abi(CompileUnit* restrict unit, Type* type)
{
    if (type->id == TYPE_ID_BITS)
    {
        todo();
    }

    if (type->id == TYPE_ID_ENUM)
    {
        todo();
    }

    return (type->id == TYPE_ID_INTEGER) & (type->integer.bit_count < 32);
}

PUB_IMPL bool type_is_integral_or_enumeration(CompileUnit* restrict unit, TypeReference type_reference)
{
    let type_pointer = type_pointer_from_reference(unit, type_reference);

    switch (type_pointer->id)
    {
        break;
        case TYPE_ID_INTEGER:
        {
            return 1;
        }
        break; default:
        {
            UNREACHABLE();
        }
    }
}


PUB_IMPL TypeReference get_semantic_return_type(TypeFunction* restrict function)
{
    return function->semantic_types[0];
}

PUB_IMPL TypeReference get_semantic_argument_type(TypeFunction* restrict function, u16 semantic_argument_index)
{
    check(semantic_argument_index < function->semantic_argument_count);
    return function->semantic_types[semantic_argument_index + 1];
}

PUB_IMPL TypeReference get_abi_return_type(TypeFunction* restrict function)
{
    return function->abi_types[0];
}

PUB_IMPL TypeReference get_abi_argument_type(TypeFunction* restrict function, u16 abi_argument_index)
{
    check(abi_argument_index < function->abi_argument_count);
    return function->abi_types[abi_argument_index + 1];
}

PUB_IMPL AbiInformation* restrict get_abis(TypeFunction* restrict function)
{
    return (AbiInformation*)(align_forward((u64)function->semantic_types + ((function->semantic_argument_count + 1) * sizeof(function->semantic_types[0])), alignof(AbiInformation)));
}

PUB_IMPL AbiInformation* restrict get_return_abi(TypeFunction* restrict function)
{
    return &get_abis(function)[0];
}

PUB_IMPL AbiInformation* restrict get_argument_abi(TypeFunction* restrict function, u16 semantic_argument_index)
{
    check(semantic_argument_index < function->semantic_argument_count);
    return &get_abis(function)[semantic_argument_index + 1];
}

PUB_IMPL bool value_id_is_intrinsic(ValueId id)
{
    switch (id)
    {
        case VALUE_ID_INTRINSIC_VALUE:
        case VALUE_ID_INTRINSIC_TYPE:
        case VALUE_ID_INTRINSIC_UNRESOLVED:
            return 1;
        default:
            return 0;
    }
}

PUB_IMPL u32 location_get_line(SourceLocation location)
{
    return location.line_number_offset + 1;
}

PUB_IMPL u32 location_get_column(SourceLocation location)
{
    return location.column_offset + 1;
}

PUB_IMPL bool statement_is_block_like(StatementId id)
{
    switch (id)
    {
        break;
        case STATEMENT_ID_BLOCK:
        case STATEMENT_ID_IF:
        case STATEMENT_ID_WHEN:
        case STATEMENT_ID_SWITCH:
        case STATEMENT_ID_WHILE:
        case STATEMENT_ID_FOR:
        {
            return 1;
        }
        break; default:
        {
            return 0;
        }
    }
}

PUB_IMPL void unit_show(CompileUnit* restrict unit, str message)
{
    let show = unit->show_callback;
    if (likely(show))
    {
        show(unit, message);
        show(unit, S("\n"));
    }
}

PUB_IMPL Arena* unit_arena(CompileUnit* unit, UnitArenaKind kind)
{
    Arena* arena = (Arena*)unit - 1;
    let result = (Arena*)((u8*)arena + ((s64)kind * arena->reserved_size));
    return result;
}

PUB_IMPL Arena* get_default_arena(CompileUnit* restrict unit)
{
    return unit_arena(unit, UNIT_ARENA_COMPILE_UNIT);
}

#define reference_offset_function_impl(O, o, AU) \
PUB_IMPL reference_offset_function_ref(O, o)\
{\
    let arena = unit_arena(unit, AU);\
    let o ## _byte_pointer = (u8*)o;\
    let arena_byte_pointer = (u8*)arena;\
    let arena_bottom = arena_byte_pointer;\
    let arena_top = arena_byte_pointer + arena->position;\
    check(o ## _byte_pointer > arena_bottom && o ## _byte_pointer < arena_top);\
    let sub = o ## _byte_pointer - arena_byte_pointer;\
    check(sub < UINT32_MAX);\
    return (O ## Reference) {\
        .v = (u32)(sub + 1),\
    };\
}\
PUB_IMPL reference_offset_function_ptr(O, o)\
{\
    check(o_reference.v != 0);\
    let arena = unit_arena(unit, AU);\
    let arena_byte_pointer = (u8*)arena;\
    let arena_bottom = arena_byte_pointer;\
    let arena_top = arena_byte_pointer + arena->position;\
    let o ## _byte_pointer = arena_byte_pointer + (o_reference.v - 1);\
    check(o ## _byte_pointer > arena_bottom && o ## _byte_pointer < arena_top);\
    let o = (O* restrict)o ## _byte_pointer; \
    return o;\
}

reference_offset_function_impl(Scope, scope, UNIT_ARENA_COMPILE_UNIT);
reference_offset_function_impl(File, file, UNIT_ARENA_COMPILE_UNIT);
reference_offset_function_impl(Argument, argument, UNIT_ARENA_COMPILE_UNIT);
reference_offset_function_impl(Local, local, UNIT_ARENA_COMPILE_UNIT);
reference_offset_function_impl(Global, global, UNIT_ARENA_COMPILE_UNIT);
reference_offset_function_impl(Statement, statement, UNIT_ARENA_COMPILE_UNIT);
reference_offset_function_impl(Block, block, UNIT_ARENA_COMPILE_UNIT);
reference_offset_function_impl(TopLevelDeclaration, top_level_declaration, UNIT_ARENA_COMPILE_UNIT);
reference_offset_function_impl(ValueNode, value_node, UNIT_ARENA_COMPILE_UNIT);
reference_offset_function_impl(Variable, variable, UNIT_ARENA_COMPILE_UNIT);

PUB_IMPL Global* get_current_function(CompileUnit* restrict unit)
{
    let current_function_ref = unit->current_function;
    if (!is_ref_valid(current_function_ref))
    {
        todo();
    }

    let current_function = global_pointer_from_reference(unit, current_function_ref);
    return current_function;
}

PUB_IMPL u64 get_byte_size(CompileUnit* restrict unit, Type* type_pointer)
{
    check(unit->phase >= COMPILE_PHASE_ANALYSIS);

    switch (type_pointer->id)
    {
        break; case TYPE_ID_INTEGER:
        {
            let bit_count = type_pointer->integer.bit_count;
            let byte_count = aligned_byte_count_from_bit_count(bit_count);
            return byte_count;
        }
        break; case TYPE_ID_POINTER:
        {
            return unit->pointer_size;
        }
        break; default:
        {
            todo();
        }
    }
}

PUB_IMPL u64 get_bit_size(CompileUnit* restrict unit, Type* restrict type)
{
    check(unit->phase >= COMPILE_PHASE_ANALYSIS);

    switch (type->id)
    {
        break; case TYPE_ID_INTEGER:
        {
            let bit_count = type->integer.bit_count;
            let byte_count = aligned_byte_count_from_bit_count(bit_count);
            return byte_count;
        }
        break; default:
        {
            todo();
        }
    }
}

PUB_IMPL bool type_is_signed(CompileUnit* restrict unit, Type* type)
{
    switch (type->id)
    {
        break; case TYPE_ID_INTEGER:
        {
            let is_signed = type->integer.is_signed;
            return is_signed;
        }
        break; default: todo();
    }
}

PUB_IMPL bool type_is_record(Type* restrict type)
{
    switch (type->id)
    {
        case TYPE_ID_VOID:
        case TYPE_ID_NORETURN:
        case TYPE_ID_INTEGER:
        case TYPE_ID_FLOAT:
        case TYPE_ID_FUNCTION:
        case TYPE_ID_ENUM:
        case TYPE_ID_POINTER:
        case TYPE_ID_OPAQUE:
        case TYPE_ID_ARRAY:
        case TYPE_ID_BITS:
        case TYPE_ID_VECTOR:
        case TYPE_ID_ENUM_ARRAY:
            return false;
        case TYPE_ID_STRUCT:
        case TYPE_ID_UNION:
            return true;
        case TYPE_ID_COUNT: UNREACHABLE();
    }
}

PUB_IMPL u32 get_alignment(CompileUnit* restrict unit, Type* type)
{
    switch (type->id)
    {
        break; case TYPE_ID_INTEGER:
        {
            let bit_count = type->integer.bit_count;
            let result = aligned_byte_count_from_bit_count(bit_count);
            check(result == 1 || result == 2 || result == 4 || result == 8 || result == 16);
            return result;
        }
        break; case TYPE_ID_POINTER:
        {
            return unit->pointer_alignment;
        }
        break; default: todo();
    }
}

PUB_IMPL ResolvedCallingConvention resolve_calling_convention(Target target, CallingConvention cc)
{
    switch (cc)
    {
        break; case CALLING_CONVENTION_C:
        {
            switch (target.cpu)
            {
                break; case CPU_ARCH_UNKNOWN: UNREACHABLE();
                break; case CPU_ARCH_X86_64:
                {
                    switch (target.os)
                    {
                        break; case OPERATING_SYSTEM_UNKNOWN: UNREACHABLE();
                        break; case OPERATING_SYSTEM_LINUX: return RESOLVED_CALLING_CONVENTION_SYSTEM_V;
                        break; case OPERATING_SYSTEM_MACOS: return RESOLVED_CALLING_CONVENTION_SYSTEM_V;
                        break; case OPERATING_SYSTEM_WINDOWS: return RESOLVED_CALLING_CONVENTION_WIN64;
                    }
                }
                break; case CPU_ARCH_AARCH64:
                {
                    return RESOLVED_CALLING_CONVENTION_AARCH64;
                }
                break; default: UNREACHABLE();
            }
        }
        break; default: UNREACHABLE();
    }
}

PUB_IMPL StringReference string_reference_from_string(CompileUnit* restrict unit, str s)
{
    let arena = unit_arena(unit, UNIT_ARENA_STRING);
    let arena_byte_pointer = (char*)arena;
    let arena_bottom = arena_byte_pointer;
    let arena_top = arena_byte_pointer + arena->position;
    check((arena_bottom < s.pointer) & (arena_top > s.pointer));
    let string_top = s.pointer + s.length;
    check(string_top <= arena_top);
    let length_pointer = (u32*)s.pointer - 1;
    let length = *length_pointer;
    check(s.length == length);

    let diff = (char*)length_pointer - arena_bottom;
    check(diff < UINT32_MAX);
    return (StringReference) {
        .v = diff + 1,
    };
}

PUB_IMPL str string_from_reference(CompileUnit* restrict unit, StringReference reference)
{
    check(is_ref_valid(reference));

    let arena = unit_arena(unit, UNIT_ARENA_STRING);
    let arena_byte_pointer = (char*)arena;
    let arena_bottom = arena_byte_pointer;
    let arena_position = arena->position;

    let length_offset = reference.v - 1;
    check(length_offset >= sizeof(Arena));
    check(length_offset < arena_position);
    let length_byte_pointer = arena_bottom + length_offset;
    let length_pointer = (u32*)length_byte_pointer;
    let string_pointer = (char* restrict) (length_pointer + 1);
    u64 string_length = *length_pointer;
    return (str){ .pointer = string_pointer, .length = string_length };
}

PUB_IMPL TypeReference type_reference_from_pointer(CompileUnit* restrict unit, Type* type)
{
    let type_arena = unit_arena(unit, UNIT_ARENA_TYPE);
    let arena_byte_pointer = (u8*)type_arena;
    let arena_position = type_arena->position;
    let arena_bottom = arena_byte_pointer;
    let arena_top = arena_byte_pointer + arena_position;
    let type_byte_pointer = (u8*)type;
    check(type_byte_pointer > arena_bottom && type_byte_pointer < arena_top);
    let diff = type_byte_pointer - (arena_bottom + sizeof(Arena));
    check(diff % sizeof(Type) == 0);
    check(diff < UINT32_MAX);
    diff /= sizeof(Type);
    return (TypeReference) {
        .v = diff + 1,
    };
}

PUB_IMPL TypeReference type_reference_from_index(CompileUnit* restrict unit, u32 index)
{
    let type_arena = unit_arena(unit, UNIT_ARENA_TYPE);
    let byte_offset = index * sizeof(Type);
    let arena_position = type_arena->position;
    check(sizeof(Arena) + byte_offset + sizeof(Type) <= arena_position);
    return (TypeReference) {
        .v = index + 1,
    };
}

PUB_IMPL Type* type_pointer_from_reference(CompileUnit* restrict unit, TypeReference reference)
{
    check(is_ref_valid(reference));
    let arena = unit_arena(unit, UNIT_ARENA_TYPE);
    let index = reference.v - 1;
    let byte_offset = index * sizeof(Type);
    let arena_position = arena->position;
    check(sizeof(Arena) + byte_offset + sizeof(Type) <= arena_position);
    let type = (Type*)((u8*)arena + sizeof(Arena) + byte_offset);
    return type;
}

PUB_IMPL ValueReference value_reference_from_pointer(CompileUnit* restrict unit, Value* value)
{
    let value_arena = unit_arena(unit, UNIT_ARENA_VALUE);
    let arena_byte_pointer = (u8*)value_arena;
    let arena_position = value_arena->position;
    let arena_bottom = arena_byte_pointer;
    let arena_top = arena_byte_pointer + arena_position;
    let value_byte_pointer = (u8*)value;
    check(value_byte_pointer > arena_bottom && value_byte_pointer < arena_top);
    let diff = value_byte_pointer - (arena_bottom + sizeof(Arena));
    check(diff % sizeof(Value) == 0);
    check(diff < UINT32_MAX);
    diff /= sizeof(Value);
    return (ValueReference) {
        .v = diff + 1,
    };
}

PUB_IMPL ValueReference value_reference_from_index(CompileUnit* restrict unit, u32 index)
{
    let value_arena = unit_arena(unit, UNIT_ARENA_VALUE);
    let byte_offset = index * sizeof(Value);
    let arena_position = value_arena->position;
    check(sizeof(Arena) + byte_offset + sizeof(Value) < arena_position);
    return (ValueReference) {
        .v = index + 1,
    };
}

PUB_IMPL Value* value_pointer_from_reference(CompileUnit* restrict unit, ValueReference reference)
{
    check(is_ref_valid(reference));
    let arena = unit_arena(unit, UNIT_ARENA_VALUE);
    let index = reference.v - 1;
    let byte_offset = index * sizeof(Value);
    let arena_position = arena->position;
    check(sizeof(Arena) + byte_offset + sizeof(Value) <= arena_position);
    let result = (Value*)((u8*)arena + sizeof(Arena) + byte_offset);
    return result;
}

PUB_IMPL Type* new_types(CompileUnit* restrict unit, u32 type_count)
{
    let arena = unit_arena(unit, UNIT_ARENA_TYPE);
    let types = arena_allocate(arena, Type, type_count);
    return types;
}

PUB_IMPL Type* allocate_free_type(CompileUnit* restrict unit)
{
    let type_ref = unit->free_types;
    check(is_ref_valid(type_ref));
    let type = type_pointer_from_reference(unit, type_ref);
    let next = type->next;
    type->next = (TypeReference){};
    unit->free_types = next;
    return type;
}

PUB_IMPL Type* new_type(CompileUnit* restrict unit)
{
    let result = is_ref_valid(unit->free_types) ? allocate_free_type(unit) : new_types(unit, 1);
    return result;
}

PUB_IMPL Value* new_values(CompileUnit* restrict unit, u32 value_count)
{
    let arena = unit_arena(unit, UNIT_ARENA_VALUE);
    let values = arena_allocate(arena, Value, value_count);
    return values;
}

PUB_IMPL Value* new_value(CompileUnit* restrict unit)
{
    return new_values(unit, 1);
}

PUB_IMPL Scope* restrict new_scope(CompileUnit* restrict unit)
{
    let arena = get_default_arena(unit);
    let scope = arena_allocate(arena, Scope, 1);
    return scope;
}

PUB_IMPL u64 align_bit_count(u64 bit_count)
{
    let aligned_bit_count = MAX(next_power_of_two(bit_count), 8);
    check((aligned_bit_count & (aligned_bit_count - 1)) == 0);
    return aligned_bit_count;
}

PUB_IMPL u64 aligned_byte_count_from_bit_count(u64 bit_count)
{
    let aligned_bit_count = align_bit_count(bit_count);
    check(aligned_bit_count % 8 == 0);
    return aligned_bit_count / 8;
}

PUB_IMPL TypeReference get_u1(CompileUnit* restrict unit)
{
    return get_integer_type(unit, 1, 0);
}

PUB_IMPL TypeReference get_u8(CompileUnit* restrict unit)
{
    return get_integer_type(unit, 8, 0);
}

PUB_IMPL TypeReference get_u16(CompileUnit* restrict unit)
{
    return get_integer_type(unit, 16, 0);
}

PUB_IMPL TypeReference get_u32(CompileUnit* restrict unit)
{
    return get_integer_type(unit, 32, 0);
}

PUB_IMPL TypeReference get_u64(CompileUnit* restrict unit)
{
    return get_integer_type(unit, 64, 0);
}

PUB_IMPL Type* get_function_type_from_storage(CompileUnit* restrict unit, Global* global)
{
    let function_storage_ref = global->variable.storage;
    let function_storage = value_pointer_from_reference(unit, function_storage_ref);
    let function_pointer_type_ref = function_storage->type;
    check(is_ref_valid(function_pointer_type_ref));
    let function_pointer_type = type_pointer_from_reference(unit, function_pointer_type_ref);
    check(function_pointer_type->id == TYPE_ID_POINTER);
    let function_type_ref = function_pointer_type->pointer.element_type;
    check(is_ref_valid(function_type_ref));
    let function_type = type_pointer_from_reference(unit, function_type_ref);

    if (function_type->id != TYPE_ID_FUNCTION)
    {
        print(S("'"));
        print(string_from_reference(unit, global->variable.name));
        print(S("': "));
        print(format_integer(get_default_arena(unit), (FormatIntegerOptions){ .value = function_pointer_type_ref.v }, false));
        print(S(" -> "));
        print(format_integer(get_default_arena(unit), (FormatIntegerOptions){ .value = function_type_ref.v }, false));
        print(S("\n"));
    }

    check(function_type->id == TYPE_ID_FUNCTION);

    return function_type;
}

[[noreturn]] PUB_IMPL void todo_internal(CompileUnit* unit, u32 line, str function_name, str file_path)
{
    let arena = get_default_arena(unit);
    str parts[] = {
        S("TODO at: "),
        function_name,
        S(" in "),
        file_path,
        S(":"),
        format_integer(arena, (FormatIntegerOptions) {
            .format = INTEGER_FORMAT_DECIMAL,
            .value = line,
        }, false),
    };
    unit_show(unit, arena_join_string(arena, string_array_to_slice(parts), true));
    fail();
}

LOCAL bool compiler_main(int argc, const char* argv[], char** envp)
{
    os_init();

    return process_command_line(argc, argv, envp);
}

int main(int argc, const char* argv[], char** envp)
{
    bool result = compiler_main(argc, argv, envp);
    int result_code = result ? 0 : 1;
    return result_code;
}
