#pragma once

#include <std/base.h>
#include <std/os.h>

typedef enum CpuArchitecture : u8
{
    CPU_ARCH_X86_64,
    CPU_ARCH_AARCH64,
} CpuArchitecture;

fn String cpu_to_string(CpuArchitecture cpu)
{
    switch (cpu)
    {
    case CPU_ARCH_X86_64:
        return strlit("x86_64");
    case CPU_ARCH_AARCH64:
        return strlit("aarch64");
    }
}

typedef enum OperatingSystem : u8
{
    OPERATING_SYSTEM_LINUX,
    OPERATING_SYSTEM_MAC,
    OPERATING_SYSTEM_WINDOWS,
} OperatingSystem;

fn String operating_system_to_string(OperatingSystem os)
{
    switch (os)
    {
    case OPERATING_SYSTEM_LINUX:
        return strlit("linux");
    case OPERATING_SYSTEM_MAC:
        return strlit("macos");
    case OPERATING_SYSTEM_WINDOWS:
        return strlit("windows");
    }
}

STRUCT(Target)
{
    CpuArchitecture cpu;
    OperatingSystem os;
};

typedef enum CompilerBackend : u8
{
    COMPILER_BACKEND_BB,
    COMPILER_BACKEND_LLVM,
    COMPILER_BACKEND_COUNT,
} CompilerBackend;

fn String compiler_backend_to_one_char_string(CompilerBackend backend)
{
    switch (backend)
    {
    case COMPILER_BACKEND_BB:
        return strlit("b");
    case COMPILER_BACKEND_LLVM:
        return strlit("l");
    case COMPILER_BACKEND_COUNT:
        unreachable();
    }
}

fn String compiler_backend_to_string(CompilerBackend backend)
{
    switch (backend)
    {
    case COMPILER_BACKEND_BB:
        return strlit("bb");
    case COMPILER_BACKEND_LLVM:
        return strlit("llvm");
    case COMPILER_BACKEND_COUNT:
        unreachable();
    }
}

typedef enum BinaryFileType : u8
{
    BINARY_FILE_OBJECT,
    BINARY_FILE_STATIC_LIBRARY,
    BINARY_FILE_DYNAMIC_LIBRARY,
    BINARY_FILE_EXECUTABLE,
} BinaryFileType;

STRUCT(BinaryPathOptions)
{
    String build_directory;
    String name;
    Target target;
    CompilerBackend backend;
    BinaryFileType binary_file_type;
};

fn String binary_path_from_options(Arena* arena, BinaryPathOptions options)
{
    String object_extension;
    switch (options.target.os)
    {
        case OPERATING_SYSTEM_WINDOWS:
            object_extension = strlit(".obj");
            break;
        default:
            object_extension = strlit(".o");
            break;
    }
    String executable_extension;
    switch (options.target.os)
    {
        case OPERATING_SYSTEM_WINDOWS:
            executable_extension = strlit(".exe");
            break;
        default:
            executable_extension = strlit("");
            break;
    }

    String extension;
    switch (options.binary_file_type)
    {
    case BINARY_FILE_OBJECT:
        extension = object_extension;
        break;
    case BINARY_FILE_STATIC_LIBRARY:
        unreachable();
        break;
    case BINARY_FILE_DYNAMIC_LIBRARY:
        unreachable();
        break;
    case BINARY_FILE_EXECUTABLE:
        extension = executable_extension;
        break;
    }

    auto backend_string = compiler_backend_to_string(options.backend);
    auto cpu_string = cpu_to_string(options.target.cpu);
    auto os_string = operating_system_to_string(options.target.os);
    String parts[] = {
        options.build_directory,
        strlit("/"),
        options.name,
        // strlit("_"),
        // cpu_string,
        // strlit("_"),
        // os_string,
        // strlit("_"),
        // backend_string,
        extension,
    };

    auto result = arena_join_string(arena, (Slice(String)) array_to_slice(parts));
    return result;
}

fn CompilerBackend one_char_string_to_compiler_backend(String string)
{
    CompilerBackend result = COMPILER_BACKEND_COUNT;

    for (u32 i = 0; i < COMPILER_BACKEND_COUNT; i += 1)
    {
        auto candidate = (CompilerBackend)i;
        if (s_equal(compiler_backend_to_one_char_string(candidate), string))
        {
            result = candidate;
            break;
        }
    }

    return result;
}

STRUCT(CodegenOptions)
{
    String test_name;
    Target target;
    CompilerBackend backend;
    u8 generate_debug_information;
};

fn Target native_target_get()
{
    Target target = {
#ifdef __x86_64__
        .cpu = CPU_ARCH_X86_64,
#else
        .cpu = CPU_ARCH_AARCH64,
#endif
#if _WIN32
        .os = OPERATING_SYSTEM_WINDOWS,
#elif defined(__APPLE__)
        .os = OPERATING_SYSTEM_MAC,
#elif defined(__linux__)
        .os = OPERATING_SYSTEM_LINUX,
#else
#error "Unknown platform"
#endif
    };

    return target;
}

STRUCT(LinkerArguments)
{
    Target target;
    String out_path;
    Slice(String) objects;
    Slice(String) libraries;
    u8 link_libc:1;
    u8 link_libcpp:1;
};
