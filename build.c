#include <std/base.h>
#include <std/os.h>
#include <std/project.h>

#include <std/base.c>
#include <std/os.c>

typedef enum C_Compiler
{
    C_COMPILER_GCC,
    C_COMPILER_CLANG,
    C_COMPILER_MSVC,
    C_COMPILER_TCC,
    C_COMPILER_COUNT,
} C_Compiler;

global_variable char* c_compiler_names[] = {
    "gcc",
    "clang",
    "cl",
    "tcc",
};

typedef enum CompilerArgumentStyle
{
    COMPILER_ARGUMENT_STYLE_GNU,
    COMPILER_ARGUMENT_STYLE_MSVC,
    COMPILER_ARGUMENT_STYLE_COUNT,
} CompilerArgumentStyle;

global_variable C_Compiler preferred_c_compiler = C_COMPILER_COUNT;
global_variable char** environment_pointer;

typedef enum BuildType
{
    BUILD_TYPE_DEBUG,
    BUILD_TYPE_RELEASE_SAFE,
    BUILD_TYPE_RELEASE_FAST,
    BUILD_TYPE_RELEASE_SMALL,
    BUILD_TYPE_COUNT,
} BuildType;

const char* build_type_strings[BUILD_TYPE_COUNT] = {
    "debug",
    "release_safe",
    "release_fast",
    "release_small",
};

char* optimization_switches[COMPILER_ARGUMENT_STYLE_COUNT][BUILD_TYPE_COUNT] = {
    [COMPILER_ARGUMENT_STYLE_GNU] = {
        [BUILD_TYPE_DEBUG] = "-O0",
        [BUILD_TYPE_RELEASE_SAFE] = "-O2",
        [BUILD_TYPE_RELEASE_FAST] = "-O3",
        [BUILD_TYPE_RELEASE_SMALL] = "-Oz",
    },
    [COMPILER_ARGUMENT_STYLE_MSVC] = {
        [BUILD_TYPE_DEBUG] = "/Od",
        [BUILD_TYPE_RELEASE_SAFE] = "/Ox",
        [BUILD_TYPE_RELEASE_FAST] = "/O2",
        [BUILD_TYPE_RELEASE_SMALL] = "/O1",
    },
};

STRUCT(CompileFlags)
{
    u64 colored_output:1;
    u64 debug:1;
    u64 error_limit:1;
    u64 time_trace:1;
};

STRUCT(CompileOptions)
{
    String source_path;
    String output_path;
    String compiler_path;
    RenderingBackend rendering_backend;
    WindowingBackend windowing_backend;
    BuildType build_type;
    CompileFlags flags;
};

typedef enum CompilerSwitch
{
    COMPILER_SWITCH_DEBUG_INFO,
    COMPILER_SWITCH_COUNT,
} CompilerSwitch;


global_variable char* compiler_switches[COMPILER_ARGUMENT_STYLE_COUNT][COMPILER_SWITCH_COUNT] = {
    [COMPILER_ARGUMENT_STYLE_GNU] = {
        [COMPILER_SWITCH_DEBUG_INFO] = "-g",
    },
    [COMPILER_ARGUMENT_STYLE_MSVC] = {
        [COMPILER_SWITCH_DEBUG_INFO] = "/Zi",
    },
};

fn C_Compiler c_compiler_from_path(String path)
{
    C_Compiler result = C_COMPILER_COUNT;
    let(last_ch_slash, string_last_ch(path, '/'));
    let(start, last_ch_slash);
#if _WIN32
    let(last_ch_backslash, string_last_ch(path, '\\'));
    start = MIN(last_ch_slash, last_ch_backslash);
#endif
    assert(start != STRING_NO_MATCH); // This ensures us the path is not just the executable name
    let(compiler_name, s_get_slice(u8, path, start + 1, path.length));

    for (C_Compiler i = 0; i < C_COMPILER_COUNT; i += 1)
    {
        let(candidate_compiler_name, cstr(c_compiler_names[i]));
        if (string_contains(compiler_name, candidate_compiler_name))
        {
            result = i;
            break;
        }
    }

    return result;
}

fn u8 c_compiler_is_supported_by_os(C_Compiler compiler)
{
#ifdef __linux__
    switch (compiler)
    {
        case C_COMPILER_TCC: case C_COMPILER_GCC: case C_COMPILER_CLANG: return 1;
        case C_COMPILER_MSVC: return 0;
        case C_COMPILER_COUNT: unreachable();
    }
#elif __APPLE__
    switch (compiler)
    {
        case C_COMPILER_TCC: case C_COMPILER_CLANG: return 1;
        case C_COMPILER_MSVC: case C_COMPILER_GCC: return 0;
        case C_COMPILER_COUNT: unreachable();
    }
#elif _WIN32
    switch (compiler)
    {
        case C_COMPILER_MSVC: case C_COMPILER_TCC: case C_COMPILER_CLANG: return 1;
        case C_COMPILER_GCC: return 0;
    }
#endif
    unreachable();
}

fn String c_compiler_to_string(C_Compiler c_compiler)
{
    switch (c_compiler)
    {
        case C_COMPILER_GCC: return strlit("gcc");
        case C_COMPILER_MSVC: return strlit("MSVC");
        case C_COMPILER_CLANG: return strlit("clang");
        case C_COMPILER_TCC: return strlit("tcc");
        default: unreachable();
    }
}

// Returns the absolute path of a C compiler
fn String get_c_compiler_path(Arena* arena, BuildType build_type)
{
    String cc_path = {};
    String cc_env = os_get_environment_variable("CC");
    String path_env = os_get_environment_variable("PATH");
    String extension = {};
#if _WIN32
    extension = strlit(".exe");
#endif
    if (cc_env.pointer)
    {
        cc_path = cc_env;
    }

    if (!cc_path.pointer)
    {
#if _WIN32
        cc_path = strlit("cl");
#elif defined(__APPLE__)
        cc_path = strlit("clang");
#elif defined(__linux__)
        cc_path = strlit("clang");
#else
#error "Operating system not supported"
#endif
    }

    let(no_path_sep, string_first_ch(cc_path, '/') == STRING_NO_MATCH);
#ifdef _WIN32
    no_path_sep = no_path_sep && string_first_ch(cc_path, '\\') == STRING_NO_MATCH;
#endif
    if (no_path_sep)
    {
        cc_path = file_find_in_path(arena, cc_path, path_env, extension);
    }

#ifndef _WIN32
    if (cc_path.pointer)
    {
        u8 buffer[4096];
        let(realpath, os_realpath(cc_path, (String)array_to_slice(buffer)));
        if (!s_equal(realpath, cc_path))
        {
            cc_path.pointer = arena_allocate(arena, u8, realpath.length + 1);
            cc_path.length = realpath.length;
            memcpy(cc_path.pointer, realpath.pointer, realpath.length);
            cc_path.pointer[cc_path.length] = 0;
        }
    }
#endif

#if __APPLE__
    if (s_equal(cc_path, strlit("/usr/bin/cc")))
    {
        cc_path = strlit("/usr/bin/clang");
    }
#endif

    if (preferred_c_compiler != C_COMPILER_COUNT && c_compiler_is_supported_by_os(preferred_c_compiler))
    {
        String find_result = file_find_in_path(arena, c_compiler_to_string(preferred_c_compiler), path_env, extension);
        if (find_result.pointer)
        {
            cc_path = find_result;
        }
    }

    if (!BB_CI)
    {
        if (build_type != BUILD_TYPE_DEBUG)
        {
            return strlit("/usr/lib/llvm18/bin/clang-18");
        }
    }

    return cc_path;
}

fn u8 c_compiler_supports_colored_output(C_Compiler compiler)
{
    // TODO: fix
    switch (compiler)
    {
        case C_COMPILER_GCC: case C_COMPILER_CLANG: return 1;
        case C_COMPILER_TCC: case C_COMPILER_MSVC: return 0;
        default: unreachable();
    }
}

fn char* c_compiler_get_error_limit_switch(C_Compiler compiler)
{
    // TODO: fix
    switch (compiler)
    {
        case C_COMPILER_CLANG: return "-ferror-limit=1";
        case C_COMPILER_GCC: return "-fmax-errors=1";
        case C_COMPILER_MSVC: case C_COMPILER_TCC: return 0;
        default: unreachable();
    }
}

fn char* c_compiler_get_highest_c_standard_flag(C_Compiler compiler)
{
    switch (compiler)
    {
        case C_COMPILER_CLANG: case C_COMPILER_GCC: return "-std=gnu2x";
        case C_COMPILER_MSVC: return "/std:clatest";
        case C_COMPILER_TCC: return "-std=gnu2x"; // TODO: does it do anything in TCC?
        default: unreachable();
    }
}

fn RenderingBackend rendering_backend_parse_env(String env)
{
    unused(env);
    todo();
}

fn RenderingBackend rendering_backend_pick()
{
    RenderingBackend rendering_backend = RENDERING_BACKEND_COUNT;
#if BB_CI
    rendering_backend = RENDERING_BACKEND_NONE;
#else
    char* env = getenv("BB_RENDERING_BACKEND");
    if (env)
    {
        rendering_backend = rendering_backend_parse_env(cstr(env));
    }

    if (!rendering_backend_is_valid(rendering_backend))
    {
#ifdef __linux__
        rendering_backend = RENDERING_BACKEND_VULKAN;
#elif defined(__APPLE__)
        rendering_backend = RENDERING_BACKEND_METAL;
#elif _WIN32
        rendering_backend = RENDERING_BACKEND_VULKAN;
#endif
    }
#endif

    return rendering_backend;
}

fn WindowingBackend windowing_backend_parse_env(String env)
{
    unused(env);
    todo();
}

fn WindowingBackend windowing_backend_pick()
{
    WindowingBackend windowing_backend = WINDOWING_BACKEND_COUNT;
#if BB_CI
    windowing_backend = WINDOWING_BACKEND_NONE;
#else
    // Only done for Linux because it is the only operating system in which two windowing backends officially coexist
#ifdef __linux__
    char* env = getenv("BB_WINDOWING_BACKEND");
    if (env)
    {
        windowing_backend = windowing_backend_parse_env(cstr(env));
    }
#endif

    if (!windowing_backend_is_valid(windowing_backend))
    {
#ifdef __linux__
        // Prefer X11 over Wayland because:
        // 1) It works both on Wayland and on X11 desktops
        // 2) It works with debugging tools like RenderDoc
        windowing_backend = WINDOWING_BACKEND_X11;
#elif _WIN32
        windowing_backend = WINDOWING_BACKEND_WIN32;
#elif __APPLE__
        windowing_backend = WINDOWING_BACKEND_COCOA;
#endif
    }
#endif

    return windowing_backend;
}

fn u8 c_compiler_supports_time_trace(C_Compiler compiler)
{
    switch (compiler)
    {
        case C_COMPILER_CLANG: return 1;
        default: return 0;
        case C_COMPILER_COUNT: unreachable();
    }
}

fn BuildType build_type_pick()
{
    String build_type_string = strlit(BB_BUILD_TYPE);
    BuildType build_type;

    for (build_type = 0; build_type < BUILD_TYPE_COUNT; build_type += 1)
    {
        if (s_equal(build_type_string, cstr(build_type_strings[build_type])))
        {
            break;
        }
    }

    return build_type;
}

fn void compile_program(Arena* arena, CompileOptions options)
{
    if (!options.compiler_path.pointer)
    {
        char* cc_env = getenv("CC");
        if (options.flags.debug)
        {
            print("Could not find a valid compiler for CC: \"{cstr}\"\n", cc_env ? cc_env : "");
            print("PATH: {cstr}\n", getenv("PATH"));
        }

        failed_execution();
    }

    if (options.flags.debug)
    {
        print("C compiler path: {s}\n", options.compiler_path);
    }

    C_Compiler c_compiler = c_compiler_from_path(options.compiler_path);
    if (c_compiler != C_COMPILER_COUNT)
    {
        String compiler_name = c_compiler_to_string(c_compiler);
        if (options.flags.debug)
        {
            print("Identified compiler as {s}\n", compiler_name);
        }
    }
    else
    {
        print("Unrecognized C compiler: {s}\n", options.compiler_path);
        os_exit(1);
    }
    char* args[4096];
    u64 arg_i = 0;
#define add_arg(arg) args[arg_i++] = (arg)
    add_arg(string_to_c(options.compiler_path));

    if (c_compiler == C_COMPILER_MSVC)
    {
        add_arg("/nologo");
    }

    u8 llvm_mca = 0;
    if (llvm_mca)
    {
        add_arg("-S");
        add_arg("-masm=intel");
    }

#if __APPLE__
    add_arg("-x");
    add_arg("objective-c");
#endif

    add_arg(string_to_c(options.source_path));

    switch (c_compiler)
    {
        case C_COMPILER_MSVC:
            {
                String strings[] = {
                    strlit("/Fe"),
                    options.output_path,
                };
                String arg = arena_join_string(arena, (Slice(String))array_to_slice(strings));
                add_arg(string_to_c(arg));

                add_arg("/Fo" BUILD_DIR "\\");
                add_arg("/Fd" BUILD_DIR "\\");
            } break;
        case C_COMPILER_GCC:
            {
            } break;
        case C_COMPILER_CLANG:
            {
                // add_arg("-working-directory");
                // add_arg(BUILD_DIR);
                // add_arg("-save-temps");
            } break;
        default: break;
    }

    if (c_compiler != C_COMPILER_MSVC)
    {
        add_arg("-o");
        add_arg(string_to_c(options.output_path));
    }

#ifdef __linux__
    add_arg("-fuse-ld=mold");
#endif

    add_arg("-Ibootstrap");
    add_arg("-Idependencies/stb");
    add_arg("-I" BUILD_DIR); // Include the build dir for generated files

    char* c_include_path = getenv("C_INCLUDE_PATH");
    if (c_include_path)
    {
        String c_include_path_string = cstr(c_include_path);

        u64 previous_i = 0;
        for (u64 i = 0; i < c_include_path_string.length; i += 1)
        {
            u8 ch = c_include_path_string.pointer[i];
            if (ch == ':')
            {
                todo();
            }
        }

        String strings[] = {
            strlit("-I"),
            s_get_slice(u8, c_include_path_string, previous_i, c_include_path_string.length),
        };
        String arg = arena_join_string(arena, (Slice(String))array_to_slice(strings));
        add_arg(string_to_c(arg));
    }

    let(debug_info, options.build_type != BUILD_TYPE_RELEASE_SMALL && !llvm_mca);
    if (debug_info)
    {
        add_arg(compiler_switches[c_compiler == C_COMPILER_MSVC][COMPILER_SWITCH_DEBUG_INFO]);
    }

    if (c_compiler != C_COMPILER_TCC)
    {
        add_arg(optimization_switches[c_compiler == C_COMPILER_MSVC][options.build_type]);
    }

    switch (options.build_type)
    {
        case BUILD_TYPE_COUNT: unreachable();
        case BUILD_TYPE_DEBUG:
        case BUILD_TYPE_RELEASE_SAFE:
        {
            add_arg("-DBB_DEBUG=1");
            add_arg("-D_DEBUG=1");
        } break;
        case BUILD_TYPE_RELEASE_FAST:
        case BUILD_TYPE_RELEASE_SMALL:
        {
            add_arg("-DBB_DEBUG=0");
            add_arg("-DNDEBUG=1");
            if (c_compiler != C_COMPILER_MSVC)
            {
                add_arg("-fno-stack-protector");
            }
        } break;
    }

    if (BB_CI)
    {
        add_arg("-DBB_CI=1");
    }
    else
    {
        add_arg("-DBB_CI=0");
    }

    // TODO: careful. If handing binaries built by CI to people, we need to be specially careful about this
    if (c_compiler == C_COMPILER_MSVC)
    {
        add_arg("/arch:AVX512");
    }
    else
    {
        add_arg("-march=native");
    }

    // Immutable options
    switch (c_compiler)
    {
        case C_COMPILER_MSVC:
            {
                add_arg("/Wall");
#if BB_ERROR_ON_WARNINGS
                add_arg("/WX");
#endif
                add_arg("/wd4255");
                add_arg("/J");
            } break;
        default:
            {
                add_arg("-pedantic");
                add_arg("-Wall");
                add_arg("-Wextra");
                add_arg("-Wpedantic");
                add_arg("-Wno-unused-function");
                add_arg("-Wno-nested-anon-types");
                add_arg("-Wno-keyword-macro");
                add_arg("-Wno-gnu-auto-type");
                add_arg("-Wno-gnu-binary-literal");
#ifndef __APPLE__
                add_arg("-Wno-auto-decl-extensions");
#endif
                add_arg("-Wno-gnu-empty-initializer");
                add_arg("-Wno-fixed-enum-extension");
                add_arg("-Wno-overlength-strings");
                add_arg("-Wno-gnu-zero-variadic-macro-arguments");
#if BB_ERROR_ON_WARNINGS
                add_arg("-Werror");
#endif

                add_arg("-fno-signed-char");
                add_arg("-fno-strict-aliasing");
                add_arg("-fwrapv");
            } break;
    }

    if (options.flags.colored_output && c_compiler_supports_colored_output(c_compiler))
    {
        add_arg("-fdiagnostics-color=auto");
    }

    if (options.flags.error_limit)
    {
        char* error_limit = c_compiler_get_error_limit_switch(c_compiler);
        if (error_limit)
        {
            add_arg(error_limit);
        }
    }

    if (options.flags.time_trace && c_compiler_supports_time_trace(c_compiler))
    {
        add_arg("-ftime-trace");
    }

    if (c_compiler == C_COMPILER_MSVC)
    {
        add_arg("/diagnostics:caret");
    }
    else
    {
        add_arg("-fdiagnostics-show-option");
    }

    add_arg(c_compiler_get_highest_c_standard_flag(c_compiler));

    switch (options.windowing_backend)
    {
        case WINDOWING_BACKEND_NONE:
            {
                add_arg("-DBB_WINDOWING_BACKEND_NONE=1");
            } break;
        case WINDOWING_BACKEND_WIN32:
            {
                add_arg("-DBB_WINDOWING_BACKEND_WIN32=1");
            } break;
        case WINDOWING_BACKEND_COCOA:
            {
                add_arg("-DBB_WINDOWING_BACKEND_COCOA=1");
            } break;
        case WINDOWING_BACKEND_X11:
            {
                add_arg("-DBB_WINDOWING_BACKEND_X11=1");
            } break;
        case WINDOWING_BACKEND_WAYLAND:
            {
                add_arg("-DBB_WINDOWING_BACKEND_WAYLAND=1");
            } break;
        case WINDOWING_BACKEND_COUNT: unreachable();
    }

    switch (options.rendering_backend)
    {
        case RENDERING_BACKEND_NONE:
            {
                add_arg("-DBB_RENDERING_BACKEND_NONE=1");
            } break;
        case RENDERING_BACKEND_METAL:
            {
                add_arg("-DBB_RENDERING_BACKEND_METAL=1");
            } break;
        case RENDERING_BACKEND_DIRECTX12:
            {
                add_arg("-DBB_RENDERING_BACKEND_DIRECTX12=1");
            } break;
        case RENDERING_BACKEND_VULKAN:
            {
                add_arg("-DBB_RENDERING_BACKEND_VULKAN=1");
#if _WIN32
                char* vk_sdk_path = getenv("VK_SDK_PATH");
                if (vk_sdk_path)
                {
                    if (c_compiler == C_COMPILER_MSVC)
                    {
                        String strings[] = {
                            strlit("-I"),
                            cstr(vk_sdk_path),
                            strlit("\\Include"),
                        };
                        String arg = arena_join_string(arena, (Slice(String))array_to_slice(strings));
                        add_arg(string_to_c(arg));
                    }
                    else
                    {
                        todo();
                    }
                }
                else
                {
                    print("VK_SDK_PATH environment variable not found\n");
                }
#endif
            } break;
        case RENDERING_BACKEND_COUNT: unreachable();
    }

#ifndef _WIN32
    add_arg("-lm");

    String path_env = cstr(getenv("PATH"));
    String llvm_config_path = executable_find_in_path(arena, strlit("llvm-config"), path_env);
    u8 buffer[16*1024];
    u32 length = 0;
    char* llvm_config_c = string_to_c(llvm_config_path);
    {
        char* arguments[] = {
            llvm_config_c,
            "--components",
            0,
        };
        RunCommandOptions run_options = {
            .stdout_stream = {
                .buffer = buffer,
                .length = &length,
                .capacity = sizeof(buffer),
                .policy = CHILD_PROCESS_STREAM_PIPE,
            },
            .debug = options.flags.debug,
        };
        RunCommandResult result = run_command(arena, (CStringSlice)array_to_slice(arguments), environment_pointer, run_options);
        let(success, result.termination_kind == PROCESS_TERMINATION_EXIT && result.termination_code == 0); 
        if (!success)
        {
            os_exit(1);
        }
    }

    {
        char* argv_buffer[4096];
        argv_buffer[0] = llvm_config_c;
        argv_buffer[1] = "--libs";
        u32 local_arg_i = 2;

        String llvm_components = { .pointer = buffer, .length = length };
        u32 i = 0;
        while (i < length)
        {
            String slice = s_get_slice(u8, llvm_components, i, llvm_components.length);
            u64 space_index = string_first_ch(slice, ' ');
            u8 there_is_space = space_index != STRING_NO_MATCH;
            u64 argument_length = unlikely(there_is_space) ? space_index : slice.length;

            String argument_slice = s_get_slice(u8, slice, 0, argument_length - !there_is_space);
            argv_buffer[local_arg_i] = string_to_c(arena_duplicate_string(arena, argument_slice));
            local_arg_i += 1;

            i += argument_length + there_is_space;
        }

        argv_buffer[local_arg_i] = 0;
        local_arg_i += 1;

        length = 0;

        RunCommandOptions run_options = {
            .stdout_stream = {
                .buffer = buffer,
                .length = &length,
                .capacity = sizeof(buffer),
                .policy = CHILD_PROCESS_STREAM_PIPE,
            },
            .debug = options.flags.debug,
        };
        CStringSlice arguments = { .pointer = argv_buffer, .length = local_arg_i };
        RunCommandResult result = run_command(arena, arguments, environment_pointer, run_options);
        let(success, result.termination_kind == PROCESS_TERMINATION_EXIT && result.termination_code == 0); 
        if (!success)
        {
            os_exit(1);
        }

        i = 0;

        String llvm_libraries = { .pointer = buffer, .length = length };
        while (i < length)
        {
            String slice = s_get_slice(u8, llvm_libraries, i, llvm_libraries.length);
            u64 space_index = string_first_ch(slice, ' ');
            u8 there_is_space = space_index != STRING_NO_MATCH;
            u64 argument_length = unlikely(there_is_space) ? space_index : slice.length;

            String argument_slice = s_get_slice(u8, slice, 0, argument_length - !there_is_space);
            add_arg(string_to_c(arena_duplicate_string(arena, argument_slice)));

            i += argument_length + there_is_space;
        }
    }
#endif

    switch (options.windowing_backend)
    {
        case WINDOWING_BACKEND_NONE:
            {
            } break;
        case WINDOWING_BACKEND_WIN32:
            {
            } break;
        case WINDOWING_BACKEND_COCOA:
            {
                add_arg("-framework");
                add_arg("AppKit");
            } break;
        case WINDOWING_BACKEND_X11:
            {
                add_arg("-lxcb");
            } break;
        case WINDOWING_BACKEND_WAYLAND:
            {
            } break;
        case WINDOWING_BACKEND_COUNT: unreachable();
    }

    switch (options.rendering_backend)
    {
        case RENDERING_BACKEND_NONE:
            {
            } break;
        case RENDERING_BACKEND_METAL:
            {
                add_arg("-framework");
                add_arg("Metal");
                add_arg("-framework");
                add_arg("QuartzCore");
            } break;
        case RENDERING_BACKEND_DIRECTX12:
            {
            } break;
        case RENDERING_BACKEND_VULKAN:
            {
#if __APPLE__
                add_arg("-framework");
                add_arg("QuartzCore");
#endif
            } break;
        case RENDERING_BACKEND_COUNT: unreachable();
    }

    add_arg(0);
    CStringSlice arguments = { .pointer = args, .length = arg_i };
    RunCommandOptions run_options = {
        .debug = options.flags.debug,
    };
    RunCommandResult result = run_command(arena, arguments, environment_pointer, run_options);
    let(success, result.termination_kind == PROCESS_TERMINATION_EXIT && result.termination_code == 0); 
    if (!success)
    {
        os_exit(1);
    }
}

STRUCT(Load)
{
    u64 mask;
    u8 index;
    u8 size;
};
decl_vb(Load);
declare_slice(Load);

STRUCT(Combine)
{
    Slice(Load) loads;
    u64 size;
};

STRUCT(Merge)
{
    Load values[2];
    u8 is_valid[2];
};

typedef enum ProgramId
{
    PROGRAM_MERGE,
    PROGRAM_COMBINE,
    PROGRAM_LOAD,
} ProgramId;

STRUCT(Program)
{
    union
    {
        Combine combine;
        Load load;
        Merge merge;
    };
    ProgramId id;
};

STRUCT(Lookup)
{
    Slice(s32) indices;
    SliceP(u8) words;
};

declare_slice(SliceP(u8));
declare_slice(SliceP(void));

fn u64 pext(u64 w, u64 m)
{
    u64 result = 0;
    u64 bit = 1;

    while (w != 0)
    {
        if ((m & 1) == 1)
        {
            if ((w & 1) == 1)
            {
                result |= bit;
            }

            bit <<= 1;
        }

        w >>= 1;
        m >>= 1;
    }

    return result;
}

fn void n_word_mask(SliceP(u8) words, u8* mask, u8 length)
{
    for (u8 i = 0; i < length; i += 1)
    {
        mask[i] = 0xff;
    }

    for (u8 byte = 0; byte < length; byte += 1)
    {
        for (u8 bit = 0; bit < 8; bit += 1)
        {
            u8 old = mask[byte];
            mask[byte] &= ~(u8)(1 << bit);

            u8 map[16*16][16] = {};
            u32 map_item_count = 0;
            u8 candidate[16] = {};

            for (u64 word_index = 0; word_index < words.length; word_index += 1)
            {
                let(word, words.pointer[word_index]);
                for (u8 mask_index = 0; mask_index < length; mask_index += 1)
                {
                    candidate[mask_index] = word[mask_index] & mask[mask_index];
                }

                u8 map_index;
                for (map_index = 0; map_index < map_item_count; map_index += 1)
                {
                    if (memcmp(map[map_index], candidate, length) == 0)
                    {
                        break;
                    }
                }

                if (map_index != map_item_count)
                {
                    mask[byte] = old;
                    break;
                }

                memcpy(map[map_item_count], candidate, length);
                map_item_count += 1;
            }
        }
    }
}

fn u64 program_lookup_size(Program program)
{
    u64 n = 0;

    switch (program.id)
    {
        case PROGRAM_COMBINE:
            {
                for (u64 i = 0; i < program.combine.loads.length; i += 1)
                {
                    n += __builtin_popcountll(program.combine.loads.pointer[i].mask);
                }
            } break;
        case PROGRAM_LOAD:
            {
                n = __builtin_popcountll(program.load.mask);
            } break;
        case PROGRAM_MERGE: todo();
    }

    return n;
}

fn u64 load_load(Load load, u8* word)
{
    u64 result;

    switch (load.size)
    {
        case 1: result = word[load.index]; break;
        case 2: result = *(u16*)&word[load.index]; break;
        case 4: result = *(u32*)&word[load.index]; break;
        case 8: result = *(u64*)&word[load.index]; break;
        default: unreachable();
    }

    return result;
}

fn u64 program_evaluate(Program program, u8* word)
{
    u64 result;

    switch (program.id)
    {
        case PROGRAM_COMBINE:
            {
                u64 q = 0;
                u64 m = 0;
                u64 shift = 0;

                for (u64 i = 0; i < program.combine.loads.length; i += 1)
                {
                    Load load = program.combine.loads.pointer[i];
                    let(qi, load_load(load, word));
                    let(mi, load.mask);

                    q |= qi << shift;
                    m |= mi << shift;

                    shift += 8 * load.size;
                }

                result = pext(q, m);
            } break;
        case PROGRAM_LOAD:
            {
                let(q, load_load(program.load, word));
                result = pext(q, program.load.mask);
            } break;
        case PROGRAM_MERGE: todo();
    }

    return result;
}

fn Slice(s32) pdep_lookup(Arena* arena, Program program, SliceP(u8) words)
{
    let(length, 1 << program_lookup_size(program));
    let(result, arena_allocate(arena, s32, length));
    for (u64 i = 0; i < length; i += 1)
    {
        result[i] = -1;
    }

    for (u64 i = 0; i < words.length; i += 1)
    {
        let(value, program_evaluate(program, words.pointer[i]));
        result[value] = i;
    }

    return (Slice(s32)) { .pointer = result, .length = length };
}

fn u8 load_trim(Load in, Load* out)
{
    u8 result = 0;
    Load l;
    switch (in.size)
    {
        case 8:
            {
                todo();
            } break;
        case 4:
            {
                if ((in.mask & 0xffff) == 0)
                {
                    l = (Load) {
                        .index = in.index + 4,
                        .size = 4,
                        .mask = in.mask >> 32,
                    };
                }
            } break;
        case 2:
            {
                if ((in.mask & 0xff) == 0)
                {
                    todo();
                }
            } break;
    }

    if (result)
    {
        *out = l;
    }

    return result;
}

fn u8 can_merge(Load* load, u8* is_valid)
{
    if (!is_valid[0] || !is_valid[1])
    {
        return 0;
    }

    if ((load[0].mask & load[1].mask) == 0)
    {
        return 1;
    }

    return 0;
}

fn u8 new_merge(Load* loads, u8* is_valid, Merge* out)
{
    u8 result = 0;

    if (can_merge(loads, is_valid))
    {
        result = 1;
        *out = (Merge)
        {
            .values = { loads[0], loads[1] },
            .is_valid = { is_valid[0], is_valid[1] },
        };
    }

    return result;
}

fn Program compile_mask(u8* mask, u8 mask_length)
{
    Program result = {};
    VirtualBuffer(Load) loads = {};
    const u8 load_sizes[] = {8, 4, 2, 1};

    while (1)
    {
        u32 active = 0;
        for (u8 i = 0; i < mask_length; i += 1)
        {
            active += mask[i] != 0;
        }

        if (active == 0)
        {
            break;
        }

        if (active == 1)
        {
            for (u8 i = 0; i < mask_length; i += 1)
            {
                u8 mask_byte = mask[i];
                if (mask_byte != 0)
                {
                    *vb_add(&loads, 1) = (Load) {
                        .index = i,
                        .size = 1,
                        .mask = mask_byte,
                    };
                    break;
                }
            }

            break;
        }

        for (u8 size_index = 0; size_index < array_length(load_sizes); size_index += 1)
        {
            u8 size = load_sizes[size_index];
            if (size > mask_length)
            {
                continue;
            }

            u8 best_count = 0;
            u8 best_index = 0;

            for (u8 i = 0; i < mask_length - size + 1; i += 1)
            {
                u8 k = 0;
                for (u8 mask_i = 0; mask_i < size; mask_i += 1)
                {
                    k += mask[mask_i + i] != 0;
                }

                if (k > best_count)
                {
                    best_count = k;
                    best_index = i;
                }
            }

            if (best_count > 0)
            {
                Load load = {
                    .index = best_index,
                    .size = size,
                };

                for (u8 i = 0; i < size; i += 1)
                {
                    load.mask |= (u64)mask[best_index + i] << (i * 8);
                }

                *vb_add(&loads, 1) = load;

                for (u8 i = 0; i < size; i += 1)
                {
                    mask[best_index + i] = 0;
                }

                break;
            }
        }
    }

    if (loads.length == 1)
    {
        while (1)
        {
            Load l;
            if (!load_trim(loads.pointer[0], &l))
            {
                break;
            }

            loads.pointer[0] = l;
        }

        return (Program) {
            .load = loads.pointer[0],
            .id = PROGRAM_LOAD,
        };
    }
    else if (loads.length == 2)
    {
        let(first, loads.pointer[0]);
        let(second, loads.pointer[1]);

        let(trimmed, first);
        u8 trimmed_is_valid = 1;
        Merge merge_memory;
        Load load_memory;
        Merge merge = {};
        u8 merge_is_valid = 0;

        while (trimmed_is_valid)
        {
            Load merge_loads[2] = { trimmed, second };
            u8 is_valid[2] = { 1, 1 };
            Merge merge_candidate = {};
            if (new_merge(merge_loads, is_valid, &merge_candidate))
            {
                merge = merge_candidate;
            }

            trimmed_is_valid = load_trim(trimmed, &load_memory);
            if (trimmed_is_valid)
            {
                trimmed = load_memory;
            }
        }

        if (merge_is_valid)
        {
            todo();
        }
    }
    
    u64 total = 0;
    for (u64 i = 0; i < loads.length; i += 1)
    {
        total += loads.pointer[i].size;
    }

    u64 size = total < 4 ? 4 : 8;
    result = (Program) {
        .combine = {
            .loads = { .pointer = loads.pointer, .length = loads.length },
            .size = size,
        },
        .id = PROGRAM_COMBINE,
    };
    return result;
}

typedef enum TypeKind
{
    TYPE_KIND_U16,
} TypeKind;

STRUCT(PerfectHashArguments)
{
    VirtualBuffer(u8)* file_h;
    VirtualBuffer(u8)* file_c;
    Slice_SliceP_u8 words_by_length;
    u8* mask;
    Lookup* lookups;
    Program* programs;
    Arena* arena;
    String kind;
    void** values_by_length;
    TypeKind value_type;
};

fn void vb_indent(VirtualBuffer(u8)* buffer, u32 indentation_level)
{
    if (likely(indentation_level > 0))
    {
        vb_copy_byte_repeatedly(buffer, ' ', 4 * indentation_level);
    }
}

fn String type_from_size(u8 size)
{
    String type;
    switch (size)
    {
        case 8: type = strlit("u64"); break;
        case 4: type = strlit("u32"); break;
        case 2: type = strlit("u16"); break;
        case 1: type = strlit("u8"); break;
        default: unreachable();
    }

    return type;
}

fn void load_write(Load load, VirtualBuffer(u8)* buffer, u32 load_name_index, u32 indentation_level, u32 length)
{
    String load_type = type_from_size(load.size);

    vb_indent(buffer, indentation_level);
    vb_format(buffer, "{s} v{u32}_{u32};\n", load_type, load_name_index, length);

    vb_indent(buffer, indentation_level);
    vb_format(buffer, "memcpy(&v{u32}_{u32}, &string_pointer[{u32}], {u32});\n", load_name_index, length, load.index, load.size);
}

fn void program_write(VirtualBuffer(u8)* buffer, Program program, u32 indentation_level, u32 length)
{
    switch (program.id)
    {
        case PROGRAM_LOAD:
            {
                // Write the load
                Load load = program.load;
                u32 load_name_index = 0;

                load_write(load, buffer, load_name_index, indentation_level, length);

                // Write result
                vb_indent(buffer, indentation_level);
                vb_format(buffer, "u64 index_{u32} = _pext_u64(v{u32}_{u32}, 0x{u64:x});\n", length, load_name_index, length, load.mask);
            } break;
        case PROGRAM_COMBINE:
            {
                Combine combine = program.combine;
                String combine_type_string = type_from_size(combine.size);
                vb_indent(buffer, indentation_level);
                vb_format(buffer, "{s} v_{u32} = 0;\n", combine_type_string, length);
                
                u64 shift = 0;
                u64 mask = 0;

                for (u64 i = 0; i < combine.loads.length; i += 1)
                {
                    Load load = combine.loads.pointer[i];
                    mask |= load.mask << shift;

                    load_write(load, buffer, (u32)i, indentation_level, length);

                    vb_indent(buffer, indentation_level);
                    vb_format(buffer, "v_{u32} |= ({s})(v{u64}_{u32}) << {u64};\n", length, combine_type_string, i, length, shift);

                    shift += 8 * load.size;
                }

                // Write result
                vb_indent(buffer, indentation_level);
                vb_format(buffer, "u64 index_{u32} = _pext_u64(v_{u32}, 0x{u64:x});\n", length, length, mask);
            } break;
        case PROGRAM_MERGE:
            {
                todo();
            } break;
    }

    // vb_indent(buffer, indentation_level);
    // vb_format(buffer, "const char* word_{u32} = words_{u32}[index_{u32}];\n", length, length, length);
    // vb_indent(buffer, indentation_level);
    // vb_format(buffer, "let(value_{u32}, values_{u32}[index_{u32}]);\n", length, length, length);
}

fn void perfect_hash_generate(PerfectHashArguments arguments)
{
    VirtualBuffer(u8)* h = arguments.file_h;
    VirtualBuffer(u8)* c = arguments.file_c;

    String type_string;
    switch (arguments.value_type)
    {
        case TYPE_KIND_U16: type_string = strlit("u16"); break;
    }

    u64 word_character_count;
    u64 value_count;

    {
        u64 word_character_offset = 0;
        u64 value_offset = 0;
        for (u64 length = 0; length < arguments.words_by_length.length; length += 1)
        {
            SliceP(u8) words = arguments.words_by_length.pointer[length];
            n_word_mask(words, arguments.mask, length);
            Program program = compile_mask(arguments.mask, length);
            arguments.programs[length] = program;
            arguments.lookups[length].indices = pdep_lookup(arguments.arena, program, words);
            arguments.lookups[length].words = words;
            value_offset += arguments.lookups[length].indices.length;
            word_character_offset += arguments.lookups[length].indices.length * length;
        }

        word_character_count = word_character_offset;
        value_count = value_offset;
    }

    u32 indentation_level = 0;
    vb_indent(h, indentation_level);
    vb_format(h, "global_variable const {s} {s}_value_lut[] = {\n", type_string, arguments.kind);

    indentation_level += 1;

    for (u64 length = 0; length < arguments.words_by_length.length; length += 1)
    {
        SliceP(u8) words = arguments.words_by_length.pointer[length];
        Lookup lookup = arguments.lookups[length];
        let(generic_values_by_length, arguments.values_by_length[length]);

        vb_indent(h, indentation_level);
        vb_format(h, "// Values [{u64}]\n", length);

        if (words.length > 0)
        {
            for (u64 i = 0; i < lookup.indices.length; i += 1)
            {
                let(index, lookup.indices.pointer[i]);
                vb_indent(h, indentation_level);

                if (index == -1)
                {
                    switch (arguments.value_type)
                    {
                        case TYPE_KIND_U16:
                            {
                                vb_copy_string(h, strlit("0xffff,\n"));
                            } break;
                    }
                }
                else
                {
                    switch (arguments.value_type)
                    {
                        case TYPE_KIND_U16:
                            {
                                let(value, ((u16*)generic_values_by_length)[index]);
                                String word = { .pointer = words.pointer[index], .length = length };
                                vb_format(h, "0x{u32:x,w=4}, // {s}\n", value, word);
                            } break;
                    }
                }
            }
        }
        else
        {
            vb_indent(h, indentation_level);
            switch (arguments.value_type)
            {
                case TYPE_KIND_U16:
                    {
                        vb_copy_string(h, strlit("0xffff,\n"));
                    } break;
            }
        }
    }

    indentation_level -= 1;

    vb_indent(h, indentation_level);
    vb_copy_string(h, strlit("};\n"));

    vb_indent(h, indentation_level);
    vb_format(h, "static_assert(array_length({s}_value_lut) == {u64});\n", arguments.kind, value_count);

    assert(is_power_of_two_u64(arguments.words_by_length.length));
    u64 epi = 512 / arguments.words_by_length.length;

    String upper_names_by_batch_flag[] = { strlit("Single"), strlit("Batch") };
    String lower_names_by_batch_flag[] = { strlit("single"), strlit("batch") };

    switch (arguments.value_type)
    {
        case TYPE_KIND_U16:
            {
                vb_format(h, "STRUCT(PextLookup{s}Result_{s})\n{\n    __m512i v[2];\n};\n", upper_names_by_batch_flag[1], arguments.kind);
            } break;
    }

    for (u8 is_batch = 0; is_batch < 2; is_batch += 1)
    {
        u64 signature_length;
        u8 result_type_buffer[256];
        String result_type_string;
        if (is_batch)
        {
            result_type_string = format_string((String)array_to_slice(result_type_buffer), "PextLookupBatchResult_{s}", arguments.kind);
        }
        else
        {
            result_type_string = type_string;
        }

        if (is_batch)
        {
            signature_length = vb_format(h, "fn {s} pext_lookup_{s}_{s}(const u8* const restrict string_base, const u32* const restrict string_offsets, const u32* const restrict string_lengths)", result_type_string, arguments.kind, lower_names_by_batch_flag[is_batch], type_string);
        }
        else
        {
            signature_length =  vb_format(h, "fn {s} pext_lookup_{s}_{s}(const u8* const restrict string_pointer, u8 string_length)", result_type_string, arguments.kind, lower_names_by_batch_flag[is_batch], type_string);
        }

        vb_copy_string(c, (String) { h->pointer + h->length - signature_length, .length = signature_length, });

        vb_copy_string(h, strlit(";\n"));

        vb_copy_string(c, strlit("\n{\n"));
        u32 indentation_level = 1;

        vb_indent(c, indentation_level);
        if (is_batch)
        {
            vb_format(c, "PextLookupBatchResult_{s} result = {};\n", arguments.kind);
        }

        assert(is_power_of_two_u64(arguments.words_by_length.length));
        {
            vb_indent(c, indentation_level);
            vb_format(c, "__m512i lengths = _mm512_set_epi{u64}(", epi);
            for (s64 length = arguments.words_by_length.length - 1; length >= 0; length -= 1)
            {
                vb_format(c, "{u64}, ", length);
            }

            c->length -= 2;

            vb_copy_string(c, strlit(");\n"));

            {
                vb_indent(c, indentation_level);
                assert(is_power_of_two_u64(arguments.words_by_length.length));
                vb_format(c, "__m512i raw_value_offsets = _mm512_set_epi{u64}(", epi);
                let(value_offset, value_count);
                for (s64 length = arguments.words_by_length.length - 1; length >= 0; length -= 1)
                {
                    value_offset -= arguments.lookups[length].indices.length;
                    vb_format(c, "{u64}, ", value_offset);
                }
                c->length -= 2;
                vb_copy_string(c, strlit(");\n"));
            }

#if 0
            // vb_indent(c, indentation_level);
            // vb_copy_string(c, strlit("global_variable const char words[] = {\n"));
            // 
            // indentation_level += 1;
            //
            // for (u64 length = 0; length < arguments.words_by_length.length; length += 1)
            // {
            //     Lookup lookup = arguments.lookups[length];
            //     SliceP(u8) words = arguments.words_by_length.pointer[length];
            //
            //     vb_indent(c, indentation_level);
            //     vb_format(c, "// Words [{u64}]\n", length);
            //
            //     if (words.length > 0)
            //     {
            //         for (u64 i = 0; i < lookup.indices.length; i += 1)
            //         {
            //             let(index, lookup.indices.pointer[i]);
            //
            //             vb_indent(c, indentation_level);
            //
            //             if (index == -1)
            //             {
            //                 *vb_add(c, 1) = '\"';
            //                 for (u64 i = 0; i < length; i += 1)
            //                 {
            //                     vb_copy_string(c, strlit("\\x00"));
            //                 }
            //
            //                 *vb_add(c, 1) = '\"';
            //                 *vb_add(c, 1) = '\n';
            //             }
            //             else
            //             {
            //                 String word = { .pointer = words.pointer[index], .length = length };
            //                 *vb_add(c, 1) = '\"';
            //                 vb_copy_string(c, word);
            //                 *vb_add(c, 1) = '\"';
            //                 *vb_add(c, 1) = '\n';
            //             }
            //         }
            //     }
            //     else
            //     {
            //         vb_indent(c, indentation_level);
            //         *vb_add(c, 1) = '\"';
            //         for (u64 i = 0; i < length; i += 1)
            //         {
            //             vb_copy_string(c, strlit("\\x00"));
            //         }
            //
            //         *vb_add(c, 1) = '\"';
            //         *vb_add(c, 1) = '\n';
            //     }
            // }
            //
            // indentation_level -= 1;
            //
            // vb_indent(c, indentation_level);
            // vb_copy_string(c, strlit("};\n"));
            //
            // vb_indent(c, indentation_level);
            // vb_format(c, "static_assert(array_length(words) == {u64} + 1);\n", word_character_count);
#endif

            // vb_indent(c, indentation_level);
            // vb_copy_string(c, strlit("u64 error_mask = 0;\n"));

            if (is_batch)
            {
                vb_indent(c, indentation_level);
                vb_copy_string(c, strlit("for (u32 string_index = 0; string_index < 64; string_index += 1)\n"));

                vb_indent(c, indentation_level);
                vb_copy_string(c, strlit("{\n"));

                indentation_level += 1;

                vb_indent(c, indentation_level);
                vb_copy_string(c, strlit("const u8* const restrict string_pointer = string_base + string_offsets[string_index];\n"));

                vb_indent(c, indentation_level);
                vb_copy_string(c, strlit("u32 string_length = string_lengths[string_index];\n"));
            }

            vb_indent(c, indentation_level);
            vb_format(c, "__mmask{u64} length_compare_mask = _mm512_cmpeq_epi{u64}_mask(_mm512_set1_epi{u64}(string_length), lengths);\n", arguments.words_by_length.length, epi, epi);

            // vb_indent(c, indentation_level);
            // vb_copy_string(c, strlit("__mmask64 length_mask = _cvtu64_mask64(_cvtmask16_u32(length_compare_mask) - 1);\n"));

            // vb_indent(c, indentation_level);
            // vb_copy_string(c, strlit("__m512i word_offsets = _mm512_permutexvar_epi32(_mm512_setzero(), _mm512_maskz_compress_epi32(length_compare_mask, raw_word_offsets));\n"));

            vb_indent(c, indentation_level);
            vb_format(c, "__m512i value_offsets = _mm512_permutexvar_epi{u64}(_mm512_setzero(), _mm512_maskz_compress_epi{u64}(length_compare_mask, raw_value_offsets));\n", epi, epi);

            // vb_indent(c, indentation_level);
            // vb_copy_string(c, strlit("__m512i candidate_string_in_memory = _mm512_maskz_loadu_epi8(length_mask, &string_pointer[0]);\n"));
        }

        for (u64 length = 0; length < arguments.words_by_length.length; length += 1)
        {
            SliceP(u8) words = arguments.words_by_length.pointer[length];

            if (words.length != 0)
            {
                program_write(c, arguments.programs[length], indentation_level, length);

                *vb_add(c, 1) = '\n';
            }
        }

        vb_indent(c, indentation_level);
        assert(is_power_of_two_u64(arguments.words_by_length.length));
        vb_format(c, "__m512i raw_indices = _mm512_set_epi{u64}(", epi);

        for (s64 length = arguments.words_by_length.length - 1; length >= 0; length -= 1)
        {
            SliceP(u8) words = arguments.words_by_length.pointer[length];
            if (words.length != 0)
            {
                vb_format(c, "index_{u64}, ", length);
            }
            else
            {
                vb_copy_string(c, strlit("0, "));
            }
        }

        c->length -= 2;
        vb_copy_string(c, strlit(");\n"));

        vb_indent(c, indentation_level);
        vb_format(c, "__m512i indices = _mm512_permutexvar_epi{u64}(_mm512_setzero(), _mm512_maskz_compress_epi{u64}(length_compare_mask, raw_indices));\n", epi, epi);

        // vb_indent(c, indentation_level);
        // vb_copy_string(c, strlit("__m512i word_indices = _mm512_add_epi32(word_offsets, indices);\n"));

        vb_indent(c, indentation_level);
        vb_format(c, "__m512i value_indices = _mm512_add_epi{u64}(value_offsets, indices);\n", epi);

        // vb_indent(c, indentation_level);
        // vb_copy_string(c, strlit("let(word_index, _mm_extract_epi32(_mm512_extracti32x4_epi32(word_indices, 0), 0));\n"));

        vb_indent(c, indentation_level);
        vb_format(c, "let(value_index, _mm_extract_epi{u64}(_mm512_extracti{u64}x{u64}_epi{u64}(value_indices, 0), 0));\n", epi, epi, (512 / 4) / epi, epi);

        // vb_indent(c, indentation_level);
        // vb_copy_string(c, strlit("__m512i string_in_memory = _mm512_maskz_loadu_epi8(length_mask, &words[word_index]);\n"));

        vb_indent(c, indentation_level);
        vb_format(c, "{s} value = {s}_value_lut[value_index];\n", type_string, arguments.kind);

        if (is_batch)
        {
            vb_indent(c, indentation_level);
            vb_copy_string(c, strlit("__mmask32 index_mask = _cvtu32_mask32(1 << string_index);\n"));

            vb_indent(c, indentation_level);
            vb_copy_string(c, strlit("result.v[string_index > 31] = _mm512_mask_blend_epi16(index_mask, result.v[string_index > 31], _mm512_set1_epi16(value));\n"));

            indentation_level -= 1;

            vb_indent(c, indentation_level);
            vb_copy_string(c, strlit("}\n"));

            vb_indent(c, indentation_level);
            vb_copy_string(c, strlit("return result;\n"));
        }
        else
        {
            vb_indent(c, indentation_level);
            vb_copy_string(c, strlit("return value;\n"));
        }
        // vb_copy_string(c, strlit("u16 asd[32];\nif (string_index == 31) { _mm512_storeu_epi16(asd, result.v[0]); breakpoint(); }\n"));

        // vb_indent(c, indentation_level);
        // vb_copy_string(c, strlit("out_values[value_index] = value;\n"));

        // vb_indent(c, indentation_level);
        // vb_copy_string(c, strlit("__mmask64 string_compare_mask = _mm512_cmpeq_epi8_mask(candidate_string_in_memory, string_in_memory);\n"));
        //
        // vb_indent(c, indentation_level);
        // vb_copy_string(c, strlit("error_mask |= (_cvtmask64_u64(_knot_mask64(string_compare_mask)) != 0) << string_index;\n"));


        vb_copy_string(c, strlit("}\n"));
    }
}

STRUCT(x86_64_Register)
{
    String name;
    u16 value;
};

typedef enum x86_64_RegisterClass : u8
{
    REGISTER_CLASS_GPR,
    REGISTER_CLASS_VECTOR,
    REGISTER_CLASS_CONTROL,
    REGISTER_CLASS_DEBUG,
} x86_64_RegisterClass;

STRUCT(RegisterSpec)
{
    String name;
    x86_64_RegisterClass class;
    u8 raw_value;
    u8 is_high:1;
    u8 size;
};

fn x86_64_Register define_register(RegisterSpec spec)
{
    x86_64_Register reg = {
        .name = spec.name,
        .value = spec.raw_value,
    };
    return reg;
}

fn void metaprogram(Arena* arena)
{
    let(file, file_read(arena, strlit("bootstrap/bloat-buster/data/x86_mnemonic.dat")));
    String enum_prefix = strlit("MNEMONIC_x86_64_");
    String it = file;
    VirtualBuffer(u8) generated_h = {};
    VirtualBuffer(u8) generated_c = {};

    vb_copy_string(&generated_h, strlit("#pragma once\n\n"));
    vb_copy_string(&generated_c, strlit("#pragma once\n\n"));

    vb_copy_string(&generated_h, strlit("#if defined(__x86_64__)\n"));
    vb_copy_string(&generated_h, strlit("#include <immintrin.h>\n"));
    vb_copy_string(&generated_h, strlit("#endif\n\n"));

    {

        STRUCT(BitsetComponent)
        {
            String name;
            u64 bit_count;
        };

        STRUCT(ByteComponent)
        {
            String type_name;
            String field_name;
            u8 array_length;
            u8 type_size;
            u8 type_alignment;
            u8 bit_count;
        };

        BitsetComponent bitset_components[] = {
            { strlit("is_rm_register"), 1 },
            { strlit("is_reg_register"), 1 },
            { strlit("implicit_register"), 1 },
            { strlit("is_immediate"), 1 },
            { strlit("immediate_size"), 2 },
            { strlit("is_displacement"), 1 },
            { strlit("is_relative"), 1 },
            { strlit("displacement_size"), 1 },
            { strlit("rex_w"), 1 },
            { strlit("opcode_plus_register"), 1 },
            { strlit("opcode_extension"), 3 },
            { strlit("prefix_0f"), 1 },
        };

        ByteComponent byte_components[] = {
            // TODO: opcode, length -> 1 byte
            { .type_name = strlit("u8"), .type_size = sizeof(u8), .type_alignment = alignof(u8), .field_name = strlit("opcode"), .array_length = 2, },
        };

        u8 bit_offsets[array_length(bitset_components)];

        u64 total_bit_count = 0;
        for (u64 i = 0; i < array_length(bitset_components); i += 1)
        {
            bit_offsets[i] = total_bit_count;
            total_bit_count += bitset_components[i].bit_count;
        }

        u64 aligned_bit_count = next_power_of_two(total_bit_count);
        if (aligned_bit_count < 8 || aligned_bit_count > 16)
        {
            os_exit(1);
        }

        u64 alignment = aligned_bit_count / 8;
        u64 bit_remainder = aligned_bit_count - total_bit_count;

        assert(aligned_bit_count % 8 == 0);
        u64 total_size = aligned_bit_count / 8;
        for (u64 i = 0; i < array_length(byte_components); i += 1)
        {
            alignment = MAX(byte_components[i].type_alignment, alignment);
            total_size += byte_components[i].type_size * byte_components[i].array_length ? byte_components[i].array_length : 1;
        }

        u64 aligned_total_size = next_power_of_two(align_forward_u64(total_size, alignment));
        u64 padding_bytes = aligned_total_size - total_size;
        
        vb_copy_string(&generated_h, strlit("STRUCT(EncodingInvariantData)\n{\n"));

        for (u64 i = 0; i < array_length(bitset_components); i += 1)
        {
            BitsetComponent component = bitset_components[i];
            vb_format(&generated_h, "    u{u64} {s}:{u32};\n", aligned_bit_count, component.name, (u32)component.bit_count);
        }

        if (bit_remainder)
        {
            vb_format(&generated_h, "    u{u64} bit_reserved:{u64};\n", aligned_bit_count, bit_remainder);
        }

        for (u64 i = 0; i < array_length(byte_components); i += 1)
        {
            ByteComponent component = byte_components[i];
            if (component.bit_count)
            {
                vb_format(&generated_h, "    {s} {s}:{u32};\n", component.type_name, component.field_name, (u32)component.bit_count);
            }
            else if (component.array_length)
            {
                vb_format(&generated_h, "    {s} {s}[{u32}];\n", component.type_name, component.field_name, (u32)component.array_length);
            }
            else
            {
                vb_format(&generated_h, "    {s} {s};\n", component.type_name, component.field_name);
            }
        }

        if (padding_bytes)
        {
            vb_format(&generated_h, "    u8 byte_reserved[{u64}];\n", padding_bytes);
        }

        vb_copy_string(&generated_h, strlit("};\n\nstatic_assert(sizeof(EncodingInvariantData) <= sizeof(u64));\n\n"));

        for (u64 i = 0; i < array_length(bitset_components); i += 1)
        {
            vb_format(&generated_h, "#define {s}_bit_offset ({u64})\n", bitset_components[i].name, (u64)bit_offsets[i]);
        }

        *vb_add(&generated_h, 1) = '\n';
    }

    vb_copy_string(&generated_h, strlit("typedef enum Mnemonic_x86_64\n{\n"));
    VirtualBufferP(u8) mnemonic_names_by_length_buffer[16] = {};
    VirtualBuffer(u16) mnemonic_values_by_length_buffer[array_length(mnemonic_names_by_length_buffer)] = {};
    SliceP(u8) mnemonic_names_by_length[array_length(mnemonic_names_by_length_buffer)] = {};
    void* mnemonic_values_by_length[array_length(mnemonic_names_by_length_buffer)] = {};
    vb_copy_string(&generated_c, strlit("fn String mnemonic_x86_64_to_string(Mnemonic_x86_64 mnemonic)\n{\n    switch (mnemonic)\n    {\n"));

    u16 mnemonic_index = 0;

    while (it.length)
    {
        let(next_eol_index, string_first_ch(it, '\n'));
        if (next_eol_index == STRING_NO_MATCH)
        {
            todo();
        }

        String mnemonic = { .pointer = it.pointer, .length = next_eol_index };
        *vb_add(&mnemonic_names_by_length_buffer[mnemonic.length], 1) = mnemonic.pointer;
        *vb_add(&mnemonic_values_by_length_buffer[mnemonic.length], 1) = mnemonic_index;

        // Generated h
        vb_copy_string(&generated_h, strlit("    "));
        vb_copy_string(&generated_h, enum_prefix);
        vb_copy_string(&generated_h, mnemonic);
        vb_format(&generated_h, " = 0x{u32:x,w=4},\n", mnemonic_index);
        mnemonic_index += 1;

        // Generated c
        vb_copy_string(&generated_c, strlit("        case "));
        vb_copy_string(&generated_c, enum_prefix);
        vb_copy_string(&generated_c, mnemonic);
        vb_copy_string(&generated_c, strlit(": return strlit(\""));
        vb_copy_string(&generated_c, mnemonic);
        vb_copy_string(&generated_c, strlit("\");\n"));

        it = s_get_slice(u8, it, next_eol_index + 1, it.length);
    }

    vb_copy_string(&generated_h, strlit("} Mnemonic_x86_64;\n"));
    vb_format(&generated_h, "#define mnemonic_x86_64_count ({u32})\n", mnemonic_index);

    vb_copy_string(&generated_c, strlit("    }\n}\n"));

    for (u32 i = 0; i < array_length(mnemonic_names_by_length_buffer); i += 1)
    {
        mnemonic_names_by_length[i] = (SliceP(u8)) { .pointer = mnemonic_names_by_length_buffer[i].pointer, .length = mnemonic_names_by_length_buffer[i].length };
        mnemonic_values_by_length[i] = mnemonic_values_by_length_buffer[i].pointer;
    }

    {
        {
            u8 mask[array_length(mnemonic_names_by_length)];
            Lookup lookups[array_length(mnemonic_names_by_length)];
            Program programs[array_length(mnemonic_names_by_length)];
            PerfectHashArguments perfect_hash = {
                .file_h = &generated_h,
                .file_c = &generated_c,
                .words_by_length = array_to_slice(mnemonic_names_by_length),
                .values_by_length = mnemonic_values_by_length,
                .value_type = TYPE_KIND_U16,
                .mask = mask,
                .lookups = lookups,
                .programs = programs,
                .arena = arena,
                .kind = strlit("mnemonic"),
            };

            perfect_hash_generate(perfect_hash);
        }

        {
#define reg(n, v, c, ...) define_register((RegisterSpec) { .name = strlit(n), .raw_value = (v), .class = REGISTER_CLASS_ ## c, __VA_ARGS__ })
#define regs(n, v, c, s, ...) define_register((RegisterSpec) { .name = strlit(n), .raw_value = (v), .class = (REGISTER_CLASS_ ## c), .size = (s), __VA_ARGS__ })
            x86_64_Register gpr_registers[] = {
                regs("al",  0b000, GPR, 0),
                regs("ah",  0b000, GPR, 1, .is_high = 1),
                regs("ax",  0b000, GPR, 1),
                regs("eax", 0b000, GPR, 2),
                regs("rax", 0b000, GPR, 3),

                regs("cl",  0b0001, GPR, 0),
                regs("ch",  0b0001, GPR, 1, .is_high = 1),
                regs("cx",  0b0001, GPR, 1),
                regs("ecx", 0b0001, GPR, 2),
                regs("rcx", 0b0001, GPR, 3),

                regs("dl",  0b0010, GPR, 0),
                regs("dh",  0b0010, GPR, 1, .is_high = 1),
                regs("dx",  0b0010, GPR, 1),
                regs("edx", 0b0010, GPR, 2),
                regs("rdx", 0b0010, GPR, 3),

                regs("bl",  0b0011, GPR, 0),
                regs("bh",  0b0011, GPR, 1, .is_high = 1),
                regs("bx",  0b0011, GPR, 1),
                regs("ebx", 0b0011, GPR, 2),
                regs("rbx", 0b0011, GPR, 3),

                regs("spl", 0b0100, GPR, 0),
                regs("sp",  0b0100, GPR, 1),
                regs("esp", 0b0100, GPR, 2),
                regs("rsp", 0b0100, GPR, 3),

                regs("bpl", 0b0101, GPR, 0),
                regs("bp",  0b0101, GPR, 1),
                regs("ebp", 0b0101, GPR, 2),
                regs("rbp", 0b0101, GPR, 3),

                regs("sil", 0b0110, GPR, 0),
                regs("si",  0b0110, GPR, 1),
                regs("esi", 0b0110, GPR, 2),
                regs("rsi", 0b0110, GPR, 3),

                regs("dil", 0b0111, GPR, 0),
                regs("di",  0b0111, GPR, 1),
                regs("edi", 0b0111, GPR, 2),
                regs("rdi", 0b0111, GPR, 3),

                regs("r8l", 0b1000, GPR, 0),
                regs("r8w", 0b1000, GPR, 1),
                regs("r8d", 0b1000, GPR, 2),
                regs("r8",  0b1000, GPR, 3),

                regs("r9l", 0b1001, GPR, 0),
                regs("r9w", 0b1001, GPR, 1),
                regs("r9d", 0b1001, GPR, 2),
                regs("r9",  0b1001, GPR, 3),

                regs("r10l", 0b1010, GPR, 0),
                regs("r10w", 0b1010, GPR, 1),
                regs("r10d", 0b1010, GPR, 2),
                regs("r10",  0b1010, GPR, 3),

                regs("r11l", 0b1011, GPR, 0),
                regs("r11w", 0b1011, GPR, 1),
                regs("r11d", 0b1011, GPR, 2),
                regs("r11",  0b1011, GPR, 3),

                regs("r12l", 0b1100, GPR, 0),
                regs("r12w", 0b1100, GPR, 1),
                regs("r12d", 0b1100, GPR, 2),
                regs("r12",  0b1100, GPR, 3),

                regs("r13l", 0b1101, GPR, 0),
                regs("r13w", 0b1101, GPR, 1),
                regs("r13d", 0b1101, GPR, 2),
                regs("r13",  0b1101, GPR, 3),

                regs("r14l", 0b1110, GPR, 0),
                regs("r14w", 0b1110, GPR, 1),
                regs("r14d", 0b1110, GPR, 2),
                regs("r14",  0b1110, GPR, 3),

                regs("r15l", 0b1111, GPR, 0),
                regs("r15w", 0b1111, GPR, 1),
                regs("r15d", 0b1111, GPR, 2),
                regs("r15",  0b1111, GPR, 3),
            };

            VirtualBufferP(u8) register_names_by_length_buffer[8] = {};
            VirtualBuffer(u16) register_values_by_length_buffer[array_length(register_names_by_length_buffer)] = {};
            SliceP(u8) register_names_by_length[array_length(register_names_by_length_buffer)] = {};
            void* register_values_by_length[array_length(register_names_by_length_buffer)] = {};

            vb_copy_string(&generated_h, strlit("typedef enum x86_64_Register : u16\n{\n"));

            for (u32 i = 0; i < array_length(gpr_registers); i += 1)
            {
                x86_64_Register reg = gpr_registers[i];
                *vb_add(&register_names_by_length_buffer[reg.name.length], 1) = reg.name.pointer;
                *vb_add(&register_values_by_length_buffer[reg.name.length], 1) = reg.value;
                vb_format(&generated_h, "    REGISTER_X86_64_{s} = 0x{u32:x,w=4},\n", reg.name, reg.value);
            }

            u8 vector_registers[32][3][5];

            for (u8 i = 0; i < 32; i += 1)
            {
                for (u8 size = 0; size < 3; size += 1)
                {
                    u8 decimal_digit_high = i / 10;
                    u8 decimal_digit_low = i % 10;
                    u8 decimal_digit_high_character = decimal_digit_high + '0';
                    u8 decimal_digit_low_character = decimal_digit_low + '0';

                    vector_registers[i][size][0] = 'x' + size;
                    vector_registers[i][size][1] = 'm';
                    vector_registers[i][size][2] = 'm';
                    vector_registers[i][size][3] = decimal_digit_high ? decimal_digit_high_character : decimal_digit_low_character;
                    vector_registers[i][size][4] = decimal_digit_low_character;
                    RegisterSpec spec = { .name = { .pointer = vector_registers[i][size], .length = 4 + (decimal_digit_high != 0) }, .raw_value = i, .class = REGISTER_CLASS_VECTOR, .size = size, };
                    let(reg, define_register(spec));
                    *vb_add(&register_names_by_length_buffer[reg.name.length], 1) = reg.name.pointer;
                    *vb_add(&register_values_by_length_buffer[reg.name.length], 1) = reg.value;
                    vb_format(&generated_h, "    REGISTER_X86_64_{s} = 0x{u32:x,w=4},\n", reg.name, reg.value);
                }
            }

            vb_copy_string(&generated_h, strlit("} x86_64_Register;\n"));

            for (u32 i = 0; i < array_length(register_names_by_length_buffer); i += 1)
            {
                register_names_by_length[i] = (SliceP(u8)) { .pointer = register_names_by_length_buffer[i].pointer, .length = register_names_by_length_buffer[i].length };
                register_values_by_length[i] = register_values_by_length_buffer[i].pointer;
            }

            u8 mask[array_length(register_names_by_length)];
            Lookup lookups[array_length(register_names_by_length)];
            Program programs[array_length(register_names_by_length)];
            PerfectHashArguments perfect_hash = {
                .file_h = &generated_h,
                .file_c = &generated_c,
                .words_by_length = array_to_slice(register_names_by_length),
                .values_by_length = register_values_by_length,
                .value_type = TYPE_KIND_U16,
                .mask = mask,
                .lookups = lookups,
                .programs = programs,
                .arena = arena,
                .kind = strlit("register"),
            };

            perfect_hash_generate(perfect_hash);
        }
    }

    String generated_h_slice = { .pointer = generated_h.pointer, .length = generated_h.length };
    String generated_c_slice = { .pointer = generated_c.pointer, .length = generated_c.length };

    {
        FileWriteOptions options = {
            .path = strlit(BUILD_DIR "/generated.h"),
            .content = generated_h_slice,
        };
        file_write(options);
    }

    {
        FileWriteOptions options = {
            .path = strlit(BUILD_DIR "/generated.c"),
            .content = generated_c_slice,
        };
        file_write(options);
    }
}

STRUCT(Parser)
{
    u8* pointer;
    u32 length;
    u32 i;
};

fn String parse_mnemonic(Parser* parser)
{
    u32 start = parser->i;
    u8* pointer = parser->pointer;
    String result = { .pointer = pointer + start };

    while (1)
    {
        u32 i = parser->i;
        u8 ch = pointer[i];
        u8 ch_is_alphanumeric = is_alphanumeric(ch);
        parser->i = i + ch_is_alphanumeric;
        if (!ch_is_alphanumeric)
        {
            break;
        }
    }

    result.length = parser->i - start;

    return result;
}

fn String parse_identifier(Parser* parser)
{
    u32 start = parser->i;
    u8* pointer = parser->pointer;
    String result = { .pointer = parser->pointer + parser->i };

    while (1)
    {
        u32 i = parser->i;
        u8 ch = pointer[i];
        u8 is_identifier_ch = is_alphanumeric(ch) | (ch == '_');
        parser->i = i + is_identifier_ch;
        if (!is_identifier_ch)
        {
            break;
        }
    }

    result.length = parser->i - start;

    return result;
}

fn u8 consume_character(Parser* parser, u8 expected_ch)
{
    u32 i = parser->i;
    u8 ch = parser->pointer[i];
    let(is_expected_ch, unlikely((ch == expected_ch) & (i < parser->length)));
    let(new_parser_i, i + is_expected_ch);
    parser->i = new_parser_i;
    return new_parser_i - i;
}

fn void expect_character(Parser* parser, u8 expected_ch)
{
    if (!likely(consume_character(parser, expected_ch)))
    {
        print("Expected character failed!\n");
        os_exit(1);
    }
}


fn u8 get_ch(Parser* parser)
{
    assert(parser->i < parser->length);
    return parser->pointer[parser->i];
}

fn u8 expect_decimal_digit(Parser* parser)
{
    u32 i = parser->i;
    assert(i < parser->length);
    u8 ch = parser->pointer[i];
    u8 is_decimal_digit = (ch >= '0') & (ch <= '9');
    parser->i = i + is_decimal_digit;
    if (likely(is_decimal_digit))
    {
        return ch - '0';
    }
    else
    {
        print("Expect integer digit failed!\n");
        os_exit(1);
    }
}

fn u8 consume_hex_byte(Parser* parser, u8* hex_byte)
{
    u32 i = parser->i;
    assert(i < parser->length - 1);
    u8* pointer = parser->pointer;
    u8 high_ch = pointer[i];
    u8 low_ch = pointer[i + 1];
    u8 is_high_digit_hex = is_hex_digit(high_ch);
    u8 is_low_digit_hex = is_hex_digit(low_ch);
    u8 is_hex_byte = is_high_digit_hex & is_low_digit_hex;
    parser->i = i + (2 * is_hex_byte);
    u8 result = is_hex_byte;
    if (likely(result))
    {
        u8 high_int = hex_ch_to_int(high_ch);
        u8 low_int = hex_ch_to_int(low_ch);
        u8 byte = (high_int << 4) | low_int;
        *hex_byte = byte;
    }

    return result;
}

fn u8 expect_hex_byte(Parser* parser)
{
    u8 result;
    if (!consume_hex_byte(parser, &result))
    {
        print("Expect hex byte failed!\n");
        os_exit(1);
    }

    return result;
}

// TODO: this might be a perf bottleneck
fn u8 consume_tab(Parser* parser)
{
    u8 space0 = consume_character(parser, ' ');
    u8 space1 = consume_character(parser, ' ');
    u8 space2 = consume_character(parser, ' ');
    u8 space3 = consume_character(parser, ' ');
    u8 result = (space0 + space1) + (space2 + space3);
    return result == 4;
}

typedef enum InstructionClass
{
    INSTRUCTION_CLASS_BASE_ARITHMETIC,
    INSTRUCTION_CLASS_UNSIGNED_ADD_FLAG,
    INSTRUCTION_CLASS_BITTEST,
    INSTRUCTION_CLASS_CMOV,
    INSTRUCTION_CLASS_JCC,
    INSTRUCTION_CLASS_ROTATE,
    INSTRUCTION_CLASS_SHIFT,
    INSTRUCTION_CLASS_SETCC,
} InstructionClass;

fn String parse_encoding_type(Parser* parser)
{
    u32 i = parser->i;
    while (1)
    {
        u8 ch = get_ch(parser);
        u8 is_valid_encoding_type_ch = is_lower(ch) | (ch == '-');
        parser->i += is_valid_encoding_type_ch;
        if (is_valid_encoding_type_ch)
        {
            if (parser->i - i > 4)
            {
                todo();
            }
        }
        else
        {
            break;
        }
    }

    u64 length = parser->i - i;
    if (length == 0)
    {
        todo();
    }
    if (length > 4)
    {
        todo();
    }

    String result = { .pointer = parser->pointer + i, .length = length };
    return result;
}

fn void parse_encoding_details(Parser* parser)
{
    expect_character(parser, '[');
    String encoding_type = parse_encoding_type(parser);
    expect_character(parser, ':');
    expect_character(parser, ' ');

    while (!consume_character(parser, ']'))
    {
        // Parser encoding atom
        u8 byte;
        if (consume_hex_byte(parser, &byte))
        {
            u8 ch = get_ch(parser);
            u8 is_plus = ch == '+';
            parser->i += is_plus;
            if (unlikely(is_plus))
            {
                expect_character(parser, 'r');
            }
        }
        else
        {
            String identifier = parse_identifier(parser);
            if (identifier.length)
            {
                if (identifier.pointer[0] == 'i')
                {
                    assert(identifier.length == 2);
                    u8 imm_byte = identifier.pointer[1];
                    u8 is_valid_imm_byte = ((imm_byte == 'b') | (imm_byte == 'w')) | ((imm_byte == 'd') | (imm_byte == 'q'));
                    if (!likely(is_valid_imm_byte))
                    {
                        print("Bad immediate value\n");
                        os_exit(1);
                    }
                }
                else if (s_equal(identifier, strlit("rex")))
                {
                    expect_character(parser, '.');
                    u8 rex_ch = get_ch(parser);
                    u8 is_valid_rex_ch = ((rex_ch == 'w') | (rex_ch == 'r')) | ((rex_ch == 'x') | (rex_ch == 'b'));
                    parser->i += is_valid_rex_ch;
                    if (!likely(is_valid_rex_ch))
                    {
                        todo();
                    }
                }
                else if (string_starts_with(identifier, strlit("rel")))
                {
                    // todo
                }
                else
                {
                    todo();
                }
            }
            else
            {
                u8 ch = get_ch(parser);
                switch (ch)
                {
                    case '/':
                        {
                            parser->i += 1;
                            if (consume_character(parser, 'r'))
                            {
                                // TODO
                            }
                            else
                            {
                                expect_decimal_digit(parser);
                            }
                        } break;
                    default:
                        todo();
                }
            }
        }

        consume_character(parser, ' ');
    }
}

fn void parse_encoding(Parser* parser)
{
    u8 first_ch = get_ch(parser);
    u32 start = parser->i;
    if (first_ch != '[')
    {
        while (1)
        {
            u32 i = parser->i;
            String operand = parse_mnemonic(parser);
            assert(operand.length);
            if (consume_character(parser, ','))
            {
                expect_character(parser, ' ');
            }
            else
            {
                break;
            }
        }

        expect_character(parser, ' ');
    }

    parse_encoding_details(parser);
}

fn void parse_instruction_table(Arena* arena)
{
    String file = file_read(arena, strlit("bootstrap/bloat-buster/data/instructions.dat"));
    Parser parser_memory = {
        .pointer = file.pointer,
        .length = file.length,
    };
    Parser* parser = &parser_memory;

    VirtualBuffer(u8) file_memory = {};
    VirtualBuffer(u8)* f = &file_memory;

    let_cast(u32, file_length, file.length);
    while (parser->i < file_length)
    {
        String mnemonic = parse_mnemonic(parser);
        expect_character(parser, ':');

        if (consume_character(parser, '\n'))
        {
            while (consume_tab(parser))
            {
                parse_encoding(parser);
                expect_character(parser, '\n');
            }
        }
        else if (consume_character(parser, ' '))
        {
            u8 next_ch = get_ch(parser);
            switch (next_ch)
            {
                case '[':
                    {
                        parse_encoding_details(parser);
                    } break;
                default:
                    {
                        String identifier = parse_identifier(parser);
                        if (s_equal(identifier, strlit("class")))
                        {
                            expect_character(parser, ' ');
                            String class_identifier = parse_identifier(parser);
                            InstructionClass instruction_class;

                            if (s_equal(class_identifier, strlit("base_arithmetic")))
                            {
                                instruction_class = INSTRUCTION_CLASS_BASE_ARITHMETIC;
                            }
                            else if (s_equal(class_identifier, strlit("unsigned_add_flag")))
                            {
                                instruction_class = INSTRUCTION_CLASS_UNSIGNED_ADD_FLAG;
                            }
                            else if (s_equal(class_identifier, strlit("bittest")))
                            {
                                instruction_class = INSTRUCTION_CLASS_BITTEST;
                            }
                            else if (s_equal(class_identifier, strlit("cmov")))
                            {
                                instruction_class = INSTRUCTION_CLASS_CMOV;
                            }
                            else if (s_equal(class_identifier, strlit("jcc")))
                            {
                                instruction_class = INSTRUCTION_CLASS_JCC;
                            }
                            else if (s_equal(class_identifier, strlit("rotate")))
                            {
                                instruction_class = INSTRUCTION_CLASS_ROTATE;
                            }
                            else if (s_equal(class_identifier, strlit("shift")))
                            {
                                instruction_class = INSTRUCTION_CLASS_SHIFT;
                            }
                            else if (s_equal(class_identifier, strlit("setcc")))
                            {
                                instruction_class = INSTRUCTION_CLASS_SETCC;
                            }
                            else
                            {
                                todo();
                            }

                            switch (instruction_class)
                            {
                                case INSTRUCTION_CLASS_BASE_ARITHMETIC:
                                    {
                                        u8 opcodes[3];
                                        expect_character(parser, '(');

                                        expect_character(parser, '/');
                                        u8 imm_digit = expect_decimal_digit(parser);
                                        expect_character(parser, ',');
                                        expect_character(parser, ' ');

                                        opcodes[0] = expect_hex_byte(parser);
                                        expect_character(parser, ',');
                                        expect_character(parser, ' ');

                                        opcodes[1] = expect_hex_byte(parser);
                                        expect_character(parser, ',');
                                        expect_character(parser, ' ');

                                        opcodes[2] = expect_hex_byte(parser);
                                        expect_character(parser, ')');
                                    } break;
                                case INSTRUCTION_CLASS_UNSIGNED_ADD_FLAG:
                                    {
                                        expect_character(parser, '(');
                                        u8 opcode = expect_hex_byte(parser);
                                        expect_character(parser, ')');
                                    } break;
                                case INSTRUCTION_CLASS_BITTEST:
                                    {
                                        expect_character(parser, '(');

                                        expect_character(parser, '/');
                                        u8 imm_digit = expect_decimal_digit(parser);
                                        expect_character(parser, ',');
                                        expect_character(parser, ' ');

                                        u8 opcode = expect_hex_byte(parser);
                                        expect_character(parser, ')');
                                    } break;
                                case INSTRUCTION_CLASS_CMOV:
                                    {
                                    } break;
                                case INSTRUCTION_CLASS_JCC:
                                    {
                                    } break;
                                case INSTRUCTION_CLASS_ROTATE:
                                    {
                                        expect_character(parser, '(');

                                        expect_character(parser, '/');
                                        u8 imm_digit = expect_decimal_digit(parser);

                                        expect_character(parser, ')');
                                    } break;
                                case INSTRUCTION_CLASS_SHIFT:
                                    {
                                        expect_character(parser, '(');

                                        expect_character(parser, '/');
                                        u8 imm_digit = expect_decimal_digit(parser);

                                        expect_character(parser, ')');
                                    } break;
                                case INSTRUCTION_CLASS_SETCC:
                                    {
                                    } break;
                            }
                        }
                        else
                        {
                            parser->i -= identifier.length;
                            parse_encoding(parser);
                        }
                    } break;
            }

            expect_character(parser, '\n');
        }
        else
        {
            todo();
        }
    }
}

int main(int argc, char* argv[], char** envp)
{
    environment_pointer = envp;
    Arena* arena = arena_initialize_default(KB(64));
    metaprogram(arena);
    parse_instruction_table(arena);
    BuildType build_type = build_type_pick();
    CompileOptions compile_options = {
        .compiler_path = get_c_compiler_path(arena, build_type),
        .source_path = strlit("bootstrap/bloat-buster/bb.c"),
        .output_path = strlit("cache/bb" EXECUTABLE_EXTENSION),
        .windowing_backend = windowing_backend_pick(),
        .rendering_backend = rendering_backend_pick(),
        .build_type = build_type,
        .flags = {
            .colored_output = 1,
            .error_limit = BB_ERROR_LIMIT,
            .debug = BB_CI,
            .time_trace = BB_TIMETRACE,
        },
    };
    compile_program(arena, compile_options);
    return 0;
}
