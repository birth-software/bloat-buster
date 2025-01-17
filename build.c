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

fn String file_find_in_path(Arena* arena, String file, String path_env, String extension)
{
    String result = {};
    assert(path_env.pointer);

    String path_it = path_env;
    u8 buffer[4096];

#if _WIN32
    u8 env_path_separator = ';';
    u8 path_separator = '\\';
#else
    u8 env_path_separator = ':';
    u8 path_separator = '/';
#endif

    while (path_it.length)
    {
        let(index, string_first_ch(path_it, env_path_separator));
        index = unlikely(index == STRING_NO_MATCH) ? path_it.length : index;
        let(path_chunk, s_get_slice(u8, path_it, 0, index));

        u64 i = 0;

        memcpy(&buffer[i], path_chunk.pointer, path_chunk.length);
        i += path_chunk.length;

        buffer[i] = path_separator;
        i += 1;

        memcpy(&buffer[i], file.pointer, file.length);
        i += file.length;

        if (extension.length)
        {
            memcpy(&buffer[i], extension.pointer, extension.length);
            i += extension.length;
        }

        buffer[i] = 0;
        i += 1;

        let(total_length, i - 1);
        OSFileOpenFlags flags = {
            .read = 1,
        };
        OSFilePermissions permissions = {
            .readable = 1,
            .writable = 1,
        };

        String path = { .pointer = buffer, .length = total_length };

        FileDescriptor fd = os_file_open(path, flags, permissions);

        if (os_file_descriptor_is_valid(fd))
        {
            os_file_close(fd);
            result.pointer = arena_allocate(arena, u8, total_length + 1);
            memcpy(result.pointer, buffer, total_length + 1);
            result.length = total_length;
            break;
        }

        String new_path = s_get_slice(u8, path_it, index + (index != path_it.length), path_it.length);
        assert(new_path.length < path_env.length);
        path_it = new_path;
    }

    return result;
}


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
fn String get_c_compiler_path(Arena* arena)
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
#ifndef _WIN32
    else
    {
        cc_path = file_find_in_path(arena, strlit("cc"), path_env, extension);
    }
#endif

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

#if __APPLE__
    add_arg("-x");
    add_arg("objective-c");
#endif

    add_arg(string_to_c(options.source_path));

    if (c_compiler == C_COMPILER_MSVC)
    {
        String strings[] = {
            strlit("/Fe"),
            options.output_path,
        };
        String arg = arena_join_string(arena, (Slice(String))array_to_slice(strings));
        add_arg(string_to_c(arg));

        add_arg("/Fo" BUILD_DIR "\\");
        add_arg("/Fd" BUILD_DIR "\\");
    }
    else
    {
        add_arg("-o");
        add_arg(string_to_c(options.output_path));
    }

    add_arg("-Ibootstrap");
    add_arg("-Idependencies/stb");

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

    let(debug_info, options.build_type != BUILD_TYPE_RELEASE_SMALL);
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
        case BUILD_TYPE_RELEASE_SAFE: add_arg("-DBB_DEBUG=1"); add_arg("-D_DEBUG=1"); break;
        case BUILD_TYPE_RELEASE_FAST:
        case BUILD_TYPE_RELEASE_SMALL: add_arg("-DBB_DEBUG=0"); add_arg("-DNDEBUG=1"); break;
    }

    // Inmutable options
    switch (c_compiler)
    {
        case C_COMPILER_MSVC:
            {
                add_arg("/Wall");
#if BB_ERROR_ON_WARNINGS
                add_arg("/WX");
#endif
                add_arg("/wd4255");
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
#ifndef __APPLE__
                add_arg("-Wno-auto-decl-extensions");
#endif
                add_arg("-Wno-gnu-empty-initializer");
                add_arg("-Wno-fixed-enum-extension");
#if BB_ERROR_ON_WARNINGS
                add_arg("-Werror");
#endif

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
    run_command(arena, arguments, environment_pointer, run_options);
}

int main(int argc, char* argv[], char** envp)
{
    environment_pointer = envp;
    Arena* arena = arena_initialize_default(KB(64));

    CompileOptions compile_options = {
        .compiler_path = get_c_compiler_path(arena),
        .source_path = strlit("bootstrap/bloat-buster/bb.c"),
        .output_path = strlit("cache/bb" EXECUTABLE_EXTENSION),
        .windowing_backend = windowing_backend_pick(),
        .rendering_backend = rendering_backend_pick(),
        .build_type = build_type_pick(),
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
