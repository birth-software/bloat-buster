#include <std/base.h>
#include <std/os.h>
#include <std/project.h>

#include <std/base.c>
#include <std/os.c>

global_variable char** environment_pointer;

STRUCT(CompileFlags)
{
    u64 debug_info:1;
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
    CompileFlags flags;
};

typedef enum CompilerArgumentStyle
{
    COMPILER_ARGUMENT_STYLE_GNU,
    COMPILER_ARGUMENT_STYLE_MICROSOFT,
    COMPILER_ARGUMENT_STYLE_COUNT,
} CompilerArgumentStyle;

typedef enum CompilerSwitch
{
    COMPILER_SWITCH_DEBUG_INFO,
    COMPILER_SWITCH_COUNT,
} CompilerSwitch;

global_variable char* compiler_switches[COMPILER_ARGUMENT_STYLE_COUNT][COMPILER_SWITCH_COUNT] = {
    [COMPILER_ARGUMENT_STYLE_GNU] = {
        [COMPILER_SWITCH_DEBUG_INFO] = "-g",
    },
    [COMPILER_ARGUMENT_STYLE_MICROSOFT] = {
        [COMPILER_SWITCH_DEBUG_INFO] = "/Zi",
    },
};

typedef enum C_Compiler
{
    C_COMPILER_GCC,
    C_COMPILER_CLANG,
    C_COMPILER_MSVC,
    C_COMPILER_TCC,
    C_COMPILER_COUNT,
} C_Compiler;

global_variable String c_compiler_names[C_COMPILER_COUNT] = {
    strlit("gcc"),
    strlit("clang"),
    strlit("cl"),
    strlit("tcc"),
};

fn String file_find_in_path(Arena* arena, String file, String path_env)
{
    String result = {};
    assert(path_env.pointer);

    String path_it = path_env;
    u8 buffer[4096];

    while (path_it.length)
    {
        auto index = string_first_ch(path_it, ':');
        index = unlikely(index == STRING_NO_MATCH) ? path_it.length : index;
        auto path_chunk = s_get_slice(u8, path_it, 0, index);

        u64 i = 0;

        memcpy(&buffer[i], path_chunk.pointer, path_chunk.length);
        i += path_chunk.length;

        buffer[i] = '/';
        i += 1;

        memcpy(&buffer[i], file.pointer, file.length);
        i += file.length;

        buffer[i] = 0;
        i += 1;

        auto total_length = i - 1;
        OSFileOpenFlags flags = {
            .read = 1,
        };
        OSFilePermissions permissions = {
            .readable = 1,
            .writable = 1,
        };

        String path = { .pointer = buffer, .length = total_length };
        if (os_file_descriptor_is_valid(os_file_open(path, flags, permissions)))
        {
            result.pointer = arena_allocate(arena, u8, total_length + 1);
            memcpy(result.pointer, buffer, total_length + 1);
            result.length = total_length;
            break;
        }

        path_it = s_get_slice(u8, path_it, index + 1, path_it.length);
    }

    return result;
}

global_variable u8 prefer_clang = 1;

fn C_Compiler c_compiler_from_path(String path)
{
    C_Compiler result = C_COMPILER_COUNT;
    auto start = string_last_ch(path, '/');
#if _WIN32
    auto last_ch_backslash = string_last_ch(path, '\\');
    start = MAX(start, last_ch_backslash == STRING_NO_MATCH ? 0 : last_ch_backslash);
#endif
    assert(start != STRING_NO_MATCH);
    auto compiler_name = s_get_slice(u8, path, start + 1, path.length);

    for (C_Compiler i = 0; i < C_COMPILER_COUNT; i += 1)
    {
        if (string_starts_with(compiler_name, c_compiler_names[i]))
        {
            result = i;
            break;
        }
    }

    return result;
}

// Returns the absolute path of a C compiler
fn String get_c_compiler_path(Arena* arena)
{
    String cc_path = {};
    String cc_env = os_get_environment_variable("CC");
    String path_env = os_get_environment_variable("PATH");
    if (cc_env.pointer)
    {
        cc_path = cc_env;
    }
#ifndef _WIN32
    else
    {
        cc_path = file_find_in_path(arena, strlit("cc"), path_env);
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

    auto no_path_sep = string_first_ch(cc_path, '/') == STRING_NO_MATCH;
#ifdef _WIN32
    no_path_sep = no_path_sep && string_first_ch(cc_path, '\\') == STRING_NO_MATCH;
#endif
    if (no_path_sep)
    {
        cc_path = file_find_in_path(arena, cc_path, path_env);
    }

#ifndef _WIN32
    u8 buffer[4096];
    auto realpath = os_realpath(cc_path, (String)array_to_slice(buffer));
    if (!s_equal(realpath, cc_path))
    {
        cc_path.pointer = arena_allocate(arena, u8, realpath.length + 1);
        cc_path.length = realpath.length;
        memcpy(cc_path.pointer, realpath.pointer, realpath.length);
        cc_path.pointer[cc_path.length] = 0;
    }

    if (prefer_clang)
    {
        if (c_compiler_from_path(cc_path) != C_COMPILER_CLANG)
        {
            cc_path = strlit("/usr/bin/clang");
        }
    }
#endif

    return cc_path;
}


fn String c_compiler_to_string(C_Compiler c_compiler)
{
    switch (c_compiler)
    {
        case C_COMPILER_GCC: return strlit("gcc");
        case C_COMPILER_MSVC: return strlit("MSVC");
        case C_COMPILER_CLANG: return strlit("clang");
        case C_COMPILER_TCC: return strlit("tcc");
        case C_COMPILER_COUNT: unreachable();
    }
}

fn u8 c_compiler_supports_colored_output(C_Compiler compiler)
{
    // TODO: fix
    switch (compiler)
    {
        case C_COMPILER_GCC: case C_COMPILER_CLANG: return 1;
        case C_COMPILER_TCC: case C_COMPILER_MSVC: return 0;
        case C_COMPILER_COUNT: unreachable();
    }
}

fn u8 c_compiler_supports_error_limit(C_Compiler compiler)
{
    // TODO: fix
    switch (compiler)
    {
        case C_COMPILER_CLANG: return 1;
        default: return 0;
        case C_COMPILER_COUNT: unreachable();
    }
}

fn char* c_compiler_get_highest_c_standard_flag(C_Compiler compiler)
{
    switch (compiler)
    {
        case C_COMPILER_CLANG: case C_COMPILER_GCC: return "-std=gnu2x";
        case C_COMPILER_MSVC: unreachable(); // TODO: fix
        case C_COMPILER_TCC: return "-std=gnu2x"; // TODO: does it do anything in TCC?
        case C_COMPILER_COUNT: unreachable();
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

fn void compile_program(Arena* arena, CompileOptions options)
{
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
    add_arg(string_to_c(options.source_path));
    add_arg("-o");
    add_arg(string_to_c(options.output_path));
    add_arg("-Ibootstrap");
    add_arg("-Idependencies/stb");

    if (options.flags.debug_info)
    {
        add_arg(compiler_switches[c_compiler == C_COMPILER_MSVC][COMPILER_SWITCH_DEBUG_INFO]);
    }

    if (options.flags.colored_output && c_compiler_supports_colored_output(c_compiler))
    {
        add_arg("-fdiagnostics-color=auto");
    }

    if (options.flags.error_limit && c_compiler_supports_error_limit(c_compiler))
    {
        add_arg("-ferror-limit=1");
    }

    if (options.flags.time_trace && c_compiler_supports_time_trace(c_compiler))
    {
        add_arg("-ftime-trace");
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
                add_arg("-lxcb");
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
            } break;
        case RENDERING_BACKEND_COUNT: unreachable();
    }

    add_arg("-lm");

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
        .flags = {
            .debug_info = 1,
            .colored_output = 1,
            .error_limit = 1,
            .debug = 0,
            .time_trace = BB_TIMETRACE,
        },
    };
    compile_program(arena, compile_options);
    return 0;
}
