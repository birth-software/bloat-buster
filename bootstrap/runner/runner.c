#include <std/base.h>
#include <std/os.h>
#include <std/entry_point.h>
#include <std/virtual_buffer.h>
#include <std/string.h>

#include <nest/base.h>

#define nest_dir "nest"

declare_slice(CompilerBackend);

typedef enum CMakeBuildType
{
    CMAKE_BUILD_TYPE_DEBUG,
    CMAKE_BUILD_TYPE_MIN_SIZE_RELEASE,
    CMAKE_BUILD_TYPE_RELEASE_WITH_DEBUG_INFO,
    CMAKE_BUILD_TYPE_RELEASE,
    CMAKE_BUILD_TYPE_COUNT,
} CMakeBuildType;

fn void run(Arena* arena, char** envp, String compiler_path, CompilerBackend compiler_backend, u8 debug, char* nest_source_path)
{
    CStringSlice args = {};
    char* compiler_backend_string;
    switch (compiler_backend)
    {
    // case COMPILER_BACKEND_C:
    //     compiler_backend_string = "c";
    //     break;
    // case COMPILER_BACKEND_INTERPRETER:
    //     compiler_backend_string = "i";
    //     break;

    // TODO: change ch
    case COMPILER_BACKEND_NEST:
        compiler_backend_string = "m";
        break;
    case COMPILER_BACKEND_COUNT:
        unreachable();
    }

#define common_compile_and_run_args \
                string_to_c(compiler_path), \
                nest_source_path, \
                compiler_backend_string, \
                0,

    if (debug)
    {
#if _WIN32
        args = (CStringSlice) array_to_slice(((char*[]){ 
            "C:\\Users\\David\\Downloads\\remedybg_0_4_0_7\\remedybg.exe",
            "-g",
            common_compile_and_run_args 
        }));
#elif defined(__linux__)
        args = (CStringSlice) array_to_slice(((char*[]){ 
            "/home/david/source/gf/gf2",
            "-ex",
            "set auto-solib-add off",
            "-ex",
            "r",
            "--args",
            common_compile_and_run_args 
        }));
#elif defined(__APPLE__)
        args = (CStringSlice) array_to_slice(((char*[]){ 
            "/usr/bin/lldb",
            "-o",
            "run",
            "--",
            common_compile_and_run_args 
        }));
#endif
    }
    else
    {
        args = (CStringSlice) array_to_slice(((char*[]){
            common_compile_and_run_args
        }));
    }

    run_command(arena, args, envp);
}

typedef enum Command : u8
{
    COMMAND_DEBUG,
    COMMAND_RUN_TESTS,
    COMMAND_COUNT,
} Command;

STRUCT(TestOptions)
{
    Slice(String) test_paths;
    Slice(CompilerBackend) compiler_backends;
};

fn void run_tests(Arena* arena, String compiler_path, TestOptions const * const test_options, char** envp)
{
    print("\n===========================\n");
    print("COMPILER BUILD [OK]\n");
    print("===========================\n\n");

    for (u32 test_i = 0; test_i < test_options->test_paths.length; test_i += 1)
    {
        String test_path = test_options->test_paths.pointer[test_i];
        char* test_path_c = string_to_c(test_path);
        auto test_dir = path_no_extension(test_path);
        auto test_name = path_base(test_dir);

        for (u32 engine_i = 0; engine_i < test_options->compiler_backends.length; engine_i += 1)
        {
            CompilerBackend compiler_backend = test_options->compiler_backends.pointer[engine_i];
            char* compiler_backend_string;
            switch (compiler_backend)
            {
                // case COMPILER_BACKEND_C:
                //     compiler_backend_string = "c";
                //     break;
                // case COMPILER_BACKEND_INTERPRETER:
                //     compiler_backend_string = "i";
                //     break;
                case COMPILER_BACKEND_NEST:
                    compiler_backend_string = "m";
                    break;
                case COMPILER_BACKEND_COUNT:
                    unreachable();
            }

            char* arguments[] = {
                string_to_c(compiler_path),
                test_path_c,
                compiler_backend_string,
                0,
            };

            run_command(arena, (CStringSlice) array_to_slice(arguments), envp);

            // if (compiler_backend != COMPILER_BACKEND_INTERPRETER)
            {
                String path_split[] = {
                    strlit("./" nest_dir "/"),
                    test_name,
#if _WIN32
                    strlit(".exe"),
#endif
                };
                String out_program = arena_join_string(arena, ((Slice(String)) array_to_slice(path_split)));
                char* run_arguments[] = {
                    string_to_c(out_program),
                    0,
                };
                run_command(arena, (CStringSlice) array_to_slice(run_arguments), envp);
            }
        }
    }
}

void entry_point(int argc, char* argv[], char* envp[])
{
    if (argc < 2)
    {
        print("Expected some arguments\n");
        fail();
    }

    Arena* arena = arena_init_default(KB(64));

    CompilerBackend preferred_compiler_backend = COMPILER_BACKEND_COUNT;
    Command command = COMMAND_COUNT;
    u8 test_every_config = 0;
    String source_file_path = {};
    CMakeBuildType build_type = CMAKE_BUILD_TYPE_COUNT;
    String release_strings[CMAKE_BUILD_TYPE_COUNT] = {
        [CMAKE_BUILD_TYPE_DEBUG] = strlit("Debug"),
        [CMAKE_BUILD_TYPE_MIN_SIZE_RELEASE] = strlit("MinSizeRel"),
        [CMAKE_BUILD_TYPE_RELEASE_WITH_DEBUG_INFO] = strlit("RelWithDebInfo"),
        [CMAKE_BUILD_TYPE_RELEASE] = strlit("Release"),
    };

    for (int i = 1; i < argc; i += 1)
    {
        char* c_argument = argv[i];
        auto argument = cstr(c_argument);

        if (string_starts_with(argument, strlit("build_type=")))
        {
            auto release_start = cast(u32, s32, string_first_ch(argument, '=') + 1);
            auto release_string = s_get_slice(u8, argument, release_start, argument.length);

            for (u64 i = 0; i < array_length(release_strings); i += 1)
            {
                if (s_equal(release_string, release_strings[i]))
                {
                    build_type = (CMakeBuildType)i;
                    break;
                }
            }

            assert(build_type != CMAKE_BUILD_TYPE_COUNT);
        }
        // else if (s_equal(argument, strlit("i")))
        // {
        //     preferred_compiler_backend = COMPILER_BACKEND_INTERPRETER;
        // }
        // else if (s_equal(argument, strlit("c")))
        // {
        //     preferred_compiler_backend = COMPILER_BACKEND_C;
        // }
        else if (s_equal(argument, strlit("m")))
        {
            preferred_compiler_backend = COMPILER_BACKEND_NEST;
        }
        else if (s_equal(argument, strlit("test")))
        {
            command = COMMAND_RUN_TESTS;
        }
        else if (s_equal(argument, strlit("debug")))
        {
            command = COMMAND_DEBUG;
        }
        else if (s_equal(argument, strlit("all")))
        {
            test_every_config = 1;
        }
    }

    auto index = 2 - (command == COMMAND_COUNT);
    if (argc > index)
    {
        auto* c_argument = argv[index];
        auto argument = cstr(c_argument);
        String expected_starts[] = {
            strlit("tests/"),
            strlit("tests\\"),
            strlit("./tests/"),
            strlit(".\\tests\\"),
            strlit("src/"),
            strlit("src\\"),
            strlit("./src/"),
            strlit(".\\src\\"),
        };

        for (u32 i = 0; i < array_length(expected_starts); i += 1)
        {
            auto expected_start = expected_starts[i];
            if (expected_start.length < argument.length)
            {
                // TODO: make our own function
                if (strncmp(c_argument, string_to_c(expected_start), expected_start.length) == 0)
                {
                    source_file_path = argument;
                    break;
                }
            }
        }
    }

    if (command == COMMAND_COUNT && !source_file_path.pointer)
    {
        print("Expected a command\n");
        fail();
    }

    if (command == COMMAND_COUNT)
    {
        command = COMMAND_RUN_TESTS;
        test_every_config = 1;
    }

    if ((command == COMMAND_DEBUG) | ((command == COMMAND_RUN_TESTS) & (test_every_config == 0)))
    {
        if (preferred_compiler_backend == COMPILER_BACKEND_COUNT)
        {
            preferred_compiler_backend = COMPILER_BACKEND_NEST;
        }
    }

    if (build_type == CMAKE_BUILD_TYPE_COUNT)
    {
        build_type = CMAKE_BUILD_TYPE_DEBUG;
    }

    auto build_type_string = release_strings[build_type];
    String compiler_path = strlit("build/nest");

    switch (command)
    {
    case COMMAND_DEBUG:
        if (!source_file_path.pointer)
        {
            fail();
        }

        run(arena, envp, compiler_path, preferred_compiler_backend, 1, string_to_c(source_file_path));
        break;
    case COMMAND_RUN_TESTS:
        {
            String every_single_test[] = {
                 strlit("tests/first.nat"),
                 // strlit("tests/add_sub.nat"),
                 // strlit("tests/mul.nat"),
                 // strlit("tests/div.nat"),
                 // strlit("tests/and.nat"),
                 // strlit("tests/or.nat"),
                 // strlit("tests/xor.nat"),
                 // strlit("tests/return_var.nat"),
                 // strlit("tests/return_mod_scope.nat"),
                 // strlit("tests/shift_left.nat"),
                 // strlit("tests/shift_right.nat"),
                 // strlit("tests/thousand_simple_functions.nat"),
                 // strlit("tests/simple_arg.nat"),
                 // strlit("tests/comparison.nat"),
            };
            CompilerBackend all_compiler_backends[] = {
                // COMPILER_BACKEND_INTERPRETER,
                // COMPILER_BACKEND_C,
                COMPILER_BACKEND_NEST,
            };

            Slice(CompilerBackend) compiler_backend_selection;

            if (test_every_config)
            {
                compiler_backend_selection = (Slice(CompilerBackend)) array_to_slice(all_compiler_backends);
            }
            else
            {
                compiler_backend_selection = (Slice(CompilerBackend)) { .pointer = &preferred_compiler_backend, .length = 1 };
            }

            Slice(String) test_selection;
            if (source_file_path.pointer)
            {
                test_selection = (Slice(String)) { .pointer = &source_file_path, .length = 1 };
            }
            else
            {
                test_selection = (Slice(String)) array_to_slice(every_single_test);
            }

            run_tests(arena, compiler_path, &(TestOptions) {
                .test_paths = test_selection,
                .compiler_backends = compiler_backend_selection,
            }, envp);
        } break;
    case COMMAND_COUNT:
        unreachable();
    }
}
