#include <compiler.hpp>

global_variable Slice<char* const> environment;

fn void compile(Arena* arena, Options options)
{
    Module module;
    auto base_allocation_type_count = i128_offset + // 64 * 2 for basic integer types
        2 + // u128, s128
        2; // void, noreturn
    auto base_type_allocation = arena_allocate<Type>(arena, base_allocation_type_count);

    auto* type_it = base_type_allocation.pointer;

    bool signs[] = {false, true};
    Type* previous = 0;

    for (bool sign: signs)
    {
        for (u32 bit_index = 0; bit_index < 64; bit_index += 1)
        {
            auto bit_count = bit_index + 1;
            auto first_digit = (u8)(bit_count < 10 ? bit_count % 10 + '0' : bit_count / 10 + '0');
            auto second_digit = (u8)(bit_count > 9 ? bit_count % 10 + '0' : 0);
            u8 name_buffer[] = { u8(sign ? 's' : 'u'), first_digit, second_digit };
            u64 name_length = 2 + (bit_count > 9);
            auto name_stack = String{name_buffer, name_length};

            auto name = arena_duplicate_string(arena, name_stack);

            *type_it = {
                .integer = {
                    .bit_count = bit_count,
                    .is_signed = sign,
                },
                .id = TypeId::integer,
                .name = name,
                .scope = &module.scope,
            };
            if (previous) previous->next = type_it;
            previous = type_it;
            type_it += 1;
        }
    }

    for (bool sign: signs)
    {
        auto name = sign ? string_literal("s128") : string_literal("u128");
        *type_it = {
            .integer = {
                .bit_count = 128,
                .is_signed = sign,
            },
            .id = TypeId::integer,
            .name = name,
            .next = previous,
            .scope = &module.scope,
        };
        if (previous) previous->next = type_it;
        previous = type_it;
        type_it += 1;
    }

    auto void_type = type_it;
    type_it += 1;
    auto noreturn_type = type_it;
    type_it += 1;
    assert((u64)(type_it - base_type_allocation.pointer) == base_allocation_type_count);

    previous->next = void_type;
    *void_type = {
        .id = TypeId::void_type,
        .name = string_literal("void"),
        .next = noreturn_type,
        .scope = &module.scope,
    };
    *noreturn_type = {
        .id = TypeId::noreturn,
        .name = string_literal("noreturn"),
        .scope = &module.scope,
    };

    module = Module{
        .arena = arena,
        .content = options.content,
        .scope = {
            .types = {
                .first = base_type_allocation.pointer,
                .last = noreturn_type,
            },
            .kind = ScopeKind::global,
        },
        .name = options.name,
        .path = options.path,
        .executable = options.executable,
        .objects = options.objects,
        .library_directories = options.library_directories,
        .library_names = options.library_names,
        .library_paths = options.library_paths,
        .link_libcpp = options.link_libcpp,
        .target = options.target,
        .build_mode = options.build_mode,
        .has_debug_info = options.has_debug_info,
        .silent = options.silent,
    };
    module.void_value = new_value(&module);
    *module.void_value = {
        .type = void_type,
        .id = ValueId::infer_or_ignore,
    };

    for (auto definition: options.definitions)
    {
        auto definition_global = new_global(&module);
        auto definition_value = new_value(&module);
        auto definition_storage = new_value(&module);
        *definition_value = {
            .string_literal = definition.value,
            .id = ValueId::string_literal,
        };
        *definition_storage = {
            .id = ValueId::global,
        };
        *definition_global = Global{
            .variable = {
                .storage = definition_storage,
                .initial_value = definition_value,
                .type = get_slice_type(&module, uint8(&module)),
                .scope = &module.scope,
                .name = definition.name,
            },
        };
    }

    parse(&module);
    emit(&module);
}

fn String compile_file(Arena* arena, Compile options)
{
    auto relative_file_path = options.relative_file_path;
    if (relative_file_path.length < 5)
    {
        bb_fail();
    }

    auto extension_start = string_last_character(relative_file_path, '.');
    if (extension_start == string_no_match)
    {
        bb_fail();
    }

    if (!relative_file_path(extension_start).equal(string_literal(".bbb")))
    {
        bb_fail();
    }

    auto separator_index = string_last_character(relative_file_path, '/');
    separator_index = separator_index == string_no_match ? 0 : separator_index;

    auto base_start = separator_index + (separator_index != 0 || relative_file_path[separator_index] == '/');
    auto base_name = relative_file_path(base_start, extension_start);

    auto is_compiler = relative_file_path.equal(string_literal("src/compiler.bbb"));

    make_directory(base_cache_dir);

    String cpu_dir_parts[] = {
        string_literal(base_cache_dir),
        string_literal("/"),
        options.host_cpu_model ? string_literal("native") : string_literal("generic"),
    };

    auto cpu_dir = arena_join_string(arena, array_to_slice(cpu_dir_parts));

    make_directory(cstr(cpu_dir));

    auto base_dir = cpu_dir;

    if (is_compiler)
    {
        String compiler_dir_parts[] = {
            base_dir,
            string_literal("/compiler"),
        };
        base_dir = arena_join_string(arena, array_to_slice(compiler_dir_parts));
        make_directory(cstr(base_dir));
    }

    String output_path_dir_parts[] = {
        base_dir,
        string_literal("/"),
        build_mode_to_string(options.build_mode),
        string_literal("_"),
        options.has_debug_info ? string_literal("di") : string_literal("nodi"),
    };
    auto output_path_dir = arena_join_string(arena, array_to_slice(output_path_dir_parts));

    make_directory(cstr(output_path_dir));
    
    String output_path_base_parts[] = {
        output_path_dir,
        string_literal("/"),
        base_name,
    };
    auto output_path_base = arena_join_string(arena, array_to_slice(output_path_base_parts));
    String output_object_path_parts[] = {
        output_path_base,
        string_literal(".o"),
    };
    auto output_object_path = arena_join_string(arena, array_to_slice(output_object_path_parts));
    auto output_executable_path = output_path_base;

    auto file_content = file_read(arena, relative_file_path);
    auto file_path = path_absolute(arena, relative_file_path);

    Slice<Definition> definitions = {};
    auto cmake_prefix_path = string_literal(CMAKE_PREFIX_PATH);
    auto cmake_prefix_path_definition = Definition{
        .name = string_literal("CMAKE_PREFIX_PATH"),
        .value = cmake_prefix_path,
    };

    if (is_compiler)
    {
        auto cmake_prefix_path_cstr = os_get_environment_variable("CMAKE_PREFIX_PATH");
        if (cmake_prefix_path_cstr)
        {
            auto cmake_prefix_path_string = c_string_to_slice(cmake_prefix_path_cstr);
            cmake_prefix_path_definition.value = cmake_prefix_path_string;
        }
    }

    String objects[] = {
        output_object_path,
    };
    Slice<String> object_slice = array_to_slice(objects);

    String c_abi_library = string_literal("build/libc_abi.a");
    String llvm_bindings_library = string_literal("build/libllvm_bindings.a");
    String library_buffer[256];
    String library_directory = {};

    Slice<String> library_directories = {};
    Slice<String> library_names = {};
    Slice<String> library_paths = {};

    if (is_compiler)
    {
        definitions = { .pointer = &cmake_prefix_path_definition, .length = 1 };

        ArgBuilder builder = {};
        String llvm_config_parts[] = {
            cmake_prefix_path,
            string_literal("/bin/llvm-config"),
        };
        builder.add(arena, arena_join_string(arena, array_to_slice(llvm_config_parts)));
        builder.add("--libdir");
        builder.add("--libs");
        builder.add("--system-libs");
        auto arguments = builder.flush();
        auto llvm_config = os_execute(arena, arguments, environment, {
            .policies = { ExecuteStandardStreamPolicy::pipe, ExecuteStandardStreamPolicy::ignore },
        });
        auto success = llvm_config.termination_kind == TerminationKind::exit && llvm_config.termination_code == 0;
        if (!success)
        {
            report_error();
        }

        auto stream = llvm_config.streams[0];
        auto line = string_first_character(stream, '\n');
        if (line == string_no_match)
        {
            report_error();
        }

        library_directory = stream(0, line);
        library_directories = { &library_directory, 1 };

        stream = stream(line + 1);

        line = string_first_character(stream, '\n');
        if (line == string_no_match)
        {
            report_error();
        }

        auto llvm_library_stream = stream(0, line);

        stream = stream(line + 1);

        u64 library_count = 0;

        while (1)
        {
            auto space = string_first_character(llvm_library_stream, ' ');
            if (space == string_no_match)
            {
                auto library_argument = llvm_library_stream;
                library_buffer[library_count] = library_argument(2);
                library_count += 1;
                break;
            }

            // Omit the first two characters: "-l"
            auto library_argument = llvm_library_stream(2, space);
            library_buffer[library_count] = library_argument;
            library_count += 1;
            llvm_library_stream = llvm_library_stream(space + 1);
        }

        line = string_first_character(stream, '\n');
        if (line == string_no_match)
        {
            report_error();
        }
        assert(line == stream.length - 1);
        auto system_library_stream = stream(0, line);

        while (1)
        {
            auto space = string_first_character(system_library_stream, ' ');
            if (space == string_no_match)
            {
                auto library_argument = system_library_stream(2);
                library_buffer[library_count] = library_argument;
                library_count += 1;
                break;
            }

            // Omit the first two characters: "-l"
            auto library_argument = system_library_stream(2, space);
            library_buffer[library_count] = library_argument;
            library_count += 1;
            system_library_stream = system_library_stream(space + 1);
        }

        library_buffer[library_count] = string_literal("gcc");
        library_count += 1;
        library_buffer[library_count] = string_literal("gcc_s");
        library_count += 1;

        library_buffer[library_count] = string_literal("lldCommon");
        library_count += 1;

        library_buffer[library_count] = string_literal("lldCOFF");
        library_count += 1;

        library_buffer[library_count] = string_literal("lldELF");
        library_count += 1;

        library_buffer[library_count] = string_literal("lldMachO");
        library_count += 1;

        library_buffer[library_count] = string_literal("lldMinGW");
        library_count += 1;

        library_buffer[library_count] = string_literal("lldWasm");
        library_count += 1;

        library_buffer[library_count] = string_literal("llvm_bindings");
        library_count += 1;

        library_names = { library_buffer, library_count };
    }
    else if (base_name.equal(string_literal("tests")))
    {
        library_paths = { &c_abi_library, 1 };
    }

    compile(arena, {
            .content = file_content,
            .path = file_path,
            .executable = output_executable_path,
            .name = base_name,
            .definitions = definitions,
            .objects = object_slice,
            .library_paths = library_paths,
            .library_names = library_names,
            .library_directories = library_directories,
            .link_libcpp = is_compiler,
            .target = {
                .cpu = CPUArchitecture::x86_64,
                .os = OperatingSystem::linux_,
                .host_cpu_model = options.host_cpu_model,
            },
            .build_mode = options.build_mode,
            .has_debug_info = options.has_debug_info,
            .silent = options.silent,
            });

    return output_executable_path;
}

global_variable String names[] =
{
    string_literal("tests"),
};

void entry_point(Slice<char* const> arguments, Slice<char* const> envp)
{
    environment = envp;
    Arena* arena = arena_initialize_default(16 * mb);

    if (arguments.length < 2)
    {
        bb_fail_with_message(string_literal("error: Not enough arguments\n"));
    }

    String command_string = c_string_to_slice(arguments[1]);
    String command_strings[] = {
        string_literal("compile"),
        string_literal("test"),
    };
    static_assert(array_length(command_strings) == (u64)Command::count);

    backing_type(Command) i;
    for (i = 0; i < (backing_type(Command))Command::count; i += 1)
    {
        String candidate = command_strings[i];
        if (candidate.equal(command_string))
        {
            break;
        }
    }

    auto command = (Command)i;

    switch (command)
    {
    case Command::compile:
        {
            if (arguments.length < 3)
            {
                bb_fail_with_message(string_literal("Not enough arguments for command 'compile'\n"));
            }

            auto build_mode = BuildMode::debug_none;
            auto has_debug_info = true;
            auto is_host_cpu_model = true;

            if (arguments.length >= 4)
            {
                auto build_mode_string = c_string_to_slice(arguments[3]);
                String build_mode_strings[] = {
                    string_literal("debug_none"),
                    string_literal("debug"),
                    string_literal("soft_optimize"),
                    string_literal("optimize_for_speed"),
                    string_literal("optimize_for_size"),
                    string_literal("aggressively_optimize_for_speed"),
                    string_literal("aggressively_optimize_for_size"),
                };

                backing_type(BuildMode) i;
                for (i = 0; i < (backing_type(BuildMode))BuildMode::count; i += 1)
                {
                    String candidate = build_mode_strings[i];
                    if (build_mode_string.equal(candidate))
                    {
                        break;
                    }
                }

                build_mode = (BuildMode)i;
                if (build_mode == BuildMode::count)
                {
                    bb_fail_with_message(string_literal("Invalid build mode\n"));
                }
            }

            if (arguments.length >= 5)
            {
                auto has_debug_info_string = c_string_to_slice(arguments[4]);
                if (has_debug_info_string.equal(string_literal("true")))
                {
                    has_debug_info = true;
                }
                else if (has_debug_info_string.equal(string_literal("false")))
                {
                    has_debug_info = false;
                }
                else
                {
                    bb_fail_with_message(string_literal("Wrong value for has_debug_info\n"));
                }
            }

            if (arguments.length >= 6)
            {
                auto is_host_cpu_model_string = c_string_to_slice(arguments[5]);
                if (is_host_cpu_model_string.equal(string_literal("true")))
                {
                    is_host_cpu_model = true;
                }
                else if (is_host_cpu_model_string.equal(string_literal("false")))
                {
                    is_host_cpu_model = false;
                }
                else
                {
                    bb_fail_with_message(string_literal("Wrong value for is_host_cpu_model\n"));
                }
            }

            auto relative_file_path = c_string_to_slice(arguments[2]);

            compile_file(arena, {
                .relative_file_path = relative_file_path,
                .build_mode = build_mode,
                .has_debug_info = has_debug_info,
                .host_cpu_model = is_host_cpu_model,
                .silent = false,
            });
        } break;
    case Command::test:
        {
            // TODO: provide more arguments
            if (arguments.length != 2)
            {
                bb_fail_with_message(string_literal("error: 'test' command takes no arguments"));
            }

            bool has_debug_info_array[] = {true, false};

            for (auto name: names)
            {
                for (BuildMode build_mode = BuildMode::debug_none; build_mode < BuildMode::count; build_mode = (BuildMode)((backing_type(BuildMode))build_mode + 1))
                {
                    for (bool has_debug_info : has_debug_info_array)
                    {
                        auto position = arena->position;

                        String relative_file_path_parts[] = { string_literal("tests/"), name, string_literal(".bbb") };
                        auto relative_file_path = arena_join_string(arena, array_to_slice(relative_file_path_parts));

                        auto executable_path = compile_file(arena, {
                                .relative_file_path = relative_file_path,
                                .build_mode = build_mode,
                                .has_debug_info = has_debug_info,
                                .silent = true,
                                });

                        char* const arguments[] =
                        {
                            (char*)executable_path.pointer,
                            0,
                        };
                        Slice<char* const> arg_slice = array_to_slice(arguments);
                        arg_slice.length -= 1;
                        auto execution = os_execute(arena, arg_slice, environment, {});
                        auto success = execution.termination_kind == TerminationKind::exit && execution.termination_code == 0;
                        if (!success)
                        {
                            print(string_literal("Test failed: "));
                            print(executable_path);
                            print(string_literal("\n"));
                            bb_fail();
                        }

                        arena_restore(arena, position);
                    }
                }
            }

            BuildMode compiler_build_mode = BuildMode::debug_none;
            bool compiler_has_debug_info = true;
            auto compiler = compile_file(arena, {
                    .relative_file_path = string_literal("src/compiler.bbb"),
                    .build_mode = compiler_build_mode,
                    .has_debug_info = compiler_has_debug_info,
                    .host_cpu_model = true,
                    .silent = true,
                    });

            char* const compiler_arguments[] =
            {
                (char*)compiler.pointer,
                (char*)"test",
                0,
            };
            Slice<char* const> arg_slice = array_to_slice(compiler_arguments);
            arg_slice.length -= 1;
            auto execution = os_execute(arena, arg_slice, environment, {});
            auto success = execution.termination_kind == TerminationKind::exit && execution.termination_code == 0;
            if (!success)
            {
                print(string_literal("Self-hosted tests failed: "));
                print(build_mode_to_string(compiler_build_mode));
                print(compiler_has_debug_info ? string_literal(" with debug info\n") : string_literal(" with no debug info\n"));
                bb_fail();
            }

            char* const reproduce_arguments[] =
            {
                (char*)compiler.pointer,
                (char*)"reproduce",
                0,
            };
            arg_slice = array_to_slice(reproduce_arguments);
            arg_slice.length -= 1;
            execution = os_execute(arena, arg_slice, environment, {});
            success = execution.termination_kind == TerminationKind::exit && execution.termination_code == 0;
            if (!success)
            {
                print(string_literal("Self-hosted reproduction failed: "));
                print(build_mode_to_string(compiler_build_mode));
                print(compiler_has_debug_info ? string_literal(" with debug info\n") : string_literal(" with no debug info\n"));
                bb_fail();
            }
        } break;
    case Command::count:
        {
            bb_fail_with_message(string_literal("error: Invalid command\n"));
        } break;
    }
}
