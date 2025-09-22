#pragma once

#include <llvm_link.h>

#include <lld_bindings.h>

STRUCT(ArgumentBuilder)
{
    Arena* arena;
    u64 count;
};

LOCAL const char** add_arguments(ArgumentBuilder* restrict builder, u64 count)
{
    let result = arena_allocate(builder->arena, const char*, count);
    builder->count += count;
    return result;
}

LOCAL const char** add_argument(ArgumentBuilder* restrict builder, const char* argument)
{
    let result = add_arguments(builder, 1);
    *result = argument;

    return result;
}

LOCAL const char** add_argument_string(ArgumentBuilder* restrict builder, str argument)
{
    assert(str_is_zero_terminated(argument));
    return add_argument(builder, argument.pointer);
}

LOCAL u8* lld_allocate_function(void* context, u64 size, u64 alignment)
{
    let arena = (Arena*)context;
    return arena_allocate_bytes(arena, size, alignment);
}

PUB_IMPL str llvm_link_machine_code(Arena* arena, Arena* string_arena, CompileUnit** restrict compile_unit_pointer, u64 compile_unit_count, LinkOptions options)
{
    assert(arena != string_arena);

    let target = compile_unit_pointer[0]->target;

    str error_message = {};
    bool result = 1;

    ArgumentBuilder ab = {
        .arena = arena,
    };
    ArgumentBuilder* restrict builder = &ab;

    const char* lld_name = {};
    switch (target.os)
    {
        break; case OPERATING_SYSTEM_UNKNOWN: UNREACHABLE();
        break; case OPERATING_SYSTEM_LINUX: lld_name = "ld.lld";
        break; case OPERATING_SYSTEM_MACOS: lld_name = "ld64.lld";
        break; case OPERATING_SYSTEM_WINDOWS: lld_name = "lld-link";
    }
    let first_argument_pointer = add_argument(builder, lld_name);

    if (target.os != OPERATING_SYSTEM_WINDOWS)
    {
        add_argument(builder, "--error-limit=0");
        add_argument(builder, "-o");
        add_argument_string(builder, options.output_artifact_path);

        if (target.os == OPERATING_SYSTEM_MACOS)
        {
            add_argument(builder, "-arch");

            const char* arg;
            switch (target.cpu)
            {
                break; case CPU_ARCH_UNKNOWN: UNREACHABLE();
                break; case CPU_ARCH_X86_64: arg = "x86_64";
                break; case CPU_ARCH_AARCH64: arg = "arm64";
            }

            add_argument(builder, arg);

            add_argument(builder, "-platform_version");

            switch (target.cpu)
            {
                break; case CPU_ARCH_UNKNOWN: UNREACHABLE();
                break; case CPU_ARCH_X86_64: arg = "13.0";
                break; case CPU_ARCH_AARCH64: arg = "26.0";
            }

            add_argument(builder, "macos");
            add_argument(builder, arg);
            add_argument(builder, arg);

#if defined(XC_SDK_PATH)
            add_argument(builder, "-syslibroot");
            add_argument(builder, XC_SDK_PATH);
#endif
        }

        str candidate_library_paths[] = {
            S("/usr/lib"),
            S("/usr/lib/x86_64-linux-gnu"),
            S("/usr/lib/aarch64-linux-gnu"),
        };

        str scrt1_object_path = {};
        str scrt1_directory_path = {};

        if (target.os == OPERATING_SYSTEM_LINUX)
        {
            u64 position;

            for (u64 i = 0; i < array_length(candidate_library_paths); i += 1, arena_set_position(string_arena, position))
            {
                position = string_arena->position;
                str directory = candidate_library_paths[i];
                str parts[] = {
                    directory,
                    S("/Scrt1.o"),
                };
                let object_path = arena_join_string(string_arena, string_array_to_slice(parts), true);

                let fd = os_file_open(object_path, (OpenFlags){ .read = 1 }, (OpenPermissions){});
                if (fd)
                {
                    os_file_close(fd);
                    scrt1_directory_path = directory;
                    scrt1_object_path = object_path;
                    break;
                }
            }

            result = !!scrt1_object_path.pointer;
        }

        if (result)
        {
            if (target.os == OPERATING_SYSTEM_LINUX)
            {
                str parts[] = {
                    S("-L"),
                    scrt1_directory_path,
                };
                add_argument_string(builder, arena_join_string(string_arena, string_array_to_slice(parts), true));
            }

            for (u64 cu_index = 0; cu_index < compile_unit_count; cu_index += 1)
            {
                CompileUnit* unit = compile_unit_pointer[cu_index];
                let object_path = unit->object_path;
                add_argument_string(builder, object_path);
            }

            switch (target.os)
            {
                break; case OPERATING_SYSTEM_UNKNOWN: UNREACHABLE();
                break; case OPERATING_SYSTEM_LINUX:
                {
                    add_argument(builder, "-dynamic-linker");

                    const char* interpreter = {};
                    switch (target.cpu)
                    {
                        break; case CPU_ARCH_UNKNOWN: UNREACHABLE();
                        break; case CPU_ARCH_X86_64: interpreter = "/lib64/ld-linux-x86-64.so.2";
                        break; case CPU_ARCH_AARCH64: interpreter = "/usr/lib/ld-linux-aarch64.so.1";
                    }

                    add_argument(builder, interpreter);

                    add_argument_string(builder, scrt1_object_path);

                    add_argument(builder, "-lc");
                }
                break; case OPERATING_SYSTEM_MACOS:
                {
                    add_argument(builder, "-lSystem");
                }
                break; case OPERATING_SYSTEM_WINDOWS: UNREACHABLE();
            }

        }
        else
        {
            error_message = S("Could not find scrt1.o");
        }
    }
    else
    {
        add_argument(builder, "-errorlimit:0");

        {
            str parts[] = {
                S("-out:"),
                options.output_artifact_path,
            };
            add_argument_string(builder, arena_join_string(string_arena, string_array_to_slice(parts), true));
        }

        add_argument(builder, "-defaultlib:libcmt");

        for (u64 cu_index = 0; cu_index < compile_unit_count; cu_index += 1)
        {
            CompileUnit* unit = compile_unit_pointer[cu_index];
            let object_path = unit->object_path;
            add_argument_string(builder, object_path);
        }
    }

    typedef lld_api_function_decl(type);
    lld_type_link* link_fn = {};

    let arg_pointer = first_argument_pointer;

    while (1)
    {
        let arg = *arg_pointer;
        if (!arg)
        {
            break;
        }

        unit_show(compile_unit_pointer[0], S(arg));

        arg_pointer += 1;
    }

    switch (target.os)
    {
        break; case OPERATING_SYSTEM_UNKNOWN: UNREACHABLE();
        break; case OPERATING_SYSTEM_LINUX: link_fn = &lld_elf_link;
        break; case OPERATING_SYSTEM_MACOS: link_fn = &lld_macho_link;
        break; case OPERATING_SYSTEM_WINDOWS: link_fn = &lld_coff_link;
    }

    let r = link_fn((char* const*)first_argument_pointer, builder->count, 1, 0, &lld_allocate_function, builder->arena);
    let is_success = r.success | (!r.stdout_string.pointer & !r.stderr_string.pointer);

    if (r.stdout_string.pointer)
    {
        os_file_write(os_get_stdout(), *(str*)&r.stdout_string);
    }

    if (r.stderr_string.pointer)
    {
        os_file_write(os_get_stdout(), *(str*)&r.stderr_string);
    }

    if (!is_success)
    {
        assert(r.stdout_string.length == 0);
        assert(r.stderr_string.length != 0);

        error_message = *(str*)&r.stderr_string;
    }

    return error_message;
}
