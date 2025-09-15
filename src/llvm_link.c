#include <llvm_link.h>

#include <lld_bindings.h>

STRUCT(ArgumentBuilder)
{
    Arena* arena;
    u64 count;
};

static const char** add_arguments(ArgumentBuilder* restrict builder, u64 count)
{
    let result = arena_allocate(builder->arena, const char*, count);
    builder->count += count;
    return result;
}

static const char** add_argument(ArgumentBuilder* restrict builder, const char* argument)
{
    let result = add_arguments(builder, 1);
    *result = argument;

    return result;
}

static const char** add_argument_string(ArgumentBuilder* restrict builder, str argument)
{
    assert(str_is_zero_terminated(argument));
    return add_argument(builder, argument.pointer);
}

static u8* lld_allocate_function(void* context, u64 size, u64 alignment)
{
    let arena = (Arena*)context;
    return arena_allocate_bytes(arena, size, alignment);
}

str llvm_link_machine_code(Arena* arena, Arena* string_arena, CompileUnit** restrict compile_unit_pointer, u64 compile_unit_count, LinkOptions options)
{
    assert(arena != string_arena);

    str result = {};

    ArgumentBuilder ab = {
        .arena = arena,
    };
    ArgumentBuilder* restrict builder = &ab;
    let first_argument_pointer = add_argument(builder, "ld.lld");
    add_argument(builder, "--error-limit=0");
    add_argument(builder, "-o");
    add_argument_string(builder, options.output_artifact_path);

    str candidate_library_paths[] = {
        S("/usr/lib"),
        S("/usr/lib/x86_64-linux-gnu"),
    };

    str scrt1_object_path = {};
    str scrt1_directory_path = {};

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

    if (scrt1_object_path.pointer)
    {
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

        add_argument(builder, "-dynamic-linker");
        add_argument(builder, "/lib64/ld-linux-x86-64.so.2");

        add_argument_string(builder, scrt1_object_path);
        add_argument(builder, "-lc");

        let r = lld_elf_link((char* const*)first_argument_pointer, builder->count, 1, 0, &lld_allocate_function, builder->arena);
        let is_success = r.success | (!r.stdout_string.pointer & !r.stderr_string.pointer);

        if (!is_success)
        {
            assert(r.stdout_string.length == 0);
            assert(r.stderr_string.length != 0);

            result = *(str*)&r.stderr_string;
        }
    }
    else
    {
        result = S("Could not find scrt1.o");
    }

    return result;
}
