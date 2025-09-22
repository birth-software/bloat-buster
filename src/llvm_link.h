#pragma once

#include <compiler.h>

STRUCT(LinkOptions)
{
    str output_artifact_path;
};

PUB_DECL str llvm_link_machine_code(Arena* arena, Arena* string_arena, CompileUnit** restrict compile_unit_pointer, u64 compile_unit_count, LinkOptions options);
