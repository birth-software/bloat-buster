#include <parser.h>

#include <compiler.h>

STRUCT(Parser)
{
    u64 offset;
};

void parse_file(CompileUnit* unit, File* file)
{
    assert(file->content.pointer);

    trap();
}
