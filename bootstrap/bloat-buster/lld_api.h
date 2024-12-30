#include <std/base.h>

STRUCT(LLDArguments)
{
    const char** argument_pointer;
    u32 argument_count;
    u8 exit_early;
    u8 disable_output;
};

#define lld_api_function_decl(link_name) u8 lld_ ## link_name ## _link(LLDArguments args)

EXPORT lld_api_function_decl(coff);
EXPORT lld_api_function_decl(elf);
EXPORT lld_api_function_decl(mingw);
EXPORT lld_api_function_decl(macho);
EXPORT lld_api_function_decl(coff);
