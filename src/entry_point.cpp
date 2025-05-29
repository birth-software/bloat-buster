#include <lib.hpp>
void entry_point(Slice<char* const> arguments, Slice<char* const> environment);
int main(int argc, const char* argv[], char* const envp[])
{
    auto* envp_end = envp;
    while (*envp_end)
    {
        envp_end += 1;
    }

    entry_point(Slice<char* const>{(char* const*)argv, (u64)argc}, {envp, (u64)(envp_end - envp)});
    return 0;
}
