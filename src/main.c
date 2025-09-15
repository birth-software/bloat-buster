#include <compiler.h>

int main(int argc, const char* argv[], char** envp)
{
    bool result = compiler_main(argc, argv, envp);
    int result_code = result ? 0 : 1;
    return result_code;
}
