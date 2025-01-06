#include <std/entry_point.h>
#include <std/os.h>

#if LINK_LIBC == 0
[[gnu::naked]] BB_NORETURN void _start()
{
    __asm__ __volatile__(
            "\nxor %ebp, %ebp"
            "\npopq %rdi"
            "\nmov %rsp, %rsi"
            "\nand $~0xf, %rsp"
            "\npushq %rsp"
            "\npushq $0"
            "\ncallq static_entry_point"
            "\nud2\n"
       );
}
#endif

#if LINK_LIBC == 0
void static_entry_point(int argc, char* argv[])
{
    char** envp = (char**)&argv[argc + 1];
#else
int main(int argc, char* argv[], char* envp[])
{
#endif
    calibrate_cpu_timer();
    entry_point(argc, argv, envp);
#if LINK_LIBC
    return 0;
#else
    syscall_exit(0);
#endif
}
