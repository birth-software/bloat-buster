#include <std/base.h>

void entry_point(int argc, char* argv[], char* envp[]);

#if LINK_LIBC == 0
[[gnu::naked]] BB_NORETURN void _start();
#endif

#if LINK_LIBC == 0
void static_entry_point(int argc, char* argv[]);
#endif
