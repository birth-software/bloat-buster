#if 0
#!/usr/bin/env bash
echo "Building..."
cc -o cache/build $0 && cache/build -Oz
exit 0
#endif

#include <stdio.h>

int main()
{
    printf("Hello world\n");
    return 0;
}
