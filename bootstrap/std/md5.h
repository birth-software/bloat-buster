#include <std/base.h>

STRUCT(MD5Result)
{
    u8 hash[16];
};

MD5Result md5_string(String string);
