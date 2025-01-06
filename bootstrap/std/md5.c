#include <std/md5.h>

STRUCT(MD5Context)
{
    u32 buffer[4];
    u8 input[64];
    u64 size;
};

// Took from: https://github.com/Zunawe/md5-c

#define MD5_A 0x67452301
#define MD5_B 0xefcdab89
#define MD5_C 0x98badcfe
#define MD5_D 0x10325476

#define MD5_F(X, Y, Z) ((X & Y) | (~X & Z))
#define MD5_G(X, Y, Z) ((X & Z) | (Y & ~Z))
#define MD5_H(X, Y, Z) (X ^ Y ^ Z)
#define MD5_I(X, Y, Z) (Y ^ (X | ~Z))

global_variable u32 md5_s[] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                       5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                       4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                       6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

global_variable u32 md5_k[] = {0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                       0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                       0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                       0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                       0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
                       0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                       0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
                       0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                       0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
                       0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                       0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
                       0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                       0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
                       0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                       0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                       0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

/*
 * Padding used to make the size (in bits) of the input congruent to 448 mod 512
 */
global_variable u8 md5_padding[] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};


fn MD5Context md5_init()
{
    return (MD5Context) {
        .buffer = { MD5_A, MD5_B, MD5_C, MD5_D },
    };
}

fn u32 rotate_left_u32(u32 x, u32 n)
{
    return (x << n) | (x >> (32 - n));
}

fn void md5_step(u32* buffer, u32* input)
{
    u32 aa = buffer[0];
    u32 bb = buffer[1];
    u32 cc = buffer[2];
    u32 dd = buffer[3];

    for (u32 i = 0; i < 64; i += 1)
    {
        u32 j;
        u32 e;
        switch (i / 16)
        {
            case 0:
                {
                    e = MD5_F(bb, cc, dd);
                    j = i;
                } break;
            case 1:
                {
                    e = MD5_G(bb, cc, dd);
                    j = ((i * 5) + 1) % 16;
                } break;
            case 2:
                {
                    e = MD5_H(bb, cc, dd);
                    j = ((i * 3) + 5) % 16;
                } break;
            default:
                {
                    e = MD5_I(bb, cc, dd);
                    j = (i * 7) % 16;
                } break;
        }

        u32 old_dd = dd;
        dd = cc;
        cc = bb;
        bb = bb + rotate_left_u32(aa + e + md5_k[i] + input[j], md5_s[i]);
        aa = old_dd;
    }

    buffer[0] += aa;
    buffer[1] += bb;
    buffer[2] += cc;
    buffer[3] += dd;
}

fn void md5_update(MD5Context* context, String input_argument)
{
    u32 input_local[16];
    auto offset = context->size % 64;
    context->size += input_argument.length;

    for (u64 i = 0; i < input_argument.length; i += 1)
    {
        context->input[offset] = input_argument.pointer[i];
        offset += 1;

        if (offset % 64 == 0)
        {
            // TODO: convert to little-endian in case we are big-endian?
            for (u16 i = 0; i < 16; i += 1)
            {
                auto existing = *(u32*)&input_argument.pointer[i * 4];
                input_local[i] = existing;
            }
            md5_step(context->buffer, input_local);
            offset = 0;
        }
    }
}

fn MD5Result md5_end(MD5Context* context)
{
    u32 input[16];
    auto offset = context->size % 64;
    auto padding_length = offset < 56 ? 56 - offset : (56 + 64) - offset;
    
    md5_update(context, (String) { .pointer = md5_padding, .length = padding_length });
    context->size -= (u64)padding_length;

    for (u32 i = 0; i < 14; i += 1)
    {
        input[i] = *(u32*)&context->input[i * 4];
    }
    input[14] = (u32)(context->size * 8);
    input[15] = (u32)((context->size * 8) >> 32);

    md5_step(context->buffer, input);

    MD5Result result;
    for (u32 i = 0; i < 4; i += 1)
    {
        result.hash[(i * 4) + 0] = (u8)((context->buffer[i] & 0x000000ff) >> 0);
        result.hash[(i * 4) + 1] = (u8)((context->buffer[i] & 0x0000ff00) >> 8);
        result.hash[(i * 4) + 2] = (u8)((context->buffer[i] & 0x00ff0000) >> 16);
        result.hash[(i * 4) + 3] = (u8)((context->buffer[i] & 0xff000000) >> 24);
    }

    return result;
}

MD5Result md5_string(String string)
{
    auto context = md5_init();
    md5_update(&context, string);
    auto result = md5_end(&context);
    return result;
}
