#include <std/image_loader.h>

#define STB_IMAGE_STATIC
#define STB_IMAGE_IMPLEMENTATION
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#include <stb_image.h>
#pragma clang diagnostic pop

EXPORT TextureMemory texture_load_from_file(Arena* arena, String path)
{
    auto file = file_read(arena, path);
    int width;
    int height;
    int channels;
    u8* buffer = stbi_load_from_memory(file.pointer, file.length, &width, &height, &channels, STBI_rgb_alpha);
    channels += 1;

    return (TextureMemory) {
        .pointer = buffer,
        .width = width,
        .height = height,
        .format = TEXTURE_FORMAT_R8G8B8A8_SRGB,
        .depth = 1,
    };
}
