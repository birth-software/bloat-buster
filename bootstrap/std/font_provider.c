#include <std/font_provider.h>

#define STBTT_STATIC
#define STB_TRUETYPE_IMPLEMENTATION
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#include <stb_truetype.h>
#pragma clang diagnostic pop

TextureAtlas font_texture_atlas_create(Arena* arena, Renderer* renderer, TextureAtlasCreate create)
{
    auto font_file = file_read(arena, create.font_path);
    stbtt_fontinfo font_info;
    if (!stbtt_InitFont(&font_info, font_file.pointer, stbtt_GetFontOffsetForIndex(font_file.pointer, 0)))
    {
        failed_execution();
    }

    TextureAtlas result = {};
    u32 character_count = 256;
    result.characters = arena_allocate(arena, FontCharacter, character_count);
    result.kerning_tables = arena_allocate(arena, s32, character_count * character_count);
    result.height = (u32)sqrtf((f32)(create.text_height * create.text_height * character_count));
    result.width = result.height;
    result.pointer = arena_allocate(arena, u32, result.width * result.height);
    auto scale_factor = stbtt_ScaleForPixelHeight(&font_info, create.text_height);

    int ascent;
    int descent;
    int line_gap;
    stbtt_GetFontVMetrics(&font_info, &ascent, &descent, &line_gap);

    result.ascent = (u32)roundf(ascent * scale_factor);
    result.descent = (u32)roundf(descent * scale_factor);
    result.line_gap = (u32)roundf(line_gap * scale_factor);

    u32 x = 0;
    u32 y = 0;
    u32 max_row_height = 0;
    u32 first_character = ' ';
    u32 last_character = '~';

    for (auto i = first_character; i <= last_character; ++i)
    {
        u32 width;
        u32 height;
        int advance;
        int left_bearing;

        auto ch = (u8)i;
        auto* character = &result.characters[i];
        stbtt_GetCodepointHMetrics(&font_info, ch, &advance, &left_bearing);

        character->advance = (u32)roundf(advance * scale_factor);
        character->left_bearing = (u32)roundf(left_bearing * scale_factor);

        u8* bitmap = stbtt_GetCodepointBitmap(&font_info, 0.0f, scale_factor, ch, (int*)&width, (int*)&height, &character->x_offset, &character->y_offset);
        auto* kerning_table = result.kerning_tables + i * character_count; 
        for (u32 j = first_character; j <= last_character; j += 1)
        {
            auto kerning_advance = stbtt_GetCodepointKernAdvance(&font_info, i, j);
            kerning_table[j] = (s32)roundf(kerning_advance * scale_factor);
        }

        if (x + width > result.width)
        {
            y += max_row_height;
            max_row_height = height;
            x = 0;
        }
        else
        {
            max_row_height = MAX(height, max_row_height);
        }

        character->x = x;
        character->y = y;
        character->width = width;
        character->height = height;

        auto* source = bitmap;
        auto* destination = result.pointer;

        for (u32 bitmap_y = 0; bitmap_y < height; bitmap_y += 1)
        {
            for (u32 bitmap_x = 0; bitmap_x < width; bitmap_x += 1)
            {
                auto source_index = bitmap_y * width + bitmap_x;
                auto destination_index = (bitmap_y + y) * result.width + (bitmap_x + x);
                auto value = source[source_index];
                destination[destination_index] = ((u32)value << 24) | 0xffffff;
            }
        }

        x += width;

        stbtt_FreeBitmap(bitmap, 0);
    }

    result.texture = renderer_texture_create(renderer, (TextureMemory) {
        .pointer = result.pointer,
        .width = result.width,
        .height = result.height,
        .depth = 1,
        .format = TEXTURE_FORMAT_R8G8B8A8_SRGB,
    });

    return result;
}

uint2 texture_atlas_compute_string_rect(String string, const TextureAtlas* atlas)
{
    auto height = atlas->ascent - atlas->descent;
    u32 x_offset = 0;
    u32 y_offset = height;

    for (u64 i = 0; i < string.length; i += 1)
    {
        auto ch = string.pointer[i];
        auto* character = &atlas->characters[ch];
        auto kerning = (atlas->kerning_tables + ch * 256)[string.pointer[i + 1]];
        x_offset += character->advance + kerning;
    }

    return (uint2) { x_offset, y_offset };
}
