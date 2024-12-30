#pragma once

STRUCT(FontCharacter)
{
    u32 advance;
    u32 left_bearing;
    u32 x;
    u32 y;
    u32 width;
    u32 height;
    s32 x_offset;
    s32 y_offset;
};

STRUCT(TextureAtlas)
{
    u32* pointer;
    FontCharacter* characters;
    s32* kerning_tables;
    u32 width;
    u32 height;
    s32 ascent;
    s32 descent;
    s32 line_gap;
    TextureIndex texture;
};

STRUCT(TextureAtlasCreate)
{
    String font_path;
    u32 text_height;
};

fn TextureAtlas font_texture_atlas_create(Arena* arena, Renderer* renderer, TextureAtlasCreate create);
fn uint2 texture_atlas_compute_string_rect(String string, const TextureAtlas* atlas);
