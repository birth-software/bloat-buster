#version 450
#extension GL_EXT_nonuniform_qualifier : require
#extension GL_EXT_debug_printf : require
#extension GL_GOOGLE_include_directive : require

#include "rect.inc"

layout (location = 0) in flat uint texture_index;
layout (location = 1) in RectFragmentShaderInput inputs;

layout (location = 0) out vec4 color;

layout(set = 0, binding = 0) uniform sampler2D textures[];

float rounded_rect_sdf(vec2 position, vec2 center, vec2 half_size, float radius)
{
    vec2 r2 = vec2(radius, radius);
    // This is 0 when the point is at the border
    vec2 d2_no_r2 = abs(center - position) - half_size;
    vec2 d2 = d2_no_r2 + r2;
    // 0 when outside the rectangle
    float negative_euclidean_distance = min(max(d2.x, d2.y), 0.0);
    // 0 when inside the rectangle
    float positive_euclidean_distance = length(max(d2, 0.0));
    float result = negative_euclidean_distance + positive_euclidean_distance - radius;
    return result;
}

void main() 
{
    vec4 in_color = inputs.color;
    vec2 position = inputs.position;
    vec2 center = inputs.center;
    vec2 half_size = inputs.half_size;
    float corner_radius = inputs.corner_radius;
    float softness = inputs.softness;
    float border_thickness = inputs.border_thickness;
    vec2 in_uv = inputs.uv;

    // WARN: do not cache nonuniformEXT indexing
    vec2 texture_size = textureSize(textures[nonuniformEXT(texture_index)], 0);
    vec2 uv = vec2(in_uv.x / texture_size.x, in_uv.y / texture_size.y);
    // WARN: do not cache nonuniformEXT indexing
    vec4 sampled = texture(textures[nonuniformEXT(texture_index)], uv);

    // Rounded corner
    float softness_padding_scalar = max(0, softness * 2 - 1);
    vec2 softness_padding = vec2(softness_padding_scalar, softness_padding_scalar);
    float distance = rounded_rect_sdf(position, center, half_size - softness_padding, corner_radius);

    float sdf_factor = 1.0 - smoothstep(0, 2 * softness, distance);

    // Hollow
    vec2 interior_half_size = half_size - vec2(border_thickness);
    float interior_radius_reduce_factor = min(interior_half_size.x / half_size.x, interior_half_size.y / half_size.y);
    float interior_corner_radius = corner_radius * interior_radius_reduce_factor * interior_radius_reduce_factor;

    float inside_distance = rounded_rect_sdf(position, center, interior_half_size - softness_padding, interior_corner_radius);
    float inside_factor = smoothstep(0, 2 * softness, inside_distance);

    float border_factor = border_thickness == 0.0 ? 1.0 : inside_factor;

    color = color * sampled * sdf_factor * border_factor;
}
