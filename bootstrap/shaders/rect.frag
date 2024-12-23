#version 450
#extension GL_EXT_nonuniform_qualifier : require
#extension GL_EXT_debug_printf : require
#extension GL_GOOGLE_include_directive : require

#include "rect.h"

layout (location = 0) in flat uint texture_index;
layout (location = 1) in FragmentShaderInput inputs;

layout (location = 0) out vec4 color;

layout(set = 0, binding = 0) uniform sampler2D textures[];

void main() 
{
    vec2 texture_size = textureSize(textures[nonuniformEXT(texture_index)], 0);
    vec2 uv = vec2(inputs.uv.x / texture_size.x, inputs.uv.y / texture_size.y);
    vec4 sampled = texture(textures[nonuniformEXT(texture_index)], uv);
    color = inputs.color * sampled;
}
