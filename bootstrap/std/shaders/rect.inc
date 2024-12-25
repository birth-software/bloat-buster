struct RectVertex
{
    vec2 p0;
    vec2 uv0;
    vec2 extent;
    float corner_radius;
    float softness;
    vec4 colors[4];
    uint texture_index;
    uint reserved[3];
}; 

struct RectFragmentShaderInput
{
    vec4 color;
    vec2 uv;
    vec2 position;
    vec2 center;
    vec2 half_size;
    float corner_radius;
    float softness;
};
