#include <metal_stdlib>
using namespace metal;

// Structs to match buffer data
struct RectVertex
{
    float2 p0;               // Bottom-left corner position
    float2 extent;           // Rectangle size (width and height)
    float2 uv0;              // UV coordinates for bottom-left
    float corner_radius;     // Corner radius
    float softness;          // Edge softness
    float4 colors[4];        // Per-vertex colors
    uint texture_index;      // Texture index
};

struct RectFragmentShaderInput
{
    float4 vertex_position [[position]];
    float4 color;            // Vertex color
    float2 uv;               // UV coordinates
    float2 position;         // Position in world space
    float2 center;           // Center of the rectangle
    float2 half_size;        // Half dimensions of the rectangle
    float corner_radius;     // Corner radius
    float softness;          // Edge softness
};

// Push constants (Metal uses constant buffers or argument buffers for this)
struct PushConstants
{
    device const RectVertex* vertex_buffer;
    float width;             // Screen width
    float height;            // Screen height
};

// Vertex shader main function
vertex RectFragmentShaderInput vertex_main(const device PushConstants& push_constants [[buffer(0)]], uint vertex_id [[vertex_id]])
{
    // Constants for normalized quad corners
    constexpr float2 vertices[] = {
        float2(-1.0, -1.0),
        float2( 1.0, -1.0),
        float2(-1.0,  1.0),
        float2( 1.0,  1.0)
    };

    // Fetch the vertex data from the buffer
    const RectVertex v = push_constants.vertex_buffer[vertex_id / 4];

    // Rectangle calculations
    float2 p0 = v.p0;
    float2 p1 = p0 + v.extent;
    float2 position_center = (p1 + p0) * 0.5;
    float2 half_size = (p1 - p0) * 0.5;
    float2 position = vertices[vertex_id % 4] * half_size + position_center;

    // Screen-space transformation
    float2 ndc_position = float2(2.0 * position.x / push_constants.width - 1.0,
                                 2.0 * position.y / push_constants.height - 1.0);

    // Texture UV calculations
    float2 uv0 = v.uv0;
    float2 uv1 = uv0 + v.extent;
    float2 texture_center = (uv1 + uv0) * 0.5;
    float2 uv = vertices[vertex_id % 4] * half_size + texture_center;

    // Output to fragment shader
    RectFragmentShaderInput out_data;
    out_data.color = v.colors[vertex_id % 4];
    out_data.uv = uv;
    out_data.position = position;
    out_data.vertex_position = float4(ndc_position.x, ndc_position.y, 0, 1);
    out_data.center = position_center;
    out_data.half_size = half_size;
    out_data.corner_radius = v.corner_radius;
    out_data.softness = v.softness;

    return out_data;
}

// Uniform buffer for textures
struct FragmentUniforms
{
    array<texture2d<float>, 100> textures; // Array of textures
    sampler texture_sampler;              // Sampler for texture sampling
};

// Calculate the signed distance field (SDF) for a rounded rectangle
float rounded_rect_sdf(float2 position, float2 center, float2 half_size, float radius)
{
    float2 r2 = float2(radius, radius);
    float2 d2_no_r2 = abs(center - position) - half_size;
    float2 d2 = d2_no_r2 + r2;
    float negative_euclidean_distance = min(max(d2.x, d2.y), 0.0);
    float positive_euclidean_distance = length(max(d2, 0.0));
    return negative_euclidean_distance + positive_euclidean_distance - radius;
}

// Fragment shader function
fragment float4 fragment_main(RectFragmentShaderInput inputs [[stage_in]], constant FragmentUniforms &uniforms [[buffer(0)]], uint texture_index)
{
    // Texture size
    float2 texture_size = float2(uniforms.textures[texture_index].get_width(), uniforms.textures[texture_index].get_height());
    float2 uv = float2(inputs.uv.x / texture_size.x, inputs.uv.y / texture_size.y);

    // Sample texture
    float4 sampled = uniforms.textures[texture_index].sample(uniforms.texture_sampler, uv);

    // Compute softness padding
    float softness = inputs.softness;
    float softness_padding_scalar = max(0.0, softness * 2.0 - 1.0);
    float2 softness_padding = float2(softness_padding_scalar, softness_padding_scalar);

    // Compute signed distance
    float distance = rounded_rect_sdf(inputs.position, inputs.center, inputs.half_size - softness_padding, inputs.corner_radius);

    // Compute SDF factor
    float sdf_factor = 1.0 - smoothstep(0.0, 2.0 * softness, distance);

    // Compute final color
    return inputs.color * sampled * sdf_factor;
}
