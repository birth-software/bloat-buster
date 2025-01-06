#pragma once

global_variable Renderer renderer_memory;

fn NSString* apple_string(String string)
{
    NSString* result = [[NSString alloc] initWithBytes:string.pointer length:string.length encoding:NSUTF8StringEncoding];
    return result;
}

fn Renderer* rendering_initialize(Arena* arena)
{
    Renderer* renderer = &renderer_memory;
    @autoreleasepool {
        renderer->device = MTLCreateSystemDefaultDevice();
        String shader_source = file_read(arena, strlit("bootstrap/std/shaders/rect.metal"));
        NSString* apple_shader_source = apple_string(shader_source);
        NSError* error = nil;
        id<MTLLibrary> library = [renderer->device newLibraryWithSource: apple_shader_source options:nil error:&error];
        if (!library)
        {
            // Inspect the error
            NSLog(@"Error Domain: %@", error.domain);
            NSLog(@"Error Code: %ld", (long)error.code);
            NSLog(@"Localized Description: %@", error.localizedDescription);

            NSDictionary *userInfo = error.userInfo;
            if (userInfo) {
                NSLog(@"Additional Info: %@", userInfo);
            }

            // Take action based on the error
            if ([error.domain isEqualToString:MTLLibraryErrorDomain]) {
                NSLog(@"Metal Library Compilation Error. Check the shader source.");
            } else {
                NSLog(@"Unexpected error occurred.");
            }
        }

        id<MTLFunction> vertex = [library newFunctionWithName:@"vertex_main"];
        id<MTLFunction> fragment = [library newFunctionWithName:@"fragment_main"];

        MTLRenderPipelineDescriptor* pipeline_descriptor = [[MTLRenderPipelineDescriptor alloc] init];
        pipeline_descriptor.vertexFunction = vertex;
        pipeline_descriptor.fragmentFunction = fragment;
        pipeline_descriptor.colorAttachments[0].pixelFormat = MTLPixelFormatBGRA8Unorm_sRGB;

        id<MTLRenderPipelineState> pipeline_state = [renderer->device newRenderPipelineStateWithDescriptor:pipeline_descriptor error:&error];

        if (!pipeline_state)
        {
            // Inspect the error
            NSLog(@"Error Domain: %@", error.domain);
            NSLog(@"Error Code: %ld", (long)error.code);
            NSLog(@"Localized Description: %@", error.localizedDescription);

            NSDictionary *userInfo = error.userInfo;
            if (userInfo) {
                NSLog(@"Additional Info: %@", userInfo);
            }
        }

        id<MTLCommandQueue> command_queue = [renderer->device newCommandQueue];
    }

    return renderer;
}

global_variable RenderWindow render_window_memory;

fn RenderWindow* rendering_initialize_window(Renderer* renderer, WindowingInstance* window)
{
    RenderWindow* render_window = &render_window_memory;

    CAMetalLayer* layer = [CAMetalLayer layer];
    render_window->layer = layer;
    layer.device = renderer->device;
    layer.pixelFormat = MTLPixelFormatBGRA8Unorm_sRGB;
    layer.framebufferOnly = true;
    layer.frame = window.frame;
    window.contentView.layer = layer;
    window.opaque = true;
    window.backgroundColor = nil;

    return render_window;
}

fn void renderer_window_frame_begin(Renderer* renderer, RenderWindow* window)
{
    @autoreleasepool {
        id<CAMetalDrawable> drawable = [window->layer nextDrawable];
        MTLRenderPassDescriptor* render_pass_descriptor = [MTLRenderPassDescriptor renderPassDescriptor];
        MTLRenderPassColorAttachmentDescriptor* color_attachment = render_pass_descriptor.colorAttachments[0];
        color_attachment.clearColor = MTLClearColorMake(1, 1, 1, 1);
        color_attachment.storeAction = MTLStoreActionStore;
        color_attachment.texture = drawable.texture;

        id<MTLCommandBuffer> command_buffer = [renderer->command_queue commandBuffer];

        id<MTLRenderCommandEncoder> render_command_encoder = [command_buffer renderCommandEncoderWithDescriptor:render_pass_descriptor];
        [render_command_encoder setRenderPipelineState: renderer->pipeline_state];
        [render_command_encoder drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:3];
        [render_command_encoder endEncoding];
        [command_buffer presentDrawable:drawable];
        [command_buffer commit];
    }
}

fn void renderer_window_frame_end(Renderer* renderer, RenderWindow* window)
{

    // todo();
}

fn TextureIndex renderer_texture_create(Renderer* renderer, TextureMemory texture_memory)
{
    todo();
}

fn void window_rect_texture_update_begin(RenderWindow* window)
{
    todo();
}

fn void renderer_queue_font_update(Renderer* renderer, RenderWindow* window, RenderFontType type, TextureAtlas atlas)
{
    todo();
}

fn void window_queue_rect_texture_update(RenderWindow* window, RectTextureSlot slot, TextureIndex texture_index)
{
    todo();
}

fn void window_rect_texture_update_end(Renderer* renderer, RenderWindow* window)
{
    todo();
}

fn void window_render_rect(RenderWindow* window, RectDraw draw)
{
    // todo();
}

fn void window_render_text(Renderer* renderer, RenderWindow* window, String string, float4 color, RenderFontType font_type, u32 x_offset, u32 y_offset)
{
    // todo();
}
