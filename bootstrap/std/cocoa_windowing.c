#pragma once

@implementation AppleApplicationDelegate
- (void)applicationDidFinishLaunching:(NSNotification*)aNotification
{
}

@end
@implementation AppleWindow
@end

global_variable WindowConnection window_connection;

fn u8 windowing_initialize()
{
    u8 result = 1;
    window_connection.application = [NSApplication sharedApplication];
    AppleApplicationDelegate* application_delegate = [[AppleApplicationDelegate alloc] init];
    NSApp.delegate = application_delegate;

    return result;
}

fn WindowingInstance* windowing_instantiate(WindowingInstantiate instantiate)
{
    NSRect rect = { { 0, 0 }, { 800, 600 } };
    AppleWindow* window = [[AppleWindow alloc] initWithContentRect:rect styleMask:(NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskResizable) backing:NSBackingStoreBuffered defer:NO];
    window.title = @"Hello Metal";
    [window_connection.application activate];
    [window orderFrontRegardless];
    return window;
}

fn WindowingSize windowing_get_instance_framebuffer_size(WindowingInstance* instance)
{
    WindowingSize size;
    @autoreleasepool {
        const NSRect contentRect = instance.contentView.frame;
        const NSRect fbRect = [instance.contentView convertRectToBacking:contentRect];

        size = (WindowingSize) {
            .width = fbRect.size.width,
            .height = fbRect.size.height,
        };
    } // autoreleasepool
    return size;
}

fn void windowing_poll_events()
{
    @autoreleasepool {
        while (1)
        {
            NSEvent* event = [NSApp nextEventMatchingMask:NSEventMaskAny untilDate:[NSDate distantPast] inMode:NSDefaultRunLoopMode dequeue:YES];

            if (event == nil)
            {
                break;
            }

            [NSApp sendEvent:event];
        }

    } // autoreleasepool
}
