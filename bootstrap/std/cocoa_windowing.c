#pragma once
// TODO: organize better

@interface AppleApplicationDelegate : NSObject<NSApplicationDelegate>
@end
@interface AppleWindow : NSWindow
@end
@interface AppleWindowDelegate : NSObject<NSWindowDelegate>
@end

@implementation AppleApplicationDelegate
- (void)applicationDidFinishLaunching:(NSNotification*)aNotification
{
    trap();
}

@end
@implementation AppleWindow
@end

fn u8 windowing_initialize()
{
    u8 result = 1;
    [NSApplication sharedApplication];
    AppleApplicationDelegate* application_delegate; 
    application_delegate = [[AppleApplicationDelegate alloc] init];
    NSApp.delegate = application_delegate;
    [NSApp run];

    return result;
}

fn OSWindow window_create(WindowCreate create)
{
}

fn void windowing_poll_events()
{
}
