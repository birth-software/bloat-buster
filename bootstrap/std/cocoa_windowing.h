#pragma once

#import <Cocoa/Cocoa.h>
#import <QuartzCore/CAMetalLayer.h>

@interface AppleApplicationDelegate : NSObject<NSApplicationDelegate>
@end
@interface AppleWindow : NSWindow
@end
@interface AppleWindowDelegate : NSObject<NSWindowDelegate>
@end

typedef AppleWindow WindowingInstance;

STRUCT(WindowConnection)
{
    NSApplication* application;
};
