#include <std/ui_builder.h>
#include <std/render.h>

UI_Signal ui_button(String string)
{
    auto* widget = ui_widget_make((UI_WidgetFlags) {
        .draw_text = 1,
        .draw_background = 1,
        .mouse_clickable = 1,
        .keyboard_pressable = 1,
    }, string);

    UI_Signal signal = ui_signal_from_widget(widget);
    return signal;
}
