#pragma once

fn UI_Signal ui_button(String string)
{
    let(widget, ui_widget_make((UI_WidgetFlags) {
        .draw_text = 1,
        .draw_background = 1,
        .mouse_clickable = 1,
        .keyboard_pressable = 1,
    }, string));

    UI_Signal signal = ui_signal_from_widget(widget);
    return signal;
}
