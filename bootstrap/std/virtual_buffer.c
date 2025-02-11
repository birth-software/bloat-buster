#pragma once

fn void vb_generic_ensure_capacity(VirtualBuffer(u8)* vb, u32 item_size, u32 item_count)
{
    u32 old_capacity = vb->capacity;
    u32 wanted_capacity = vb->length + item_count;

    if (old_capacity < wanted_capacity)
    {
        if (old_capacity == 0)
        {
            vb->pointer = os_reserve(0, item_size * UINT32_MAX, (OSReserveProtectionFlags) {}, (OSReserveMapFlags) { .priv = 1, .anon = 1, .noreserve = 1 });
        }

        let_cast(u32, old_page_capacity, align_forward_u64(old_capacity * item_size, minimum_granularity));
        let_cast(u32, new_page_capacity, align_forward_u64(wanted_capacity * item_size, minimum_granularity));

        let(commit_size, new_page_capacity - old_page_capacity);
        void* commit_pointer = vb->pointer + old_page_capacity;

        os_commit(commit_pointer, commit_size);

        let(new_capacity, new_page_capacity / item_size);
        vb->capacity = new_capacity;
    }
}

fn u8* vb_generic_add_assume_capacity(VirtualBuffer(u8)* vb, u32 item_size, u32 item_count)
{
    u32 index = vb->length;
    assert(vb->capacity >= index + item_count);
    vb->length = index + item_count;
    return vb->pointer + (index * item_size);
}

fn u8* vb_generic_add(VirtualBuffer(u8)* vb, u32 item_size, u32 item_count)
{
    vb_generic_ensure_capacity(vb, item_size, item_count);
    return vb_generic_add_assume_capacity(vb, item_size, item_count);
}

fn u8* vb_append_bytes(VirtualBuffer(u8*) vb, Slice(u8) bytes)
{
    let_cast(u32, len, bytes.length);
    vb_generic_ensure_capacity(vb, sizeof(u8), len);
    let(pointer, vb_generic_add_assume_capacity(vb, sizeof(u8), len));
    memcpy(pointer, bytes.pointer, len);
    return pointer;
}

fn u32 vb_copy_string(VirtualBuffer(u8)* buffer, String string)
{
    let(offset, buffer->length);
    let_cast(u32, length, string.length);
    let(pointer, vb_add(buffer, length));
    memcpy(pointer, string.pointer, length);
    return offset;
}

fn u64 vb_copy_string_zero_terminated(VirtualBuffer(u8)* buffer, String string)
{
    assert(string.pointer[string.length] == 0);
    string.length += 1;

    vb_copy_string(buffer, string);

    return string.length;
}

fn void vb_copy_byte_repeatedly(VirtualBuffer(u8)* buffer, u8 byte, u32 times)
{
    u8* ptr = vb_generic_add(buffer, 1, times);
    memset(ptr, byte, times);
}

fn u64 vb_format(VirtualBuffer(u8)* vb, const char* format, ...)
{
    u8 buffer[4096];
    va_list args;
    va_start(args, format);
    let(result, format_string_va((String)array_to_slice(buffer), format, args));
    va_end(args);

    assert(result.length <= array_length(buffer));
    vb_copy_string(vb, result);

    return result.length;
}
