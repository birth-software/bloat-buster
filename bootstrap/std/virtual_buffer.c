#include <std/virtual_buffer.h>
#include <std/os.h>

void vb_generic_ensure_capacity(VirtualBuffer(u8)* vb, u32 item_size, u32 item_count)
{
    u32 old_capacity = vb->capacity;
    u32 wanted_capacity = vb->length + item_count;

    if (old_capacity < wanted_capacity)
    {
        if (old_capacity == 0)
        {
            vb->pointer = os_reserve(0, item_size * UINT32_MAX, (OSReserveProtectionFlags) {}, (OSReserveMapFlags) { .priv = 1, .anon = 1, .noreserve = 1 });
        }

        u32 old_page_capacity = cast_to(u32, u64, align_forward(old_capacity * item_size, minimum_granularity));
        u32 new_page_capacity = cast_to(u32, u64, align_forward(wanted_capacity * item_size, minimum_granularity));

        u32 commit_size = new_page_capacity - old_page_capacity;
        void* commit_pointer = vb->pointer + old_page_capacity;

        os_commit(commit_pointer, commit_size);

        u32 new_capacity = new_page_capacity / item_size;
        vb->capacity = new_capacity;
    }
}

u8* vb_generic_add_assume_capacity(VirtualBuffer(u8)* vb, u32 item_size, u32 item_count)
{
    u32 index = vb->length;
    assert(vb->capacity >= index + item_count);
    vb->length = index + item_count;
    return vb->pointer + (index * item_size);
}

u8* vb_generic_add(VirtualBuffer(u8)* vb, u32 item_size, u32 item_count)
{
    vb_generic_ensure_capacity(vb, item_size, item_count);
    return vb_generic_add_assume_capacity(vb, item_size, item_count);
}

u8* vb_append_bytes(VirtualBuffer(u8*) vb, Slice(u8) bytes)
{
    auto len = cast_to(u32, u64, bytes.length);
    vb_generic_ensure_capacity(vb, sizeof(u8), len);
    auto* pointer = vb_generic_add_assume_capacity(vb, sizeof(u8), len);
    memcpy(pointer, bytes.pointer, len);
    return pointer;
}

void vb_copy_string(VirtualBuffer(u8)* buffer, String string)
{
    auto length = cast_to(u32, u64, string.length);
    auto* pointer = vb_add(buffer, length);
    memcpy(pointer, string.pointer, length);
}

u64 vb_copy_string_zero_terminated(VirtualBuffer(u8)* buffer, String string)
{
    assert(string.pointer[string.length] == 0);
    string.length += 1;

    vb_copy_string(buffer, string);

    return string.length;
}
