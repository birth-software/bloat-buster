#pragma once

#include <std/base.h>

#define VirtualBuffer(T) VirtualBuffer_ ## T
#define VirtualBufferP(T) VirtualBufferPointerTo_ ## T

#define decl_vb_ex(T, StructName) \
struct StructName \
{\
    T* pointer;\
    u32 length;\
    u32 capacity;\
};\
typedef struct StructName StructName

#define decl_vb(T) decl_vb_ex(T, VirtualBuffer(T))
#define decl_vbp(T) decl_vb_ex(T*, VirtualBufferP(T))

decl_vb(u8);
decl_vbp(u8);
decl_vb(u16);
decl_vbp(u16);
decl_vb(u32);
decl_vbp(u32);
decl_vb(s32);
decl_vbp(s32);
decl_vb(s64);
decl_vbp(s64);
decl_vb(String);
decl_vbp(char);
decl_vb(f32);
decl_vb(f64);

#define vb_size_of_element(vb) sizeof(*((vb)->pointer))
#define vb_add(vb, count) (typeof((vb)->pointer)) vb_generic_add((VirtualBuffer(u8)*)(vb), (vb_size_of_element(vb)), (count))
#define vb_add_scalar(vb, S) (S*) vb_generic_add(vb, 1, sizeof(S))
#define vb_copy_scalar(vb, s) *vb_add_scalar(vb, typeof(s)) = s
#define vb_append_struct(vb, T, s) *(vb_add_struct(vb, T)) = s
#define vb_append_one(vb, item) (typeof((vb)->pointer)) vb_generic_append((VirtualBuffer(u8)*)(vb), &(item), (vb_size_of_element(vb)), 1)
#define vb_to_bytes(vb) (Slice(u8)) { .pointer = (u8*)((vb).pointer), .length = (vb_size_of_element(vb)) * (vb).length, }
#define vb_ensure_capacity(vb, count) vb_generic_ensure_capacity((VirtualBuffer(u8)*)(vb), vb_size_of_element(vb), (count))
#define vb_copy_array(vb, arr) memcpy(vb_add(vb, array_length(arr)), arr, sizeof(arr))
#define vb_add_any_array(vb, E, count) (E*)vb_generic_add(vb, vb_size_of_element(vb), sizeof(E) * count)
#define vb_copy_any_array(vb, arr) memcpy(vb_generic_add(vb, vb_size_of_element(vb), sizeof(arr)), (arr), sizeof(arr))
#define vb_copy_any_slice(vb, slice) memcpy(vb_generic_add(vb, vb_size_of_element(vb), sizeof(*((slice).pointer)) * (slice).length), (slice).pointer, sizeof(*((slice).pointer)) * (slice).length)

fn void vb_generic_ensure_capacity(VirtualBuffer(u8)* vb, u32 item_size, u32 item_count);
fn u8* vb_generic_add_assume_capacity(VirtualBuffer(u8)* vb, u32 item_size, u32 item_count);
fn u8* vb_generic_add(VirtualBuffer(u8)* vb, u32 item_size, u32 item_count);
fn u8* vb_append_bytes(VirtualBuffer(u8*) vb, Slice(u8) bytes);
fn void vb_copy_string(VirtualBuffer(u8)* buffer, String string);
fn u64 vb_copy_string_zero_terminated(VirtualBuffer(u8)* buffer, String string);
