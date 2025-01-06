#pragma once

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN 1
#include <Windows.h>
#else
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/ptrace.h>
#endif

typedef enum TimeUnit
{
    TIME_UNIT_NANOSECONDS,
    TIME_UNIT_MICROSECONDS,
    TIME_UNIT_MILLISECONDS,
    TIME_UNIT_SECONDS,
} TimeUnit;

STRUCT(RunCommandOptions)
{
    u64 debug:1;
};

STRUCT(Timestamp)
{
    u128 value;
};

STRUCT(OSFileOpenFlags)
{
    u32 truncate:1;
    u32 executable:1;
    u32 write:1;
    u32 read:1;
    u32 create:1;
    u32 directory:1;
};

STRUCT(OSFilePermissions)
{
    u8 readable:1;
    u8 writable:1;
    u8 executable:1;
};

STRUCT(OSReserveProtectionFlags)
{
    u32 read:1;
    u32 write:1;
    u32 execute:1;
    u32 reserved:29;
};

STRUCT(OSReserveMapFlags)
{
    u32 priv:1;
    u32 anon:1;
    u32 noreserve:1;
    u32 reserved:29;
};

STRUCT(Arena)
{
    u64 reserved_size;
    u64 position;
    u64 os_position;
    u64 granularity;
    u8 reserved[4 * 8];
};

STRUCT(FileWriteOptions)
{
    String path;
    String content;
    u64 executable:1;
};

#ifndef __APPLE__
#define MY_PAGE_SIZE KB(4)
#else
#define MY_PAGE_SIZE KB(16)
#endif
global_variable const u64 page_size = MY_PAGE_SIZE;

global_variable u64 minimum_granularity = MY_PAGE_SIZE;
// global_variable u64 middle_granularity = MB(2);
global_variable u64 default_size = GB(4);

fn void vprint(const char* format, va_list args);
fn void print(const char* format, ...);
fn void run_command(Arena* arena, CStringSlice arguments, char* envp[], RunCommandOptions options);
fn String file_read(Arena* arena, String path);
fn void file_write(FileWriteOptions options);

fn String path_dir(String string);
fn String path_base(String string);
fn String path_no_extension(String string);


fn Arena* arena_initialize(u64 reserved_size, u64 granularity, u64 initial_size);
fn Arena* arena_initialize_default(u64 initial_size);
fn void arena_clear(Arena* arena);
fn String arena_join_string(Arena* arena, Slice(String) pieces);
fn u8* arena_allocate_bytes(Arena* arena, u64 size, u64 alignment);
fn void arena_reset(Arena* arena);

#define arena_allocate(arena, T, count) (T*)(arena_allocate_bytes(arena, sizeof(T) * count, alignof(T)))
#define arena_allocate_slice(arena, T, count) (Slice(T)){ .pointer = arena_allocate(arena, T, count), .length = count }

fn u8* os_reserve(u64 base, u64 size, OSReserveProtectionFlags protection, OSReserveMapFlags map);
fn void os_commit(void* address, u64 size);

fn u8 os_file_descriptor_is_valid(FileDescriptor fd);
fn FileDescriptor os_file_open(String path, OSFileOpenFlags flags, OSFilePermissions permissions);
fn void os_file_close(FileDescriptor fd);
fn u64 os_file_get_size(FileDescriptor fd);
fn void os_file_write(FileDescriptor fd, String content);
fn FileDescriptor os_stdout_get();
fn void os_directory_make(String path);
BB_NORETURN BB_COLD fn void os_exit(u32 exit_code);

fn void calibrate_cpu_timer();

fn void print_string(String string);

fn Timestamp os_timestamp();
fn f64 os_resolve_timestamps(Timestamp start, Timestamp end, TimeUnit time_unit);
fn u8 os_is_being_debugged();

#if _WIN32
typedef void* HANDLE;
fn HANDLE os_windows_get_module_handle();
#endif

#if _WIN32
#define EXECUTABLE_EXTENSION ".exe"
#else
#define EXECUTABLE_EXTENSION ""
#endif

STRUCT(OSLibrary)
{
    void* handle;
};

typedef void* OSSymbol;

fn OSLibrary os_library_load(const char* library_name);
fn OSSymbol os_symbol_load(OSLibrary library, const char* symbol_name);
