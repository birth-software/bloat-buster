#include <lib.h>

#ifdef __x86_64__
#include <immintrin.h>
#endif

#include <stdio.h>
#ifdef __linux__
#include <unistd.h>
#include <liburing.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <time.h>
#include <sys/ptrace.h>
#elif _WIN32
#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#endif

STRUCT(ProtectionFlags)
{
    u64 read:1;
    u64 write:1;
    u64 execute:1;
};

STRUCT(MapFlags)
{
    u64 private:1;
    u64 anonymous:1;
    u64 no_reserve:1;
    u64 populate:1;
};

#ifdef __linux__
static int os_linux_protection_flags(ProtectionFlags flags)
{
    int result = 
        PROT_READ * flags.read |
        PROT_WRITE * flags.write |
        PROT_EXEC * flags.execute
    ;

    return result;
}

static int os_linux_map_flags(MapFlags flags)
{
    int result = 
        MAP_PRIVATE * flags.private |
        MAP_ANON * flags.anonymous |
        MAP_NORESERVE * flags.no_reserve |
        MAP_POPULATE * flags.populate;

    return result;
}
#elif _WIN32
#endif

static void* os_reserve(void* base, u64 size, ProtectionFlags protection, MapFlags map)
{
#ifdef __linux__
    let protection_flags = os_linux_protection_flags(protection);
    let map_flags = os_linux_map_flags(map);

    let address = mmap(base, size, protection_flags, map_flags, -1, 0);
    if (address == MAP_FAILED)
    {
        UNREACHABLE();
    }
    return address;
#elif _WIN32
    let result = VirtualAlloc(base, size, MEM_RESERVE, PAGE_READWRITE);
    return result;
#endif
}

static void os_commit(void* address, u64 size, ProtectionFlags protection)
{
#ifdef __linux__
    let protection_flags = os_linux_protection_flags(protection);
    let result = mprotect(address, size, protection_flags);
    assert(result == 0);
#elif _WIN32
    let result = VirtualAlloc(address, size, MEM_COMMIT, PAGE_READWRITE);
    assert(result != 0);
#endif
}

FileDescriptor* os_file_open(str path, OpenFlags flags, OpenPermissions permissions)
{
    assert(!path.pointer[path.length]);
    FileDescriptor* result = 0;
#if defined (__linux__)

    int o = 0;
    if (flags.read & flags.write)
    {
        o = O_RDWR;
    }
    else if (flags.read)
    {
        o = O_RDONLY;
    }
    else if (flags.write)
    {
        o = O_WRONLY;
    }
    else
    {
        UNREACHABLE();
    }

    o |= (flags.truncate) * O_TRUNC;
    o |= (flags.create) * O_CREAT;
    o |= (flags.directory) * O_DIRECTORY;

    mode_t mode = permissions.execute ? 0755 : 0644;
    int fd = open(path.pointer, o, mode);

    if (fd >= 0)
    {
        result = (void*)(u64)fd;
    }

    return result;
#elif _WIN32
    DWORD desired_access = 0;
    DWORD shared_mode = 0;
    SECURITY_ATTRIBUTES security_attributes = { sizeof(security_attributes), 0, 0 };
    DWORD creation_disposition = 0;
    DWORD flags_and_attributes = 0;
    HANDLE template_file = 0;

    if (flags.read)
    {
        desired_access |= GENERIC_READ;
    }

    if (flags.write)
    {
        desired_access |= GENERIC_WRITE;
    }

    if (flags.execute)
    {
        desired_access |= GENERIC_EXECUTE;
    }

    if (permissions.read)
    {
        shared_mode |= FILE_SHARE_READ;
    }
    
    if (permissions.write)
    {
        shared_mode |= FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    }

    if (permissions.write)
    {
        creation_disposition |= CREATE_ALWAYS;
    }
    else
    {
        creation_disposition |= OPEN_EXISTING;
    }

    let fd = CreateFileA(path.pointer, desired_access, shared_mode, &security_attributes, creation_disposition, flags_and_attributes, template_file);
    if (fd != INVALID_HANDLE_VALUE)
    {
        result = (FileDescriptor*)fd;
    }
    else
    {
        DWORD error = GetLastError();
        LPVOID msgBuffer;

        FormatMessageA(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL,
                error,
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPSTR)&msgBuffer,
                0,
                NULL
                );

        printf("Error %lu: %s\n", error, (char*)msgBuffer);
        LocalFree(msgBuffer);
    }
#endif
    return result;
}

static FileDescriptor* posix_fd_to_generic_fd(int fd)
{
    assert(fd >= 0);
    return (FileDescriptor*)(u64)(fd);
}

static int generic_fd_to_posix(FileDescriptor* fd)
{
    assert(fd);
    return (int)(u64)fd;
}

static void* generic_fd_to_windows(FileDescriptor* fd)
{
    assert(fd);
    return (void*)fd;
}

u64 os_file_get_size(FileDescriptor* file_descriptor)
{
#ifdef __linux__
    int fd = generic_fd_to_posix(file_descriptor);
    struct stat sb;
    let fstat_result = fstat(fd, &sb);
    assert(fstat_result == 0);

    return (u64)sb.st_size;
#elif _WIN32
    HANDLE fd = generic_fd_to_windows(file_descriptor);
    LARGE_INTEGER file_size = {};
    BOOL result = GetFileSizeEx(fd, &file_size);
    assert(result);
    return file_size.QuadPart;
#endif
}

static u64 os_file_read_partially(FileDescriptor* file_descriptor, void* buffer, u64 byte_count)
{
#ifdef __linux__
    let fd = generic_fd_to_posix(file_descriptor);
    let read_byte_count = read(fd, buffer, byte_count);
    assert(read_byte_count > 0);

    return (u64)read_byte_count;
#elif _WIN32
    let fd = generic_fd_to_windows(file_descriptor);
    DWORD read_byte_count = 0;
    BOOL result = ReadFile(fd, buffer, (u32)byte_count, &read_byte_count, 0);
    assert(result);
    return read_byte_count;
#endif
}

static void os_file_read(FileDescriptor* file_descriptor, str buffer, u64 byte_count)
{
    u64 read_byte_count = 0;
    char* pointer = buffer.pointer;
    assert(buffer.length >= byte_count);
    while (byte_count - read_byte_count)
    {
        read_byte_count += os_file_read_partially(file_descriptor, pointer + read_byte_count, byte_count - read_byte_count);
    }
}

static u64 os_file_write_partially(FileDescriptor* file_descriptor, void* pointer, u64 length)
{
#ifdef __linux__
    let fd = generic_fd_to_posix(file_descriptor);
    let result = write(fd, pointer, length);
    assert(result > 0);
    return result;
#elif _WIN32
    let fd = generic_fd_to_windows(file_descriptor);
    DWORD written_byte_count = 0;
    BOOL result = WriteFile(fd, pointer, (u32)length, &written_byte_count, 0);
    assert(result);
    return written_byte_count;
#endif
}

void os_file_write(FileDescriptor* file_descriptor, str buffer)
{
    u64 total_written_byte_count = 0;

    while (total_written_byte_count < buffer.length)
    {
        let written_byte_count = os_file_write_partially(file_descriptor, buffer.pointer + total_written_byte_count, buffer.length - total_written_byte_count);
        total_written_byte_count += written_byte_count;
    }
}

void os_file_close(FileDescriptor* file_descriptor)
{
#ifdef __linux__
    let fd = generic_fd_to_posix(file_descriptor);
    let close_result = close(fd);
    assert(close_result == 0);
#elif _WIN32
    let fd = generic_fd_to_windows(file_descriptor);
    let result = CloseHandle(fd);
    assert(result);
#endif
}

static u64 page_size = KB(4);
static u64 default_granularity = MB(2);

static u64 minimum_position = sizeof(Arena);

Arena* arena_initialize(ArenaInitialization initialization)
{
    if (!initialization.reserved_size)
    {
        initialization.reserved_size = GB(4);
    }

    if (!initialization.count)
    {
        initialization.count = 1;
    }

    let count = initialization.count;
    let individual_reserved_size = initialization.reserved_size;
    let total_reserved_size = individual_reserved_size * count;

    ProtectionFlags protection_flags = { .read = 1, .write = 1 };
    MapFlags map_flags = { .private = 1, .anonymous = 1, .no_reserve = 1, .populate = 0 };
    let raw_pointer = os_reserve(0, total_reserved_size, protection_flags, map_flags);

    if (!initialization.granularity)
    {
        initialization.granularity = default_granularity;
    }

    if (!initialization.initial_size)
    {
        initialization.initial_size = default_granularity * 4;
    }

    for (u64 i = 0; i < count; i += 1)
    {
        let arena = (Arena*)(raw_pointer + (individual_reserved_size * i));
        os_commit(raw_pointer, initialization.initial_size, protection_flags);
        *arena = (Arena){ 
            .reserved_size = individual_reserved_size,
            .position = minimum_position,
            .os_position = initialization.initial_size,
            .granularity = initialization.granularity,
        };
    }

    return (Arena*)raw_pointer;
}

void arena_align_bits()
{
}

void arena_set_position(Arena* arena, u64 position)
{
    arena->position = position;
}

void arena_reset_to_start(Arena* arena)
{
    arena_set_position(arena, minimum_position);
}

void* arena_allocate_bytes(Arena* arena, u64 size, u64 alignment)
{
    let aligned_offset = align_forward(arena->position, alignment);
    let aligned_size_after = aligned_offset + size;
    let arena_byte_pointer = (u8*)arena;
    let os_position = arena->os_position;

    if (unlikely(aligned_size_after > os_position))
    {
        let target_committed_size = align_forward(aligned_size_after, arena->granularity);
        let size_to_commit = target_committed_size - os_position;
        let commit_pointer = arena_byte_pointer + os_position;
        os_commit(commit_pointer, size_to_commit, (ProtectionFlags) { .read = 1, .write = 1 });
        arena->os_position = target_committed_size;
    }

    let result = arena_byte_pointer + aligned_offset;
    arena->position = aligned_size_after;
    assert(arena->position <= arena->os_position);

    return result;
}

str arena_join_string(Arena* arena, StringSlice strings)
{
    u64 size = 0;

    for (u64 i = 0; i < strings.length; i += 1)
    {
        str string = strings.pointer[i];
        size += string.length;
    }

    char* pointer = arena_allocate_bytes(arena, size + 1, 1);

    u64 i = 0;

    for (u64 i = 0; i < strings.length; i += 1)
    {
        str string = strings.pointer[i];
        memcpy(pointer + i, string.pointer, string.length);
        i += string.length;
    }

    assert(i == size);
    pointer[i] = 0;

    return str_from_ptr_len(pointer, size);
}

TimeDataType take_timestamp()
{
#ifdef __linux__
    struct timespec ts;
    let result = clock_gettime(CLOCK_MONOTONIC, &ts);
    assert(result == 0);
    return *(u128*)&ts;
#elif _WIN32
    LARGE_INTEGER c;
    BOOL result = QueryPerformanceCounter(&c);
    assert(result);
    return c.QuadPart;
#endif
}

static TimeDataType frequency;

u64 ns_between(TimeDataType start, TimeDataType end)
{
#ifdef __linux__
    let start_ts = *(struct timespec*)&start;
    let end_ts = *(struct timespec*)&end;
    let second_diff = end_ts.tv_sec - start_ts.tv_sec;
    let ns_diff = end_ts.tv_nsec - start_ts.tv_nsec;

    let result = second_diff * 1000000000LL + ns_diff;
    return result;
#elif _WIN32
    let ns = (f64)((end - start) * 1000 * 1000 * 1000) / frequency;
    return ns;
#endif
}

str file_read(Arena* arena, str path, FileReadOptions options)
{
    let fd = os_file_open(path, (OpenFlags) { .read = 1 }, (OpenPermissions){ .read = 1 });
    str result = {};

    if (fd)
    {
        let file_size = os_file_get_size(fd);
        let allocation_size = align_forward(file_size + options.start_padding + options.end_padding, options.end_alignment);
        let allocation_bottom = allocation_size - (file_size + options.start_padding);
        let allocation_alignment = MAX(options.start_alignment, 1);
        let file_buffer = arena_allocate_bytes(arena, allocation_size, allocation_alignment);
        os_file_read(fd, (str) { file_buffer + options.start_padding, file_size }, file_size);
        memset(file_buffer + options.start_padding + file_size, 0, allocation_bottom);
        os_file_close(fd);
        result = (str) { file_buffer + options.start_padding, file_size };
    }

    return result;
}

void os_init()
{
#ifdef _WIN32
    BOOL result = QueryPerformanceFrequency((LARGE_INTEGER*)&frequency);
    assert(result);
#else
#endif
}

static bool is_debugger_present()
{
    let result = ptrace(PTRACE_TRACEME, 0, 0, 0) == -1;
    return result;
}

[[noreturn]] void fail()
{
    if (is_debugger_present())
    {
        trap();
    }

    exit(1);
}
