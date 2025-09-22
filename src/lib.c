#pragma once

#include <lib.h>

#ifdef __x86_64__
#include <immintrin.h>
#endif

#include <stdio.h>

#ifdef __linux__
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <pthread.h>
#elif defined(__APPLE__)
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <pthread.h>
#elif _WIN32
#define WIN32_LEAN_AND_MEAN 1
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
LOCAL RIO_EXTENSION_FUNCTION_TABLE w32_rio_functions = {};
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

#if defined (__linux__) || defined(__APPLE__)
LOCAL int os_posix_protection_flags(ProtectionFlags flags)
{
    int result = 
        PROT_READ * flags.read |
        PROT_WRITE * flags.write |
        PROT_EXEC * flags.execute
    ;

    return result;
}

LOCAL int os_posix_map_flags(MapFlags flags)
{
    int result = 
#ifdef __linux__
        MAP_POPULATE * flags.populate |
#endif
        MAP_PRIVATE * flags.private |
        MAP_ANON * flags.anonymous |
        MAP_NORESERVE * flags.no_reserve;

    return result;
}
#elif _WIN32
LOCAL DWORD os_windows_protection_flags(ProtectionFlags flags)
{
    DWORD result = 0;

    if (flags.read & flags.write & flags.execute)
    {
        result = PAGE_EXECUTE_READWRITE;
    }
    else if (flags.read & flags.write)
    {
        result = PAGE_READWRITE;
    }
    else if (flags.read & flags.execute)
    {
        result = PAGE_EXECUTE_READ;
    }
    else if (flags.read)
    {
        result = PAGE_READONLY;
    }
    else if (flags.execute)
    {
        result = PAGE_EXECUTE;
    }
    else
    {
        UNREACHABLE();
    }

    return result;
}

LOCAL DWORD os_windows_allocation_flags(MapFlags flags)
{
    DWORD result = 0;
    result |= MEM_RESERVE;

    if (!flags.no_reserve)
    {
        result |= MEM_COMMIT;
    }

    return result;
}
#endif

LOCAL bool os_lock_and_unlock(void* address, u64 size)
{
    bool result = 1;

#if defined (__linux__) || defined(__APPLE__)
    let os_result = mlock(address, size);
    result = os_result == 0;
    if (result)
    {
        os_result = munlock(address, size);
    }
    result = os_result == 0;
#elif defined(_WIN32)
    RIO_BUFFERID buffer_id = w32_rio_functions.RIORegisterBuffer(address, size);
    result = buffer_id != RIO_INVALID_BUFFERID;
    if (result)
    {
        w32_rio_functions.RIODeregisterBuffer(buffer_id);
    }
#endif
    return result;
}

LOCAL void* os_reserve(void* base, u64 size, ProtectionFlags protection, MapFlags map)
{
    void* address = 0;

#if defined(__linux__) || defined(__APPLE__)
    let protection_flags = os_posix_protection_flags(protection);
    let map_flags = os_posix_map_flags(map);

    address = mmap(base, size, protection_flags, map_flags, -1, 0);
    if (address == MAP_FAILED)
    {
        address = 0;
    }
#elif _WIN32
    let allocation_flags = os_windows_allocation_flags(map);
    let protection_flags = os_windows_protection_flags(protection);
    address = VirtualAlloc(base, size, allocation_flags, protection_flags);
#endif
    return address;
}

LOCAL bool os_unreserve(void* address, u64 size)
{
    bool result = 1;
#if defined(__linux__) || defined(__APPLE__)
    let unmap_result = munmap(address, size);
    result = unmap_result == 0;
#elif _WIN32
    let virtual_free_result = VirtualFree(address, size, MEM_DECOMMIT);
    result = virtual_free_result != 0;
    if (result)
    {
        virtual_free_result = VirtualFree(address, 0, MEM_RELEASE);
        result = virtual_free_result != 0;
    }
#endif
    return result;
}

LOCAL bool os_commit(void* address, u64 size, ProtectionFlags protection, bool lock)
{
    bool result = 1;

#if defined(__linux__) || defined(__APPLE__)
    let protection_flags = os_posix_protection_flags(protection);
    let os_result = mprotect(address, size, protection_flags);
    result = os_result == 0;
#elif _WIN32
    let protection_flags = os_windows_protection_flags(protection);
    let os_result = VirtualAlloc(address, size, MEM_COMMIT, protection_flags);
    result = os_result != 0;
#endif

    if (result & lock)
    {
        result = os_lock_and_unlock(address, size);
    }

    return result;
}

FileDescriptor* os_file_open(str path, OpenFlags flags, OpenPermissions permissions)
{
    assert(!path.pointer[path.length]);
    FileDescriptor* result = 0;
#if defined (__linux__) || defined(__APPLE__)
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

LOCAL FileDescriptor* posix_fd_to_generic_fd(int fd)
{
    assert(fd >= 0);
    return (FileDescriptor*)(u64)(fd);
}

LOCAL int generic_fd_to_posix(FileDescriptor* fd)
{
    assert(fd);
    return (int)(u64)fd;
}

LOCAL void* generic_fd_to_windows(FileDescriptor* fd)
{
    assert(fd);
    return (void*)fd;
}

u64 os_file_get_size(FileDescriptor* file_descriptor)
{
#if defined(__linux__) || defined(__APPLE__)
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

LOCAL u64 os_file_read_partially(FileDescriptor* file_descriptor, void* buffer, u64 byte_count)
{
#if defined(__linux__) || defined(__APPLE__)
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

LOCAL void os_file_read(FileDescriptor* file_descriptor, str buffer, u64 byte_count)
{
    u64 read_byte_count = 0;
    char* pointer = buffer.pointer;
    assert(buffer.length >= byte_count);
    while (byte_count - read_byte_count)
    {
        read_byte_count += os_file_read_partially(file_descriptor, pointer + read_byte_count, byte_count - read_byte_count);
    }
}

LOCAL u64 os_file_write_partially(FileDescriptor* file_descriptor, void* pointer, u64 length)
{
#if defined(__linux__) || defined(__APPLE__)
    let fd = generic_fd_to_posix(file_descriptor);
    let result = write(fd, pointer, length);
    assert(result > 0);
    return result;
#elif defined(_WIN32)
    let fd = generic_fd_to_windows(file_descriptor);
    DWORD written_byte_count = 0;
    BOOL result = WriteFile(fd, pointer, (u32)length, &written_byte_count, 0);
    assert(result);
    return written_byte_count;
#endif
}

FileDescriptor* os_get_stdout()
{
    FileDescriptor* result = {};
#if defined(__linux__) || defined(__APPLE__)
    result = posix_fd_to_generic_fd(1);
#elif defined(_WIN32)
    result = (FileDescriptor*)GetStdHandle(STD_OUTPUT_HANDLE);
#endif
    return result;
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
#if defined(__linux__) || defined(__APPLE__)
    let fd = generic_fd_to_posix(file_descriptor);
    let close_result = close(fd);
    assert(close_result == 0);
#elif _WIN32
    let fd = generic_fd_to_windows(file_descriptor);
    let result = CloseHandle(fd);
    assert(result);
#endif
}

LOCAL u64 page_size = KB(4);
LOCAL u64 default_granularity = MB(2);

LOCAL u64 minimum_position = sizeof(Arena);

LOCAL bool arena_lock_pages = true;

LOCAL u64 default_reserve_size = GB(4);
LOCAL u64 initial_size_granularity_factor = 4;

Arena* arena_create(ArenaInitialization initialization)
{
    if (!initialization.reserved_size)
    {
        initialization.reserved_size = default_reserve_size;
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
        initialization.initial_size = default_granularity * initial_size_granularity_factor;
    }

    for (u64 i = 0; i < count; i += 1)
    {
        let arena = (Arena*)(raw_pointer + (individual_reserved_size * i));
        os_commit(arena, initialization.initial_size, protection_flags, arena_lock_pages);
        *arena = (Arena){ 
            .reserved_size = individual_reserved_size,
            .position = minimum_position,
            .os_position = initialization.initial_size,
            .granularity = initialization.granularity,
        };
    }

    return (Arena*)raw_pointer;
}

bool arena_destroy(Arena* arena, u64 count)
{
    count = count == 0 ? 1 : count;
    let reserved_size = arena->reserved_size;
    let size = reserved_size * count;
    return os_unreserve(arena, size);
}

void arena_set_position(Arena* arena, u64 position)
{
    arena->position = position;
}

void arena_reset_to_start(Arena* arena)
{
    arena_set_position(arena, minimum_position);
}

void* arena_current_pointer(Arena* arena, u64 alignment)
{
    return (u8*)arena + align_forward(arena->position, alignment);
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
        os_commit(commit_pointer, size_to_commit, (ProtectionFlags) { .read = 1, .write = 1 }, arena_lock_pages);
        arena->os_position = target_committed_size;
    }

    let result = arena_byte_pointer + aligned_offset;
    arena->position = aligned_size_after;
    assert(arena->position <= arena->os_position);

    return result;
}

str arena_join_string(Arena* arena, StringSlice strings, bool zero_terminate)
{
    u64 size = 0;

    for (u64 i = 0; i < strings.length; i += 1)
    {
        str string = strings.pointer[i];
        size += string.length;
    }

    char* pointer = arena_allocate_bytes(arena, size + zero_terminate, 1);

    u64 i = 0;

    for (u64 index = 0; index < strings.length; index += 1)
    {
        str string = strings.pointer[index];
        memcpy(pointer + i, string.pointer, string.length);
        i += string.length;
    }

    assert(i == size);
    if (zero_terminate)
    {
        pointer[i] = 0;
    }

    return str_from_ptr_len(pointer, size);
}

str arena_duplicate_string(Arena* arena, str str, bool zero_terminate)
{
    char* pointer = arena_allocate_bytes(arena, str.length + zero_terminate, 1);
    memcpy(pointer, str.pointer, str.length);
    if (zero_terminate)
    {
        pointer[str.length] = 0;
    }

    return str_from_ptr_len(pointer, str.length);
}

TimeDataType take_timestamp()
{
#if defined(__linux__) || defined(__APPLE__)
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

LOCAL TimeDataType frequency;

u64 ns_between(TimeDataType start, TimeDataType end)
{
#if defined(__linux__) || defined(__APPLE__)
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
        if (!options.start_alignment)
        {
            options.start_alignment = 1;
        }

        if (!options.end_alignment)
        {
            options.end_alignment = 1;
        }

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

LOCAL str os_path_absolute_stack(str buffer, const char* restrict relative_file_path)
{
    str result = {};
#if defined(__linux__) || defined(__APPLE__)
    let syscall_result = realpath(relative_file_path, buffer.pointer);

    if (syscall_result)
    {
        result = str_from_ptr_len(syscall_result, strlen(syscall_result));
        assert(result.length < buffer.length);
    }

#elif defined(_WIN32)
    DWORD length = GetFullPathNameA(relative_file_path, buffer.length, buffer.pointer, 0);
    if (length <= buffer.length)
    {
        result = (str){buffer.pointer, length};
    }
#endif
    return result;
}

str path_absolute(Arena* arena, const char* restrict relative_file_path)
{
    char buffer[4096];
    let stack_slice = os_path_absolute_stack((str){buffer, array_length(buffer)}, relative_file_path);
    let result = arena_duplicate_string(arena, stack_slice, true);
    return result;
}

void os_init()
{
#ifdef _WIN32
    BOOL result = QueryPerformanceFrequency((LARGE_INTEGER*)&frequency);
    assert(result);

    WSADATA WinSockData;
    WSAStartup(MAKEWORD(2, 2), &WinSockData);
    GUID guid = WSAID_MULTIPLE_RIO;
    DWORD rio_byte = 0;
    SOCKET Sock = socket(AF_UNSPEC, SOCK_STREAM, IPPROTO_TCP);
    WSAIoctl(Sock, SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid), (void**)&w32_rio_functions, sizeof(w32_rio_functions), &rio_byte, 0, 0);
    closesocket(Sock);
#else
#endif
}

LOCAL bool is_debugger_present_called = false;
LOCAL bool _is_debugger_present = false;

LOCAL bool is_debugger_present()
{
    if (unlikely(!is_debugger_present_called))
    {
        is_debugger_present_called = true;
#if defined(__linux__)
        let os_result = ptrace(PTRACE_TRACEME, 0, 0, 0) == -1;
        _is_debugger_present = os_result != 0;
#elif defined(__APPLE__)
#elif defined(_WIN32)
        let os_result = IsDebuggerPresent();
        _is_debugger_present = os_result != 0;
#else
    trap();
#endif
    }

    return _is_debugger_present;
}

[[noreturn]] void fail()
{
    if (is_debugger_present())
    {
        trap();
    }

    exit(1);
}

LOCAL void str_reverse(str s)
{
    char* restrict pointer = s.pointer;
    for (u64 i = 0, reverse_i = s.length - 1; i < reverse_i; i += 1, reverse_i -= 1)
    {
        let ch = pointer[i];
        pointer[i] = pointer[reverse_i];
        pointer[reverse_i] = ch;
    }
}

LOCAL str format_integer_hexadecimal(str buffer, u64 value)
{
    str result = {};

    if (value == 0)
    {
        buffer.pointer[0] = '0';
        result = (str) { buffer.pointer, 1};
    }
    else
    {
        let v = value;
        u64 i = 0;

        while (v != 0)
        {
            let digit = v % 16;
            let ch = (u8)(digit > 9 ? (digit - 10 + 'a') : (digit + '0'));
            assert(i < buffer.length);
            buffer.pointer[i] = ch;
            i += 1;
            v = v / 16;
        }

        let length = i;

        result = (str) { buffer.pointer , length };
        str_reverse(result);
    }

    return result;
}

LOCAL str format_integer_decimal(str buffer, u64 value, bool treat_as_signed)
{
    str result = {};

    if (value == 0)
    {
        buffer.pointer[0] = '0';
        result = (str) { buffer.pointer, 1};
    }
    else
    {
        u64 i = treat_as_signed;

        buffer.pointer[0] = '-';
        let v = value;

        while (v != 0)
        {
            let digit = v % 10;
            let ch = (u8)(digit + '0');
            assert(i < buffer.length);
            buffer.pointer[i] = ch;
            i += 1;
            v = v / 10;
        }

        let length = i;

        result = (str) { buffer.pointer + treat_as_signed, length - treat_as_signed };
        str_reverse(result);
        result.pointer -= treat_as_signed;
        result.length += treat_as_signed;
    }

    return result;
}

LOCAL str format_integer_octal(str buffer, u64 value)
{
    str result = {};

    if (value == 0)
    {
        buffer.pointer[0] = '0';
        result = (str) { buffer.pointer, 1};
    }
    else
    {
        u64 i = 0;
        let v = value;

        while (v != 0)
        {
            let digit = v % 8;
            let ch = (u8)(digit + '0');
            assert(i < buffer.length);
            buffer.pointer[i] = ch;
            i += 1;
            v = v / 8;
        }

        let length = i;

        result = (str) { buffer.pointer, length };
        str_reverse(result);
    }

    return result;
}

LOCAL str format_integer_binary(str buffer, u64 value)
{
    str result = {};

    if (value == 0)
    {
        buffer.pointer[0] = '0';
        result = (str) { buffer.pointer, 1};
    }
    else
    {
        u64 i = 0;
        let v = value;

        while (v != 0)
        {
            let digit = v % 2;
            let ch = (u8)(digit + '0');
            assert(i < buffer.length);
            buffer.pointer[i] = ch;
            i += 1;
            v = v / 2;
        }

        let length = i;

        result = (str) { buffer.pointer, length };
        str_reverse(result);
    }

    return result;
}

str format_integer_stack(str buffer, FormatIntegerOptions options)
{
    if (options.treat_as_signed)
    {
        assert(!options.prefix);
        assert(options.format == INTEGER_FORMAT_DECIMAL);
    }

    u64 prefix_digit_count = 2;

    str result = {};
    if (options.prefix)
    {
        u8 prefix_ch;
        switch (options.format)
        {
            break; case INTEGER_FORMAT_HEXADECIMAL: prefix_ch = 'x';
            break; case INTEGER_FORMAT_DECIMAL: prefix_ch = 'd';
            break; case INTEGER_FORMAT_OCTAL: prefix_ch = 'o';
            break; case INTEGER_FORMAT_BINARY: prefix_ch = 'b';
            break; default: UNREACHABLE();
        }
        buffer.pointer[0] = '0';
        buffer.pointer[1] = prefix_ch;
        buffer.pointer += prefix_digit_count;
        buffer.length += prefix_digit_count;
    }

    switch (options.format)
    {
        break; case INTEGER_FORMAT_HEXADECIMAL:
        {
            result = format_integer_hexadecimal(buffer, options.value);
        }
        break; case INTEGER_FORMAT_DECIMAL:
        {
            result = format_integer_decimal(buffer, options.value, options.treat_as_signed);
        }
        break; case INTEGER_FORMAT_OCTAL:
        {
            result = format_integer_octal(buffer, options.value);
        }
        break; case INTEGER_FORMAT_BINARY:
        {
            result = format_integer_binary(buffer, options.value);
        }
        break; default: UNREACHABLE();
    }

    if (options.prefix)
    {
        result.pointer -= prefix_digit_count;
        result.length += prefix_digit_count;
    }

    return result;
}

str format_integer(Arena* arena, FormatIntegerOptions options, bool zero_terminate)
{
    char buffer[128];
    let stack_string = format_integer_stack((str){ buffer, array_length(buffer) }, options);
    return arena_duplicate_string(arena, stack_string, zero_terminate);
}

ExecutionResult os_execute(Arena* arena, char** arguments, char** environment, ExecutionOptions options)
{
    ExecutionResult result = {};

#if defined (__linux__) || defined(__APPLE__)
    FileDescriptor* null_file_descriptor = 0;

    if (options.null_file_descriptor)
    {
        null_file_descriptor = options.null_file_descriptor;
    }
    else if ((options.policies[0] == STREAM_POLICY_IGNORE) | (options.policies[1] == STREAM_POLICY_IGNORE))
    {
        null_file_descriptor = os_file_open(S("/dev/null"), (OpenFlags) { .write = 1 }, (OpenPermissions){});
    }

    int pipes[STREAM_COUNT][2];

    for (int i = 0; i < STREAM_COUNT; i += 1)
    {
        if (options.policies[i] == STREAM_POLICY_PIPE)
        {
            if (pipe(pipes[i]) == -1)
            {
                fail();
            }
        }
    }

    let pid = fork();

    switch (pid)
    {
        break; case -1:
        {
            fail();
        }
        break; case 0:
        {
            for (int i = 0; i < STREAM_COUNT; i += 1)
            {
                let fd = (i + 1);

                switch (options.policies[i])
                {
                    break; case STREAM_POLICY_INHERIT: {}
                    break; case STREAM_POLICY_PIPE:
                    {
                        close(pipes[i][0]);
                        dup2(pipes[i][1], fd);
                        close(pipes[i][1]);
                    }
                    break; case STREAM_POLICY_IGNORE:
                    {
                        dup2(generic_fd_to_posix(null_file_descriptor), fd);
                        close(generic_fd_to_posix(null_file_descriptor));
                    }
                }
            }

            let result = execve(arguments[0], arguments, environment);

            if (result != -1)
            {
                UNREACHABLE();
            }

            fail();
        }
        break; default:
        {
            for (int i = 0; i < STREAM_COUNT; i += 1)
            {
                if (options.policies[i] == STREAM_POLICY_PIPE)
                {
                    close(pipes[i][1]);
                }
            }

            u64 offset = 0;

            if (options.policies[0] == STREAM_POLICY_PIPE | options.policies[1] == STREAM_POLICY_PIPE)
            {
                fail();
            }

            int status = 0;
            let waitpid_result = waitpid(pid, &status, 0);

            if (waitpid_result == pid)
            {
                if (WIFEXITED(status))
                {
                    result.termination_code = WEXITSTATUS(status);
                    result.termination_kind = TERMINATION_KIND_EXIT;
                }
                else if (WIFSIGNALED(status))
                {
                    result.termination_code = WTERMSIG(status);
                    result.termination_kind = TERMINATION_KIND_SIGNAL;
                }
                else if (WIFSTOPPED(status))
                {
                    result.termination_code = WSTOPSIG(status);
                    result.termination_kind = TERMINATION_KIND_STOP;
                }
                else
                {
                    result.termination_kind = TERMINATION_KIND_UNKNOWN;
                }

                if (!options.null_file_descriptor & !!null_file_descriptor)
                {
                    os_file_close(null_file_descriptor);
                }
            }
            else if (waitpid_result == -1)
            {
                fail();
            }
            else
            {
                UNREACHABLE();
            }
        }
    }
#elif _WIN32
    {
        HANDLE hStdInRead  = NULL, hStdInWrite  = NULL;
        HANDLE hStdOutRead = NULL, hStdOutWrite = NULL;
        HANDLE hStdErrRead = NULL, hStdErrWrite = NULL;

        SECURITY_ATTRIBUTES sa = { sizeof(sa) };
        sa.bInheritHandle = TRUE;
        sa.lpSecurityDescriptor = NULL;

        if (options.policies[0] == STREAM_POLICY_PIPE)
        {
            if (!CreatePipe(&hStdOutRead, &hStdOutWrite, &sa, 0))
            {
                fail();
            }
            if (!SetHandleInformation(hStdOutRead, HANDLE_FLAG_INHERIT, 0))
            {
                fail();
            }
        }

        if (options.policies[1] == STREAM_POLICY_PIPE)
        {
            if (!CreatePipe(&hStdErrRead, &hStdErrWrite, &sa, 0))
            {
                fail();
            }
            if (!SetHandleInformation(hStdErrRead, HANDLE_FLAG_INHERIT, 0))
            {
                fail();
            }
        }

        STARTUPINFO si;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.dwFlags |= STARTF_USESTDHANDLES;

        si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
        si.hStdOutput = (options.policies[0] == STREAM_POLICY_PIPE) ? hStdOutWrite : GetStdHandle(STD_OUTPUT_HANDLE);
        si.hStdError  = (options.policies[1] == STREAM_POLICY_PIPE) ? hStdErrWrite : GetStdHandle(STD_ERROR_HANDLE);

        PROCESS_INFORMATION pi;
        ZeroMemory(&pi, sizeof(pi));

        size_t cmd_len = 0;
        for (int i = 0; arguments[i]; i += 1)
        {
            cmd_len += strlen(arguments[i]) + 1;
        }
        char* cmdline = (char*)malloc(cmd_len + 1);
        if (!cmdline)
        {
            fail();
        }
        cmdline[0] = '\0';
        for (int i = 0; arguments[i]; i += 1)
        {
            strcat(cmdline, arguments[i]);
            if (arguments[i+1]) strcat(cmdline, " ");
        }

        LPVOID env_block = NULL;
        if (environment)
        {
            size_t total_len = 1;
            for (char** e = environment; *e; ++e)
            {
                total_len += strlen(*e) + 1;
            }

            env_block = malloc(total_len);

            if (!env_block)
            {
                fail();
            }

            char* dst = (char*)env_block;
            for (char** e = environment; *e; ++e)
            {
                size_t len = strlen(*e);
                memcpy(dst, *e, len);
                dst[len] = '\0';
                dst += len + 1;
            }
            *dst = '\0';
        }

        BOOL success = CreateProcessA(
            NULL,
            cmdline,
            NULL,
            NULL,
            TRUE,
            0,
            env_block,
            NULL,
            &si,
            &pi
        );

        free(cmdline);

        if (!success)
        {
            fail();
        }

        if (hStdInRead)
        {
            CloseHandle(hStdInRead);
        }
        if (hStdOutWrite)
        {
            CloseHandle(hStdOutWrite);
        }
        if (hStdErrWrite)
        {
            CloseHandle(hStdErrWrite);
        }

        WaitForSingleObject(pi.hProcess, INFINITE);

        DWORD exit_code = 0;
        if (!GetExitCodeProcess(pi.hProcess, &exit_code))
        {
            fail();
        }

        result.termination_code = (int)exit_code;
        result.termination_kind = TERMINATION_KIND_EXIT;

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);

        if (env_block)
        {
            free(env_block);
        }
    }
#endif

    return result;
}
#if defined(__AVX512F__)
IntegerParsing parse_hexadecimal_vectorized(const char* restrict p)
{
    u64 value = 0;
    u64 i = 0;

    while (1)
    {
        // let ch = p[i];
        //
        // if (!is_hexadecimal(ch))
        // {
        //     break;
        // }
        //
        // i += 1;
        // value = accumulate_hexadecimal(value, ch);
        trap();
    }

    return (IntegerParsing){ .value = value, .i = i };
}

IntegerParsing parse_decimal_vectorized(const char* restrict p)
{
    let zero = _mm512_set1_epi8('0');
    let nine = _mm512_set1_epi8('9');
    let chunk = _mm512_loadu_epi8(&p[0]);
    let lower_limit = _mm512_cmpge_epu8_mask(chunk, zero);
    let upper_limit = _mm512_cmple_epu8_mask(chunk, nine);
    let is = _kand_mask64(lower_limit, upper_limit);

    let digit_count = _tzcnt_u64(~_cvtmask64_u64(is));

    let digit_mask = _cvtu64_mask64((1ULL << digit_count) - 1);
    let digit2bin = _mm512_maskz_sub_epi8(digit_mask, chunk, zero);
    let lo0 = _mm512_castsi512_si128(digit2bin);
    let a = _mm512_cvtepu8_epi64(lo0);
    let digit_count_splat = _mm512_set1_epi8((u8)digit_count);

    let to_sub = _mm512_set_epi8(
            64, 63, 62, 61, 60, 59, 58, 57,
            56, 55, 54, 53, 52, 51, 50, 49,
            48, 47, 46, 45, 44, 43, 42, 41,
            40, 39, 38, 37, 36, 35, 34, 33,
            32, 31, 30, 29, 28, 27, 26, 25,
            24, 23, 22, 21, 20, 19, 18, 17,
            16, 15, 14, 13, 12, 11, 10, 9,
            8, 7, 6, 5, 4, 3, 2, 1);
    let ib = _mm512_maskz_sub_epi8(digit_mask, digit_count_splat, to_sub);
    let asds = _mm512_maskz_permutexvar_epi8(digit_mask, ib, digit2bin);

    let a128_0_0 = _mm512_extracti64x2_epi64(asds, 0);
    let a128_1_0 = _mm512_extracti64x2_epi64(asds, 1);

    let a128_0_1 = _mm_srli_si128(a128_0_0, 8);
    let a128_1_1 = _mm_srli_si128(a128_1_0, 8);

    let a8_0_0 = _mm512_cvtepu8_epi64(a128_0_0);
    let a8_0_1 = _mm512_cvtepu8_epi64(a128_0_1);
    let a8_1_0 = _mm512_cvtepu8_epi64(a128_1_0);

    let powers_of_ten_0_0 = _mm512_set_epi64(
            10000000,
            1000000,
            100000,
            10000,
            1000,
            100,
            10,
            1);
    let powers_of_ten_0_1 = _mm512_set_epi64(
            1000000000000000,
            100000000000000,
            10000000000000,
            1000000000000,
            100000000000,
            10000000000,
            1000000000,
            100000000
            );
    let powers_of_ten_1_0 = _mm512_set_epi64(
            0,
            0,
            0,
            0,
            10000000000000000000ULL,
            1000000000000000000,
            100000000000000000,
            10000000000000000
            );

    let a0_0 = _mm512_mullo_epi64(a8_0_0, powers_of_ten_0_0);
    let a0_1 = _mm512_mullo_epi64(a8_0_1, powers_of_ten_0_1);
    let a1_0 = _mm512_mullo_epi64(a8_1_0, powers_of_ten_1_0);

    let add = _mm512_add_epi64(_mm512_add_epi64(a0_0, a0_1), a1_0);
    let reduce_add = _mm512_reduce_add_epi64(add);
    let value = reduce_add;

    return (IntegerParsing){ .value = value, .i = digit_count };
}

IntegerParsing parse_octal_vectorized(const char* restrict p)
{
    u64 value = 0;
    u64 i = 0;

    while (1)
    {
        let chunk = _mm512_loadu_epi8(&p[i]);
        let lower_limit = _mm512_cmpge_epu8_mask(chunk, _mm512_set1_epi8('0'));
        let upper_limit = _mm512_cmple_epu8_mask(chunk, _mm512_set1_epi8('7'));
        let is_octal = _kand_mask64(lower_limit, upper_limit);
        let octal_mask = _cvtu64_mask64(_tzcnt_u64(~_cvtmask64_u64(is_octal)));

        trap();

        // if (!is_octal(ch))
        // {
        //     break;
        // }
        //
        // i += 1;
        // value = accumulate_octal(value, ch);
    }

    return (IntegerParsing) { .value = value, .i = i };
}

IntegerParsing parse_binary_vectorized(const char* restrict f)
{
    u64 value = 0;

    let chunk = _mm512_loadu_epi8(f);
    let zero = _mm512_set1_epi8('0');
    let is0 = _mm512_cmpeq_epu8_mask(chunk, zero);
    let is1 = _mm512_cmpeq_epu8_mask(chunk, _mm512_set1_epi8('1'));
    let is_binary_chunk = _kor_mask64(is0, is1);
    u64 i = _tzcnt_u64(~_cvtmask64_u64(is_binary_chunk));
    let digit2bin = _mm512_maskz_sub_epi8(is_binary_chunk, chunk, zero);
    let rotated = _mm512_permutexvar_epi8(digit2bin,
            _mm512_set_epi8(
                0, 1, 2, 3, 4, 5, 6, 7,
                8, 9, 10, 11, 12, 13, 14, 15,
                16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31,
                32, 33, 34, 35, 36, 37, 38, 39,
                40, 41, 42, 43, 44, 45, 46, 47,
                48, 49, 50, 51, 52, 53, 54, 55,
                56, 57, 58, 59, 60, 61, 62, 63
                ));
    let mask = _mm512_test_epi8_mask(rotated, rotated);
    let mask_int = _cvtmask64_u64(mask);

    return (IntegerParsing) { .value = value, .i = i };
}
#endif

LOCAL u64 accumulate_hexadecimal(u64 accumulator, u8 ch)
{
    u8 value;

    if (is_decimal(ch))
    {
        value = ch - '0';
    }
    else if (is_hexadecimal_alpha_upper(ch))
    {
        value = ch - 'A' + 10;
    }
    else if (is_hexadecimal_alpha_lower(ch))
    {
        value = ch - 'a' + 10;
    }
    else
    {
        UNREACHABLE();
    }

    return (accumulator * 16) + value;
}

LOCAL u64 accumulate_decimal(u64 accumulator, u8 ch)
{
    assert(is_decimal(ch));
    return (accumulator * 10) + (ch - '0');
}

LOCAL u64 accumulate_octal(u64 accumulator, u8 ch)
{
    assert(is_octal(ch));

    return (accumulator * 8) + (ch - '0');
}

LOCAL u64 accumulate_binary(u64 accumulator, u8 ch)
{
    assert(is_binary(ch));

    return (accumulator * 2) + (ch - '0');
}

u64 parse_integer_decimal_assume_valid(str string)
{
    u64 value = 0;

    for (u64 i = 0; i < string.length; i += 1)
    {
        let ch = string.pointer[i];
        value = accumulate_decimal(value, ch);
    }

    return value;
}

IntegerParsing parse_hexadecimal_scalar(const char* restrict p)
{
    u64 value = 0;
    u64 i = 0;

    while (1)
    {
        let ch = p[i];

        if (!is_hexadecimal(ch))
        {
            break;
        }

        i += 1;
        value = accumulate_hexadecimal(value, ch);
    }

    return (IntegerParsing){ .value = value, .i = i };
}

IntegerParsing parse_decimal_scalar(const char* restrict p)
{
    u64 value = 0;
    u64 i = 0;

    while (1)
    {
        let ch = p[i];

        if (!is_decimal(ch))
        {
            break;
        }

        i += 1;
        value = accumulate_decimal(value, ch);
    }

    return (IntegerParsing){ .value = value, .i = i };
}

IntegerParsing parse_octal_scalar(const char* restrict p)
{
    u64 value = 0;
    u64 i = 0;

    while (1)
    {
        let ch = p[i];

        if (!is_octal(ch))
        {
            break;
        }

        i += 1;
        value = accumulate_octal(value, ch);
    }

    return (IntegerParsing) { .value = value, .i = i };
}

IntegerParsing parse_binary_scalar(const char* restrict p)
{
    u64 value = 0;
    u64 i = 0;

    while (1)
    {
        let ch = p[i];

        if (!is_binary(ch))
        {
            break;
        }

        i += 1;
        value = accumulate_binary(value, ch);
    }

    return (IntegerParsing){ .value = value, .i = i };
}

#if defined(_WIN32)
LOCAL ThreadHandle* os_windows_thread_to_generic(HANDLE handle)
{
    assert(handle != 0);
    return (ThreadHandle*)handle;
}

LOCAL HANDLE os_windows_thread_from_generic(ThreadHandle* handle)
{
    assert(handle != 0);
    return (HANDLE)handle;
}
#endif

#if defined(__linux__) || defined(__APPLE__)
LOCAL ThreadHandle* os_posix_thread_to_generic(pthread_t handle)
{
    assert(handle != 0);
    return (ThreadHandle*)handle;
}

LOCAL pthread_t os_posix_thread_from_generic(ThreadHandle* handle)
{
    assert(handle != 0);
    return (pthread_t)handle;
}
#endif

ThreadHandle* os_thread_create(ThreadCallback* callback, ThreadCreateOptions options)
{
    ThreadHandle* result = 0;
#if defined (__linux__) || defined(__APPLE__)
    pthread_t handle;
    let create_result = pthread_create(&handle, 0, callback, 0);
    bool os_result = create_result == 0;
    handle = os_result ? handle : 0;
    result = os_posix_thread_to_generic(handle);
#elif defined (_WIN32)
    HANDLE handle = CreateThread(0, 0, callback, 0, 0, 0);
    result = os_windows_thread_to_generic(handle);
#endif
    return result;
}

u32 os_thread_join(ThreadHandle* handle)
{
    u32 return_code = 1;

#if defined(__linux__) || defined(__APPLE__)
    let pthread = os_posix_thread_from_generic(handle);
    void* void_return_value = 0;
    let join_result = pthread_join(pthread, &void_return_value);
    if (join_result == 0)
    {
        return_code = (u32)(u64)void_return_value;
    }
#elif defined(_WIN32)
    let thread_handle = os_windows_thread_from_generic(handle);
    WaitForSingleObject(thread_handle, INFINITE);

    DWORD exit_code;
    let result = GetExitCodeThread(thread_handle, &exit_code) != 0;
    if (result)
    {
        return_code = (u32)exit_code;
    }

    CloseHandle(thread_handle);
#endif

    return return_code;
}

void test_error(str check_text, u32 line, str function, str file_path)
{
    if (is_debugger_present())
    {
        trap();
    }
}

PUB_IMPL u64 next_power_of_two(u64 n)
{
    n -= 1;

    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    n |= n >> 32;

    n += 1;

    return n;
}

PUB_IMPL bool str_is_zero_terminated(str s)
{
    return s.pointer[s.length] == 0;
}

PUB_IMPL str str_from_pointers(char* start, char* end)
{
    assert(end >= start);
    u64 len = end - start;
    return (str) { start, len };
}

PUB_IMPL str str_from_ptr_len(const char* ptr, u64 len)
{
    return (str) { (char*)ptr, len };
}

PUB_IMPL str str_from_ptr_start_end(char* ptr, u64 start, u64 end)
{
    return (str) { ptr + start, end - start };
}

PUB_IMPL str str_slice_start(str s, u64 start)
{
    s.pointer += start;
    s.length -= start;
    return s;
}

PUB_IMPL bool memory_compare(void* a, void* b, u64 i)
{
    assert(a != b);
    bool result = 1;

    let p1 = (u8*)a;
    let p2 = (u8*)b;

    while (i--)
    {
        bool is_equal = *p1 == *p2;
        if (!is_equal)
        {
            result = 0;
            break;
        }

        p1 += 1;
        p2 += 1;
    }

    return result;
}

PUB_IMPL str str_slice(str s, u64 start, u64 end)
{
    s.pointer += start;
    s.length = end - start;
    return s;
}

PUB_IMPL bool str_equal(str s1, str s2)
{
    bool is_equal = s1.length == s2.length;
    if (is_equal & (s1.length != 0))
    {
        is_equal = memory_compare(s1.pointer, s2.pointer, s1.length);
    }

    return is_equal;
}

PUB_IMPL u64 str_last_ch(str s, u8 ch)
{
    let result = string_no_match;

    let pointer = s.pointer + s.length;

    do
    {
        pointer -= 1;
        if (*pointer == ch)
        {
            result = pointer - s.pointer;
            break;
        }
    } while (pointer - s.pointer);

    return result;
}

PUB_IMPL u64 align_forward(u64 n, u64 a)
{
    let mask = a - 1;
    let result = (n + mask) & ~mask;
    return result;
}

PUB_IMPL bool is_space(char ch)
{
    return ((ch == ' ') | (ch == '\t')) | ((ch == '\r') | (ch == '\n'));
}

PUB_IMPL bool is_decimal(char ch)
{
    return (ch >= '0') & (ch <= '9');
}

PUB_IMPL bool is_octal(char ch)
{
    return (ch >= '0') & (ch <= '7');
}

PUB_IMPL bool is_binary(char ch)
{
    return (ch == '0') | (ch == '1');
}

PUB_IMPL bool is_hexadecimal_alpha_lower(char ch)
{
    return (ch >= 'a') & (ch <= 'f');
}

PUB_IMPL bool is_hexadecimal_alpha_upper(char ch)
{
    return (ch >= 'A') & (ch <= 'F');
}

PUB_IMPL bool is_hexadecimal_alpha(char ch)
{
    return is_hexadecimal_alpha_upper(ch) | is_hexadecimal_alpha_lower(ch);
}

PUB_IMPL bool is_hexadecimal(char ch)
{
    return is_decimal(ch) | is_hexadecimal_alpha(ch);
}

PUB_IMPL bool is_identifier_start(char ch)
{
    return (((ch >= 'a') & (ch <= 'z')) | ((ch >= 'A') & (ch <= 'Z'))) | (ch == '_');
}

PUB_IMPL bool is_identifier(char ch)
{
    return is_identifier_start(ch) | is_decimal(ch);
}

#if BB_INCLUDE_TESTS
bool lib_tests(TestArguments* restrict arguments)
{
    bool result = 1;
    let arena = arguments->arena;
    let position = arena->position;
    test(arguments, str_equal(S("123"), format_integer(arena, (FormatIntegerOptions) { .value = 123, .format = INTEGER_FORMAT_DECIMAL, }, true)));
    test(arguments, str_equal(S("1000"), format_integer(arena, (FormatIntegerOptions) { .value = 1000, .format = INTEGER_FORMAT_DECIMAL }, true)));
    test(arguments, str_equal(S("12839128391258192419"), format_integer(arena, (FormatIntegerOptions) { .value = 12839128391258192419ULL, .format = INTEGER_FORMAT_DECIMAL}, true)));
    test(arguments, str_equal(S("-1"), format_integer(arena, (FormatIntegerOptions) { .value = 1, .format = INTEGER_FORMAT_DECIMAL, .treat_as_signed = true}, true)));
    test(arguments, str_equal(S("-1123123123"), format_integer(arena, (FormatIntegerOptions) { .value = 1123123123, .format = INTEGER_FORMAT_DECIMAL, .treat_as_signed = true}, true)));
    test(arguments, str_equal(S("0d0"), format_integer(arena, (FormatIntegerOptions) { .value = 0, .format = INTEGER_FORMAT_DECIMAL, .prefix = true }, true)));
    test(arguments, str_equal(S("0d123"), format_integer(arena, (FormatIntegerOptions) { .value = 123, .format = INTEGER_FORMAT_DECIMAL, .prefix = true, }, true)));
    test(arguments, str_equal(S("0"), format_integer(arena, (FormatIntegerOptions) { .value = 0, .format = INTEGER_FORMAT_HEXADECIMAL, }, true)));
    test(arguments, str_equal(S("af"), format_integer(arena, (FormatIntegerOptions) { .value = 0xaf, .format = INTEGER_FORMAT_HEXADECIMAL, }, true)));
    test(arguments, str_equal(S("0x0"), format_integer(arena, (FormatIntegerOptions) { .value = 0, .format = INTEGER_FORMAT_HEXADECIMAL, .prefix = true }, true)));
    test(arguments, str_equal(S("0x8591baefcb"), format_integer(arena, (FormatIntegerOptions) { .value = 0x8591baefcb, .format = INTEGER_FORMAT_HEXADECIMAL, .prefix = true }, true)));
    test(arguments, str_equal(S("0o12557"), format_integer(arena, (FormatIntegerOptions) { .value = 012557, .format = INTEGER_FORMAT_OCTAL, .prefix = true }, true)));
    test(arguments, str_equal(S("12557"), format_integer(arena, (FormatIntegerOptions) { .value = 012557, .format = INTEGER_FORMAT_OCTAL, }, true)));
    test(arguments, str_equal(S("0b101101"), format_integer(arena, (FormatIntegerOptions) { .value = 0b101101, .format = INTEGER_FORMAT_BINARY, .prefix = true }, true)));
    test(arguments, str_equal(S("101101"), format_integer(arena, (FormatIntegerOptions) { .value = 0b101101, .format = INTEGER_FORMAT_BINARY, }, true)));
    arena->position = position;
    return result;
}
#endif
