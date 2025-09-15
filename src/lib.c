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

static bool os_lock_and_unlock(void* address, u64 size)
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
#elif defined(__APPLE__)
#elif defined(_WIN32)
#endif
    return result;
}

static void* os_reserve(void* base, u64 size, ProtectionFlags protection, MapFlags map)
{
    void* address = 0;

#ifdef __linux__
    let protection_flags = os_linux_protection_flags(protection);
    let map_flags = os_linux_map_flags(map);

    address = mmap(base, size, protection_flags, map_flags, -1, 0);
    if (address == MAP_FAILED)
    {
        address = 0;
    }
#elif _WIN32
    let result = VirtualAlloc(base, size, MEM_RESERVE, PAGE_READWRITE);
    return result;
#endif
    return address;
}

static bool os_commit(void* address, u64 size, ProtectionFlags protection, bool lock)
{
    bool result = 1;

#ifdef __linux__
    let protection_flags = os_linux_protection_flags(protection);
    let os_result = mprotect(address, size, protection_flags);
    result = os_result == 0;
#elif _WIN32
    let result = VirtualAlloc(address, size, MEM_COMMIT, PAGE_READWRITE);
    assert(result != 0);
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

static bool arena_lock_pages = true;

static u64 default_reserve_size = GB(4);
static u64 initial_size_granularity_factor = 4;

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
    let unmap_result = munmap(arena, size);
    return unmap_result == 0;
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

static str os_path_absolute_stack(str buffer, const char* restrict relative_file_path)
{
    str result = {};
    let syscall_result = realpath(relative_file_path, buffer.pointer);

    if (syscall_result)
    {
        result = str_from_ptr_len(syscall_result, strlen(syscall_result));
        assert(result.length < buffer.length);
    }

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
#else
#endif
}

static bool is_debugger_present_called = false;
static bool _is_debugger_present = false;

static bool is_debugger_present()
{
    if (unlikely(!is_debugger_present_called))
    {
        let result = ptrace(PTRACE_TRACEME, 0, 0, 0) == -1;
        _is_debugger_present = result != 0;
        is_debugger_present_called = true;
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

static void str_reverse(str s)
{
    char* restrict pointer = s.pointer;
    for (u64 i = 0, reverse_i = s.length - 1; i < reverse_i; i += 1, reverse_i -= 1)
    {
        let ch = pointer[i];
        pointer[i] = pointer[reverse_i];
        pointer[reverse_i] = ch;
    }
}

static str format_integer_hexadecimal(str buffer, u64 value)
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

static str format_integer_decimal(str buffer, u64 value, bool treat_as_signed)
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

static str format_integer_octal(str buffer, u64 value)
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

static str format_integer_binary(str buffer, u64 value)
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

#ifdef __linux__
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
#endif

    return result;
}

void test_error(str check_text, u32 line, str function, str file_path)
{
    if (is_debugger_present())
    {
        trap();
    }
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
