#include <lib.h>

#ifdef __x86_64__
#include <immintrin.h>
#endif

#ifdef __linux__
#include <unistd.h>
#include <liburing.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <time.h>
#include <stdio.h>
#else
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
#else
#endif
}

static void os_commit(void* address, u64 size, ProtectionFlags protection)
{
#ifdef __linux__
    let protection_flags = os_linux_protection_flags(protection);
    let result = mprotect(address, size, protection_flags);
    assert(result == 0);
#else
#endif
}

FileDescriptor* os_file_open(str path, OpenFlags flags, OpenPermissions permissions)
{
    assert(!path.pointer[path.length]);

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

    FileDescriptor* result = 0;
    if (fd >= 0)
    {
        result = (void*)(u64)fd;
    }

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

u64 os_file_get_size(FileDescriptor* file_descriptor)
{
    int fd = generic_fd_to_posix(file_descriptor);
    struct stat sb;
    let fstat_result = fstat(fd, &sb);
    assert(fstat_result == 0);

    return (u64)sb.st_size;
}

static u64 os_file_read_partially(FileDescriptor* file_descriptor, void* buffer, u64 byte_count)
{
    let fd = generic_fd_to_posix(file_descriptor);
    let read_byte_count = read(fd, buffer, byte_count);
    assert(read_byte_count > 0);

    return (u64)read_byte_count;
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
    let fd = generic_fd_to_posix(file_descriptor);
    let result = write(fd, pointer, length);
    assert(result > 0);
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
    let fd = generic_fd_to_posix(file_descriptor);
    let close_result = close(fd);
    assert(close_result == 0);
}

static u64 page_size = KB(4);
static u64 default_granularity = MB(2);

static_assert(sizeof(Arena) % CACHE_LINE_GUESS == 0);

static u64 minimum_position = sizeof(Arena);

Arena* arena_initialize(ArenaInitialization initialization)
{
    if (!initialization.reserved_size)
    {
        initialization.reserved_size = GB(4);
    }

    if (!initialization.granularity)
    {
        initialization.granularity = default_granularity;
    }

    if (!initialization.initial_size)
    {
        initialization.initial_size = default_granularity * 4;
    }

    ProtectionFlags protection_flags = { .read = 1, .write = 1 };
    MapFlags map_flags = { .private = 1, .anonymous = 1, .no_reserve = 1, .populate = 0 };
    let raw_pointer = os_reserve(0, initialization.reserved_size, protection_flags, map_flags);
    let arena = (Arena*)raw_pointer;
    os_commit(raw_pointer, initialization.initial_size, protection_flags);

    *arena = (Arena){ 
        .reserved_size = initialization.reserved_size,
        .position = minimum_position,
        .os_position = initialization.initial_size,
        .granularity = initialization.granularity,
    };

    return arena;
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

static struct timespec take_timestamp()
{
    struct timespec ts;
    let result = clock_gettime(CLOCK_MONOTONIC, &ts);
    assert(result == 0);
    return ts;
}

static u64 ns_between(struct timespec start, struct timespec end)
{
    let second_diff = end.tv_sec - start.tv_sec;
    let ns_diff = end.tv_nsec - start.tv_nsec;

    let result = second_diff * 1000000000LL + ns_diff;
    return result;
}

str file_read(Arena* arena, str path)
{
    let open_start = take_timestamp();
    let fd = os_file_open(path, (OpenFlags) { .read = 1 }, (OpenPermissions){ .read = 1 });
    let open_end = take_timestamp();
    str result = {};
    if (fd)
    {
        let stat_start = open_end;
        let file_size = os_file_get_size(fd);
        let stat_end = take_timestamp();
        let allocation_start = stat_end;
        let file_buffer = arena_allocate_bytes(arena, file_size, 1);
        let allocation_end = take_timestamp();
        let read_start = allocation_end;
        os_file_read(fd, (str) { file_buffer, file_size }, file_size);
        let read_end = take_timestamp();
        let close_start = read_end;
        os_file_close(fd);
        let close_end = take_timestamp();
        result = (str) { file_buffer, file_size };

        printf("\tOpen: %lu ns\n\tStat: %lu ns\n\tArena: %lu ns\n\tRead: %lu ns\n\tClose: %lu ns\n", ns_between(open_start, open_end), ns_between(stat_start, stat_end), ns_between(allocation_start, allocation_end), ns_between(read_start, read_end), ns_between(close_start, close_end));
    }
    return result;
}
