#include <std/os.h>
#include <std/string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN 1
#include <Windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/time.h>
#endif

#if LINK_LIBC
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#endif

fn 
#if _WIN32
u64
#else
#if LINK_LIBC
struct timespec
#else
u64 
#endif
#endif
timestamp()
{
#ifdef _WIN32
    LARGE_INTEGER li;
    QueryPerformanceCounter(&li);
    return (u64)li.QuadPart;
#else
#if LINK_LIBC
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts;
#else
#if defined(__x86_64__)
    return __rdtsc();
#else
    return 0;
#endif
#endif
#endif
}


#if _WIN32
global_variable u64 cpu_frequency;
#else
#if LINK_LIBC
global_variable struct timespec cpu_resolution;
#else
global_variable u64 cpu_frequency;
#endif
#endif

FileDescriptor os_stdout_get()
{
#if _WIN32
    auto handle = GetStdHandle(STD_OUTPUT_HANDLE);
    assert(handle != INVALID_HANDLE_VALUE);
    return handle;
#else
    return 1;
#endif
}

typedef enum TimeUnit
{
    TIME_UNIT_NANOSECONDS,
    TIME_UNIT_MICROSECONDS,
    TIME_UNIT_MILLISECONDS,
    TIME_UNIT_SECONDS,
} TimeUnit;

may_be_unused fn f64 resolve_timestamp(
#if _WIN32
        u64 start, u64 end,
#else
#if LINK_LIBC
        struct timespec start, struct timespec end,
#else
        u64 start, u64 end,
#endif
#endif
        TimeUnit time_unit)
{
#if _WIN32
    auto s = (f64)(end - start) / (f64)cpu_frequency;
    switch (time_unit)
    {
        case TIME_UNIT_NANOSECONDS:
            return s * 1000000000.0;
        case TIME_UNIT_MICROSECONDS:
            return s * 1000000.0;
        case TIME_UNIT_MILLISECONDS:
            return s * 1000.0;
        case TIME_UNIT_SECONDS:
            return s;
    }
#else
#if LINK_LIBC
    assert(end.tv_sec >= start.tv_sec);
    struct timespec result = {
        .tv_sec = end.tv_sec - start.tv_sec,
        .tv_nsec = end.tv_nsec - start.tv_nsec,
    };

    auto ns_in_a_sec = 1000000000;
    if (result.tv_nsec < 0)
    {
        result.tv_sec -= 1;
        result.tv_nsec += ns_in_a_sec;
    }

    auto ns = result.tv_sec * ns_in_a_sec + result.tv_nsec;
    switch (time_unit)
    {
    case TIME_UNIT_NANOSECONDS:
        return (f64)ns;
    case TIME_UNIT_MICROSECONDS:
        return (f64)ns / 1000.0;
    case TIME_UNIT_MILLISECONDS:
        return (f64)ns / 1000000.0;
    case TIME_UNIT_SECONDS:
        return (f64)ns / 1000000000.0;
    }
#else
    assert(end >= start);
    auto ticks = end - start;
    f64 s = (f64)(end - start);
    if (cpu_frequency)
    {
        s = s / (f64)cpu_frequency;

        switch (time_unit)
        {
            case TIME_UNIT_NANOSECONDS:
                return s * 1000000000.0;
            case TIME_UNIT_MICROSECONDS:
                return s * 1000000.0;
            case TIME_UNIT_MILLISECONDS:
                return s * 1000.0;
            case TIME_UNIT_SECONDS:
                return s;
        }
    }
    else
    {
        // warning: rdtsc frequency not queried (returning ticks as are)
        return s;
    }
#endif
#endif
}

String path_dir(String string)
{
    String result = {};
    auto index = string_last_ch(string, '/');
    if (index != -1)
    {
        result = s_get_slice(u8, string, 0, index);
    }

    return result;
}

String path_base(String string)
{
    String result = {};
    auto maybe_index = string_last_ch(string, '/');
    if (maybe_index != -1)
    {
        auto index = cast_to(u64, s64, maybe_index);
        result = s_get_slice(u8, string, index + 1, string.length);
    }
#if _WIN32
    if (!result.pointer)
    {
        auto maybe_index = string_last_ch(string, '\\');
        auto index = cast_to(u64, s64, maybe_index);
        result = s_get_slice(u8, string, index + 1, string.length);
    }
#endif

    return result;
}

String path_no_extension(String string)
{
    String result = {};
    auto maybe_index = string_last_ch(string, '.');
    if (maybe_index != -1)
    {
        auto index = cast_to(u64, s64, maybe_index);
        result = s_get_slice(u8, string, 0, index);
    }

    return result;
}

#if LINK_LIBC == 0
#ifdef __linux__
may_be_unused fn forceinline long syscall0(long n)
{
    long ret;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n) : "rcx", "r11", "memory");
    return ret;
}

may_be_unused fn forceinline long syscall1(long n, long a1)
{
    long ret;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1) : "rcx", "r11", "memory");
    return ret;
}

may_be_unused fn forceinline long syscall2(long n, long a1, long a2)
{
    long ret;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2)
    : "rcx", "r11", "memory");
    return ret;
}

may_be_unused fn forceinline long syscall3(long n, long a1, long a2, long a3)
{
    long ret;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
    "d"(a3) : "rcx", "r11", "memory");
    return ret;
}

may_be_unused fn forceinline long syscall4(long n, long a1, long a2, long a3, long a4)
{
    long ret;
    register long r10 __asm__("r10") = a4;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
    "d"(a3), "r"(r10): "rcx", "r11", "memory");
    return ret;
}

may_be_unused fn forceinline long syscall5(long n, long a1, long a2, long a3, long a4, long a5)
{
    long ret;
    register long r10 __asm__("r10") = a4;
    register long r8 __asm__("r8") = a5;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
    "d"(a3), "r"(r10), "r"(r8) : "rcx", "r11", "memory");
    return ret;
}

may_be_unused fn forceinline long syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6)
{
    long ret;
    register long r10 __asm__("r10") = a4;
    register long r8 __asm__("r8") = a5;
    register long r9 __asm__("r9") = a6;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
    "d"(a3), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
    return ret;
}

enum SyscallX86_64 : u64 {
    syscall_x86_64_read = 0,
    syscall_x86_64_write = 1,
    syscall_x86_64_open = 2,
    syscall_x86_64_close = 3,
    syscall_x86_64_stat = 4,
    syscall_x86_64_fstat = 5,
    syscall_x86_64_lstat = 6,
    syscall_x86_64_poll = 7,
    syscall_x86_64_lseek = 8,
    syscall_x86_64_mmap = 9,
    syscall_x86_64_mprotect = 10,
    syscall_x86_64_munmap = 11,
    syscall_x86_64_brk = 12,
    syscall_x86_64_rt_sigaction = 13,
    syscall_x86_64_rt_sigprocmask = 14,
    syscall_x86_64_rt_sigreturn = 15,
    syscall_x86_64_ioctl = 16,
    syscall_x86_64_pread64 = 17,
    syscall_x86_64_pwrite64 = 18,
    syscall_x86_64_readv = 19,
    syscall_x86_64_writev = 20,
    syscall_x86_64_access = 21,
    syscall_x86_64_pipe = 22,
    syscall_x86_64_select = 23,
    syscall_x86_64_sched_yield = 24,
    syscall_x86_64_mremap = 25,
    syscall_x86_64_msync = 26,
    syscall_x86_64_mincore = 27,
    syscall_x86_64_madvise = 28,
    syscall_x86_64_shmget = 29,
    syscall_x86_64_shmat = 30,
    syscall_x86_64_shmctl = 31,
    syscall_x86_64_dup = 32,
    syscall_x86_64_dup2 = 33,
    syscall_x86_64_pause = 34,
    syscall_x86_64_nanosleep = 35,
    syscall_x86_64_getitimer = 36,
    syscall_x86_64_alarm = 37,
    syscall_x86_64_setitimer = 38,
    syscall_x86_64_getpid = 39,
    syscall_x86_64_sendfile = 40,
    syscall_x86_64_socket = 41,
    syscall_x86_64_connect = 42,
    syscall_x86_64_accept = 43,
    syscall_x86_64_sendto = 44,
    syscall_x86_64_recvfrom = 45,
    syscall_x86_64_sendmsg = 46,
    syscall_x86_64_recvmsg = 47,
    syscall_x86_64_shutdown = 48,
    syscall_x86_64_bind = 49,
    syscall_x86_64_listen = 50,
    syscall_x86_64_getsockname = 51,
    syscall_x86_64_getpeername = 52,
    syscall_x86_64_socketpair = 53,
    syscall_x86_64_setsockopt = 54,
    syscall_x86_64_getsockopt = 55,
    syscall_x86_64_clone = 56,
    syscall_x86_64_fork = 57,
    syscall_x86_64_vfork = 58,
    syscall_x86_64_execve = 59,
    syscall_x86_64_exit = 60,
    syscall_x86_64_wait4 = 61,
    syscall_x86_64_kill = 62,
    syscall_x86_64_uname = 63,
    syscall_x86_64_semget = 64,
    syscall_x86_64_semop = 65,
    syscall_x86_64_semctl = 66,
    syscall_x86_64_shmdt = 67,
    syscall_x86_64_msgget = 68,
    syscall_x86_64_msgsnd = 69,
    syscall_x86_64_msgrcv = 70,
    syscall_x86_64_msgctl = 71,
    syscall_x86_64_fcntl = 72,
    syscall_x86_64_flock = 73,
    syscall_x86_64_fsync = 74,
    syscall_x86_64_fdatasync = 75,
    syscall_x86_64_truncate = 76,
    syscall_x86_64_ftruncate = 77,
    syscall_x86_64_getdents = 78,
    syscall_x86_64_getcwd = 79,
    syscall_x86_64_chdir = 80,
    syscall_x86_64_fchdir = 81,
    syscall_x86_64_rename = 82,
    syscall_x86_64_mkdir = 83,
    syscall_x86_64_rmdir = 84,
    syscall_x86_64_creat = 85,
    syscall_x86_64_link = 86,
    syscall_x86_64_unlink = 87,
    syscall_x86_64_symlink = 88,
    syscall_x86_64_readlink = 89,
    syscall_x86_64_chmod = 90,
    syscall_x86_64_fchmod = 91,
    syscall_x86_64_chown = 92,
    syscall_x86_64_fchown = 93,
    syscall_x86_64_lchown = 94,
    syscall_x86_64_umask = 95,
    syscall_x86_64_gettimeofday = 96,
    syscall_x86_64_getrlimit = 97,
    syscall_x86_64_getrusage = 98,
    syscall_x86_64_sysinfo = 99,
    syscall_x86_64_times = 100,
    syscall_x86_64_ptrace = 101,
    syscall_x86_64_getuid = 102,
    syscall_x86_64_syslog = 103,
    syscall_x86_64_getgid = 104,
    syscall_x86_64_setuid = 105,
    syscall_x86_64_setgid = 106,
    syscall_x86_64_geteuid = 107,
    syscall_x86_64_getegid = 108,
    syscall_x86_64_setpgid = 109,
    syscall_x86_64_getppid = 110,
    syscall_x86_64_getpgrp = 111,
    syscall_x86_64_setsid = 112,
    syscall_x86_64_setreuid = 113,
    syscall_x86_64_setregid = 114,
    syscall_x86_64_getgroups = 115,
    syscall_x86_64_setgroups = 116,
    syscall_x86_64_setresuid = 117,
    syscall_x86_64_getresuid = 118,
    syscall_x86_64_setresgid = 119,
    syscall_x86_64_getresgid = 120,
    syscall_x86_64_getpgid = 121,
    syscall_x86_64_setfsuid = 122,
    syscall_x86_64_setfsgid = 123,
    syscall_x86_64_getsid = 124,
    syscall_x86_64_capget = 125,
    syscall_x86_64_capset = 126,
    syscall_x86_64_rt_sigpending = 127,
    syscall_x86_64_rt_sigtimedwait = 128,
    syscall_x86_64_rt_sigqueueinfo = 129,
    syscall_x86_64_rt_sigsuspend = 130,
    syscall_x86_64_sigaltstack = 131,
    syscall_x86_64_utime = 132,
    syscall_x86_64_mknod = 133,
    syscall_x86_64_uselib = 134,
    syscall_x86_64_personality = 135,
    syscall_x86_64_ustat = 136,
    syscall_x86_64_statfs = 137,
    syscall_x86_64_fstatfs = 138,
    syscall_x86_64_sysfs = 139,
    syscall_x86_64_getpriority = 140,
    syscall_x86_64_setpriority = 141,
    syscall_x86_64_sched_setparam = 142,
    syscall_x86_64_sched_getparam = 143,
    syscall_x86_64_sched_setscheduler = 144,
    syscall_x86_64_sched_getscheduler = 145,
    syscall_x86_64_sched_get_priority_max = 146,
    syscall_x86_64_sched_get_priority_min = 147,
    syscall_x86_64_sched_rr_get_interval = 148,
    syscall_x86_64_mlock = 149,
    syscall_x86_64_munlock = 150,
    syscall_x86_64_mlockall = 151,
    syscall_x86_64_munlockall = 152,
    syscall_x86_64_vhangup = 153,
    syscall_x86_64_modify_ldt = 154,
    syscall_x86_64_pivot_root = 155,
    syscall_x86_64__sysctl = 156,
    syscall_x86_64_prctl = 157,
    syscall_x86_64_arch_prctl = 158,
    syscall_x86_64_adjtimex = 159,
    syscall_x86_64_setrlimit = 160,
    syscall_x86_64_chroot = 161,
    syscall_x86_64_sync = 162,
    syscall_x86_64_acct = 163,
    syscall_x86_64_settimeofday = 164,
    syscall_x86_64_mount = 165,
    syscall_x86_64_umount2 = 166,
    syscall_x86_64_swapon = 167,
    syscall_x86_64_swapoff = 168,
    syscall_x86_64_reboot = 169,
    syscall_x86_64_sethostname = 170,
    syscall_x86_64_setdomainname = 171,
    syscall_x86_64_iopl = 172,
    syscall_x86_64_ioperm = 173,
    syscall_x86_64_create_module = 174,
    syscall_x86_64_init_module = 175,
    syscall_x86_64_delete_module = 176,
    syscall_x86_64_get_kernel_syms = 177,
    syscall_x86_64_query_module = 178,
    syscall_x86_64_quotactl = 179,
    syscall_x86_64_nfsservctl = 180,
    syscall_x86_64_getpmsg = 181,
    syscall_x86_64_putpmsg = 182,
    syscall_x86_64_afs_syscall = 183,
    syscall_x86_64_tuxcall = 184,
    syscall_x86_64_security = 185,
    syscall_x86_64_gettid = 186,
    syscall_x86_64_readahead = 187,
    syscall_x86_64_setxattr = 188,
    syscall_x86_64_lsetxattr = 189,
    syscall_x86_64_fsetxattr = 190,
    syscall_x86_64_getxattr = 191,
    syscall_x86_64_lgetxattr = 192,
    syscall_x86_64_fgetxattr = 193,
    syscall_x86_64_listxattr = 194,
    syscall_x86_64_llistxattr = 195,
    syscall_x86_64_flistxattr = 196,
    syscall_x86_64_removexattr = 197,
    syscall_x86_64_lremovexattr = 198,
    syscall_x86_64_fremovexattr = 199,
    syscall_x86_64_tkill = 200,
    syscall_x86_64_time = 201,
    syscall_x86_64_futex = 202,
    syscall_x86_64_sched_setaffinity = 203,
    syscall_x86_64_sched_getaffinity = 204,
    syscall_x86_64_set_thread_area = 205,
    syscall_x86_64_io_setup = 206,
    syscall_x86_64_io_destroy = 207,
    syscall_x86_64_io_getevents = 208,
    syscall_x86_64_io_submit = 209,
    syscall_x86_64_io_cancel = 210,
    syscall_x86_64_get_thread_area = 211,
    syscall_x86_64_lookup_dcookie = 212,
    syscall_x86_64_epoll_create = 213,
    syscall_x86_64_epoll_ctl_old = 214,
    syscall_x86_64_epoll_wait_old = 215,
    syscall_x86_64_remap_file_pages = 216,
    syscall_x86_64_getdents64 = 217,
    syscall_x86_64_set_tid_address = 218,
    syscall_x86_64_restart_syscall = 219,
    syscall_x86_64_semtimedop = 220,
    syscall_x86_64_fadvise64 = 221,
    syscall_x86_64_timer_create = 222,
    syscall_x86_64_timer_settime = 223,
    syscall_x86_64_timer_gettime = 224,
    syscall_x86_64_timer_getoverrun = 225,
    syscall_x86_64_timer_delete = 226,
    syscall_x86_64_clock_settime = 227,
    syscall_x86_64_clock_gettime = 228,
    syscall_x86_64_clock_getres = 229,
    syscall_x86_64_clock_nanosleep = 230,
    syscall_x86_64_exit_group = 231,
    syscall_x86_64_epoll_wait = 232,
    syscall_x86_64_epoll_ctl = 233,
    syscall_x86_64_tgkill = 234,
    syscall_x86_64_utimes = 235,
    syscall_x86_64_vserver = 236,
    syscall_x86_64_mbind = 237,
    syscall_x86_64_set_mempolicy = 238,
    syscall_x86_64_get_mempolicy = 239,
    syscall_x86_64_mq_open = 240,
    syscall_x86_64_mq_unlink = 241,
    syscall_x86_64_mq_timedsend = 242,
    syscall_x86_64_mq_timedreceive = 243,
    syscall_x86_64_mq_notify = 244,
    syscall_x86_64_mq_getsetattr = 245,
    syscall_x86_64_kexec_load = 246,
    syscall_x86_64_waitid = 247,
    syscall_x86_64_add_key = 248,
    syscall_x86_64_request_key = 249,
    syscall_x86_64_keyctl = 250,
    syscall_x86_64_ioprio_set = 251,
    syscall_x86_64_ioprio_get = 252,
    syscall_x86_64_inotify_init = 253,
    syscall_x86_64_inotify_add_watch = 254,
    syscall_x86_64_inotify_rm_watch = 255,
    syscall_x86_64_migrate_pages = 256,
    syscall_x86_64_openat = 257,
    syscall_x86_64_mkdirat = 258,
    syscall_x86_64_mknodat = 259,
    syscall_x86_64_fchownat = 260,
    syscall_x86_64_futimesat = 261,
    syscall_x86_64_fstatat64 = 262,
    syscall_x86_64_unlinkat = 263,
    syscall_x86_64_renameat = 264,
    syscall_x86_64_linkat = 265,
    syscall_x86_64_symlinkat = 266,
    syscall_x86_64_readlinkat = 267,
    syscall_x86_64_fchmodat = 268,
    syscall_x86_64_faccessat = 269,
    syscall_x86_64_pselect6 = 270,
    syscall_x86_64_ppoll = 271,
    syscall_x86_64_unshare = 272,
    syscall_x86_64_set_robust_list = 273,
    syscall_x86_64_get_robust_list = 274,
    syscall_x86_64_splice = 275,
    syscall_x86_64_tee = 276,
    syscall_x86_64_sync_file_range = 277,
    syscall_x86_64_vmsplice = 278,
    syscall_x86_64_move_pages = 279,
    syscall_x86_64_utimensat = 280,
    syscall_x86_64_epoll_pwait = 281,
    syscall_x86_64_signalfd = 282,
    syscall_x86_64_timerfd_create = 283,
    syscall_x86_64_eventfd = 284,
    syscall_x86_64_fallocate = 285,
    syscall_x86_64_timerfd_settime = 286,
    syscall_x86_64_timerfd_gettime = 287,
    syscall_x86_64_accept4 = 288,
    syscall_x86_64_signalfd4 = 289,
    syscall_x86_64_eventfd2 = 290,
    syscall_x86_64_epoll_create1 = 291,
    syscall_x86_64_dup3 = 292,
    syscall_x86_64_pipe2 = 293,
    syscall_x86_64_inotify_init1 = 294,
    syscall_x86_64_preadv = 295,
    syscall_x86_64_pwritev = 296,
    syscall_x86_64_rt_tgsigqueueinfo = 297,
    syscall_x86_64_perf_event_open = 298,
    syscall_x86_64_recvmmsg = 299,
    syscall_x86_64_fanotify_init = 300,
    syscall_x86_64_fanotify_mark = 301,
    syscall_x86_64_prlimit64 = 302,
    syscall_x86_64_name_to_handle_at = 303,
    syscall_x86_64_open_by_handle_at = 304,
    syscall_x86_64_clock_adjtime = 305,
    syscall_x86_64_syncfs = 306,
    syscall_x86_64_sendmmsg = 307,
    syscall_x86_64_setns = 308,
    syscall_x86_64_getcpu = 309,
    syscall_x86_64_process_vm_readv = 310,
    syscall_x86_64_process_vm_writev = 311,
    syscall_x86_64_kcmp = 312,
    syscall_x86_64_finit_module = 313,
    syscall_x86_64_sched_setattr = 314,
    syscall_x86_64_sched_getattr = 315,
    syscall_x86_64_renameat2 = 316,
    syscall_x86_64_seccomp = 317,
    syscall_x86_64_getrandom = 318,
    syscall_x86_64_memfd_create = 319,
    syscall_x86_64_kexec_file_load = 320,
    syscall_x86_64_bpf = 321,
    syscall_x86_64_execveat = 322,
    syscall_x86_64_userfaultfd = 323,
    syscall_x86_64_membarrier = 324,
    syscall_x86_64_mlock2 = 325,
    syscall_x86_64_copy_file_range = 326,
    syscall_x86_64_preadv2 = 327,
    syscall_x86_64_pwritev2 = 328,
    syscall_x86_64_pkey_mprotect = 329,
    syscall_x86_64_pkey_alloc = 330,
    syscall_x86_64_pkey_free = 331,
    syscall_x86_64_statx = 332,
    syscall_x86_64_io_pgetevents = 333,
    syscall_x86_64_rseq = 334,
    syscall_x86_64_pidfd_send_signal = 424,
    syscall_x86_64_io_uring_setup = 425,
    syscall_x86_64_io_uring_enter = 426,
    syscall_x86_64_io_uring_register = 427,
    syscall_x86_64_open_tree = 428,
    syscall_x86_64_move_mount = 429,
    syscall_x86_64_fsopen = 430,
    syscall_x86_64_fsconfig = 431,
    syscall_x86_64_fsmount = 432,
    syscall_x86_64_fspick = 433,
    syscall_x86_64_pidfd_open = 434,
    syscall_x86_64_clone3 = 435,
    syscall_x86_64_close_range = 436,
    syscall_x86_64_openat2 = 437,
    syscall_x86_64_pidfd_getfd = 438,
    syscall_x86_64_faccessat2 = 439,
    syscall_x86_64_process_madvise = 440,
    syscall_x86_64_epoll_pwait2 = 441,
    syscall_x86_64_mount_setattr = 442,
    syscall_x86_64_quotactl_fd = 443,
    syscall_x86_64_landlock_create_ruleset = 444,
    syscall_x86_64_landlock_add_rule = 445,
    syscall_x86_64_landlock_restrict_self = 446,
    syscall_x86_64_memfd_secret = 447,
    syscall_x86_64_process_mrelease = 448,
    syscall_x86_64_futex_waitv = 449,
    syscall_x86_64_set_mempolicy_home_node = 450,
    syscall_x86_64_cachestat = 451,
    syscall_x86_64_fchmodat2 = 452,
    syscall_x86_64_map_shadow_stack = 453,
    syscall_x86_64_futex_wake = 454,
    syscall_x86_64_futex_wait = 455,
    syscall_x86_64_futex_requeue = 456,
};
#endif
#endif

#ifndef _WIN32
may_be_unused fn void* posix_mmap(void* address, size_t length, int protection_flags, int map_flags, int fd, signed long offset)
{
#if LINK_LIBC
    return mmap(address, length, protection_flags, map_flags, fd, offset);
#else 
#ifdef __linux__
    return (void*) syscall6(syscall_x86_64_mmap, (s64)address, cast_to(s64, u64, length), protection_flags, map_flags, fd, offset);
#else
#error "Unsupported operating system for static linking" 
#endif
#endif
}

may_be_unused fn int syscall_mprotect(void *address, size_t length, int protection_flags)
{
#if LINK_LIBC
    return mprotect(address, length, protection_flags);
#else 
#ifdef __linux__
    return cast_to(s32, s64, syscall3(syscall_x86_64_mprotect, (s64)address, cast_to(s64, u64, length), protection_flags));
#else
    return mprotect(address, length, protection_flags);
#endif
#endif
}

may_be_unused fn int syscall_open(const char *file_path, int flags, int mode)
{
#if LINK_LIBC
    return open(file_path, flags, mode);
#else
#ifdef __linux__
    return cast_to(s32, s64, syscall3(syscall_x86_64_open, (s64)file_path, flags, mode));
#else
    return open(file_path, flags, mode);
#endif
#endif
}

may_be_unused fn int syscall_close(int fd)
{
#if LINK_LIBC
    return close(fd);
#else
#ifdef __linux__
    return cast_to(s32, s64, syscall1(syscall_x86_64_close, fd));
#else
    return close(fd);
#endif
#endif
}

fn int syscall_fstat(int fd, struct stat *buffer)
{
#if LINK_LIBC
    return fstat(fd, buffer);
#else
#ifdef __linux__
    return cast_to(s32, s64, syscall2(syscall_x86_64_fstat, fd, (s64)buffer));
#else
    return fstat(fd, buffer);
#endif
#endif
}

may_be_unused fn ssize_t syscall_read(int fd, void* buffer, size_t bytes)
{
#if LINK_LIBC
    return read(fd, buffer, bytes);
#else
#ifdef __linux__
    return syscall3(syscall_x86_64_read, fd, (s64)buffer, (s64)bytes);
#else
    return read(fd, buffer, bytes);
#endif
#endif
}

may_be_unused fn ssize_t syscall_write(int fd, const void *buffer, size_t bytes)
{
#if LINK_LIBC
    return write(fd, buffer, bytes);
#else
#ifdef __linux__
    return syscall3(syscall_x86_64_write, fd, (s64)buffer, (s64)bytes);
#else
    return write(fd, buffer, bytes);
#endif
#endif
}

may_be_unused fn int syscall_mkdir(String path, u32 mode)
{
    assert(path.pointer[path.length] == 0);
#if LINK_LIBC
    return mkdir((char*)path.pointer, mode);
#else
    return cast_to(s32, s64, syscall2(syscall_x86_64_mkdir, (s64)path.pointer, (s64)mode));
#endif
}

may_be_unused fn int syscall_rmdir(String path)
{
    assert(path.pointer[path.length] == 0);
#if LINK_LIBC
    return rmdir((char*)path.pointer);
#else
    return cast_to(s32, s64, syscall1(syscall_x86_64_rmdir, (s64)path.pointer));
#endif
}

may_be_unused fn int syscall_unlink(String path)
{
    assert(path.pointer[path.length] == 0);
#if LINK_LIBC
    return unlink((char*)path.pointer);
#else
    return cast_to(s32, s64, syscall1(syscall_x86_64_unlink, (s64)path.pointer));
#endif
}

may_be_unused fn pid_t syscall_fork()
{
#if LINK_LIBC
    return fork();
#else
    return cast_to(s32, s64, syscall0(syscall_x86_64_fork));
#endif

}

may_be_unused fn signed long syscall_execve(const char* path, char *const argv[], char *const envp[])
{
#if LINK_LIBC
    return execve(path, argv, envp);
#else
    return syscall3(syscall_x86_64_execve, (s64)path, (s64)argv, (s64)envp);
#endif
}

may_be_unused fn pid_t syscall_waitpid(pid_t pid, int* status, int options)
{
#if LINK_LIBC
    return waitpid(pid, status, options);
#else
    return cast_to(s32, s64, syscall4(syscall_x86_64_wait4, pid, (s64)status, options, 0));
#endif
}

may_be_unused fn int syscall_gettimeofday(struct timeval* tv, struct timezone* tz)
{
#if LINK_LIBC
    return gettimeofday(tv, tz);
#else
    return cast_to(s32, s64, syscall2(syscall_x86_64_gettimeofday, (s64)tv, (s64)tz));
#endif
}

may_be_unused [[noreturn]] [[gnu::cold]] fn void syscall_exit(int status)
{
#if LINK_LIBC
    _exit(status);
#else
#ifdef __linux__
    (void)syscall1(231, status);
    trap();
#else
    _exit(status);
#endif
#endif
}
#endif

may_be_unused fn u64 os_timer_freq()
{
    return 1000 * 1000;
}

may_be_unused fn u64 os_timer_get()
{
#if _WIN32
    LARGE_INTEGER large_integer;
    QueryPerformanceCounter(&large_integer);
    return (u64)large_integer.QuadPart;
#else
    struct timeval tv;
    syscall_gettimeofday(&tv, 0);
    auto result = os_timer_freq() * cast_to(u64, s64, tv.tv_sec) + cast_to(u64, s64, tv.tv_usec);
    return result;
#endif
}

u8 os_file_descriptor_is_valid(FileDescriptor fd)
{
#if _WIN32
    return fd != INVALID_HANDLE_VALUE;
#else
    return fd >= 0;
#endif
}

FileDescriptor os_file_open(String path, OSFileOpenFlags flags, OSFilePermissions permissions)
{
    assert(path.pointer[path.length] == 0);
#if _WIN32
    DWORD dwDesiredAccess = 0;
    dwDesiredAccess |= flags.read * GENERIC_READ;
    dwDesiredAccess |= flags.write * GENERIC_WRITE;
    dwDesiredAccess |= flags.executable * GENERIC_EXECUTE;
    DWORD dwShareMode = 0;
    LPSECURITY_ATTRIBUTES lpSecurityAttributes = 0;
    DWORD dwCreationDisposition = 0;
    dwCreationDisposition |= (!flags.create) * OPEN_EXISTING;
    dwCreationDisposition |= flags.create * CREATE_ALWAYS;
    DWORD dwFlagsAndAttributes = 0;
    dwFlagsAndAttributes |= FILE_ATTRIBUTE_NORMAL;
    dwFlagsAndAttributes |= flags.directory * FILE_FLAG_BACKUP_SEMANTICS;
    HANDLE hTemplateFile = 0;

    auto handle = CreateFileA(string_to_c(path), dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    return handle;
#else
    int posix_flags = 0;
    posix_flags |= O_WRONLY * (flags.write & !flags.read);
    posix_flags |= O_RDONLY * ((!flags.write) & flags.read);
    posix_flags |= O_RDWR * (flags.write & flags.read);
    posix_flags |= O_CREAT * flags.create;
    posix_flags |= O_TRUNC * flags.truncate;

    int posix_permissions;
    // TODO: make permissions better
    if (permissions.executable)
    {
        posix_permissions = 0755;
    }
    else
    {
        posix_permissions = 0644;
    }
    auto result = syscall_open((char*)path.pointer, posix_flags, posix_permissions);
    return result;
#endif
}

u64 os_file_get_size(FileDescriptor fd)
{
#if _WIN32
    LARGE_INTEGER file_size;
    BOOL result = GetFileSizeEx(fd, &file_size);
    assert(result != 0);
    return (u64)file_size.QuadPart;
#else
    struct stat stat_buffer;
    int stat_result = syscall_fstat(fd, &stat_buffer);
    assert(stat_result == 0);
    auto size = cast_to(u64, s64, stat_buffer.st_size);
    return size;
#endif
}

void os_file_write(FileDescriptor fd, String content)
{
#if _WIN32
    DWORD bytes_written = 0;
    BOOL result = WriteFile(fd, content.pointer, cast_to(u32, u64, content.length), &bytes_written, 0);
    assert(result != 0);
#else
    auto result = syscall_write(fd, content.pointer, content.length);
    assert(cast_to(u64, s64, result) == content.length);
#endif
}

may_be_unused fn u64 os_file_read(FileDescriptor fd, String buffer, u64 byte_count)
{
    assert(byte_count);
    assert(byte_count <= buffer.length);
    u64 bytes_read = 0;
    if (byte_count <= buffer.length)
    {
#if _WIN32
        DWORD read = 0;
        BOOL result = ReadFile(fd, buffer.pointer, cast_to(u32, u64, byte_count), &read, 0);
        assert(result != 0);
        bytes_read = read;
#else
        auto result = syscall_read(fd, buffer.pointer, byte_count);
        assert(result > 0);
        if (result > 0)
        {
            bytes_read = cast_to(u64, s64, result);
        }
#endif
    }
    assert(bytes_read == byte_count);
    return bytes_read;
}

void os_file_close(FileDescriptor fd)
{
#if _WIN32
    BOOL result = CloseHandle(fd);
    assert(result != 0);
#else
    auto result = syscall_close(fd);
    assert(result == 0);
#endif
}

void calibrate_cpu_timer()
{
#ifndef SILENT
#if _WIN32
    LARGE_INTEGER li;
    QueryPerformanceFrequency(&li);
    cpu_frequency = (u64)li.QuadPart;
#else
#if LINK_LIBC
    clock_getres(CLOCK_MONOTONIC, &cpu_resolution);
#else
    u64 miliseconds_to_wait = 100;
    u64 cpu_start = timestamp();
    u64 os_frequency = os_timer_freq();
    u64 os_elapsed = 0;
    u64 os_start = os_timer_get();
    u64 os_wait_time = os_frequency * miliseconds_to_wait / 1000;

    while (os_elapsed < os_wait_time)
    {
        auto os_end = os_timer_get();
        os_elapsed = os_end - os_start;
    }

    u64 cpu_end = timestamp();
    u64 cpu_elapsed = cpu_end - cpu_start;
    cpu_frequency = os_frequency * cpu_elapsed / os_elapsed;
#endif
#endif
#endif
}

u8* os_reserve(u64 base, u64 size, OSReserveProtectionFlags protection, OSReserveMapFlags map)
{
#if _WIN32
    DWORD map_flags = 0;
    map_flags |= (MEM_RESERVE * map.noreserve);
    DWORD protection_flags = 0;
    protection_flags |= PAGE_READWRITE * (!protection.write && !protection.read);
    protection_flags |= PAGE_READWRITE * (protection.write && protection.read);
    protection_flags |= PAGE_READONLY * (protection.write && !protection.read);
    return (u8*)VirtualAlloc((void*)base, size, map_flags, protection_flags);
#else
    int protection_flags = (protection.read * PROT_READ) | (protection.write * PROT_WRITE) | (protection.execute * PROT_EXEC);
    int map_flags = (map.anon * MAP_ANONYMOUS) | (map.priv * MAP_PRIVATE) | (map.noreserve * MAP_NORESERVE);
    u8* result = (u8*)posix_mmap((void*)base, size, protection_flags, map_flags, -1, 0);
    assert(result != MAP_FAILED);
    return result;
#endif
}

void os_commit(void* address, u64 size)
{
#if _WIN32
    VirtualAlloc(address, size, MEM_COMMIT, PAGE_READWRITE);
#else
    int result = syscall_mprotect(address, size, PROT_READ | PROT_WRITE);
    assert(result == 0);
#endif
}

void os_directory_make(String path)
{
    assert(path.pointer[path.length] == 0);
#if _WIN32
    CreateDirectoryA((char*)path.pointer, 0);
#else
    syscall_mkdir(path, 0755);
#endif
}

void print(const char* format, ...)
{
#ifndef SILENT
        u8 stack_buffer[4096];
        va_list args;
        va_start(args, format);
        String buffer = { .pointer = stack_buffer, .length = array_length(stack_buffer) };
        u8* it = (u8*)format;
        u64 buffer_i = 0;

        while (*it)
        {
            while (*it && *it != brace_open)
            {
                s_get(buffer, buffer_i) = *it;
                buffer_i += 1;
                it += 1;
            }

            if (*it == brace_open)
            {
                it += 1;
                auto next_ch = *it;

                if (next_ch == brace_open)
                {
                    trap();
                }
                else
                {
                    switch (next_ch)
                    {
                        case 'c':
                            {
                                int done = 0;
                                it += 1;
                                if (*it == 's')
                                {
                                    it += 1;
                                    if (*it == 't')
                                    {
                                        it += 1;
                                        if (*it == 'r')
                                        {
                                            it += 1;
                                            done = 1;
                                            auto* cstring = va_arg(args, const u8*);
                                            while (*cstring)
                                            {
                                                buffer.pointer[buffer_i] = *cstring;
                                                buffer_i += 1;
                                                cstring += 1;
                                            }
                                        }
                                    }
                                }
                                else
                                {
                                    auto character = cast_to(u8, u32, va_arg(args, u32));
                                    buffer.pointer[buffer_i] = character;
                                    buffer_i += 1;
                                    done = 1;
                                }

                                assert(done);
                            } break;
                        case 'f':
                            {
                                it += 1;
                                f64 value_double;
                                switch (*it)
                                {
                                    case '3':
                                        it += 1;
                                        if (*it != '2')
                                        {
                                            failed_execution();
                                        }
                                        it += 1;
                                        failed_execution();
                                        break;
                                    case '6':
                                        it += 1;
                                        if (*it != '4')
                                        {
                                            failed_execution();
                                        }
                                        it += 1;
                                        value_double = va_arg(args, f64);
                                        break;
                                    default:
                                        failed_execution();
                                }

                                buffer_i += format_float(s_get_slice(u8, buffer, buffer_i, buffer.length), value_double);
                            } break;
                        case 's':
                            {
                                it += 1;

                                if (is_decimal_digit(*it))
                                {
                                    u8* bit_count_start = it;
                                    while (is_decimal_digit(*it))
                                    {
                                        it += 1;
                                    }

                                    u8* bit_count_end = it;
                                    u64 bit_count = parse_decimal(slice_from_pointer_range(u8, (u8*)bit_count_start, (u8*)bit_count_end));

                                    typedef enum IntegerFormat : u8
                                    {
                                        INTEGER_FORMAT_HEXADECIMAL,
                                        INTEGER_FORMAT_DECIMAL,
                                        INTEGER_FORMAT_OCTAL,
                                        INTEGER_FORMAT_BINARY,
                                    } IntegerFormat;

                                    IntegerFormat format = INTEGER_FORMAT_DECIMAL;

                                    if (*it == ':')
                                    {
                                        it += 1;
                                        switch (*it)
                                        {
                                            case 'x':
                                                format = INTEGER_FORMAT_HEXADECIMAL;
                                                break;
                                            case 'd':
                                                format = INTEGER_FORMAT_DECIMAL;
                                                break;
                                            case 'o':
                                                format = INTEGER_FORMAT_OCTAL;
                                                break;
                                            case 'b':
                                                format = INTEGER_FORMAT_BINARY;
                                                break;
                                            default:
                                                trap();
                                        }

                                        it += 1;
                                    }

                                    s64 original_value;
                                    switch (bit_count)
                                    {
                                        case 8:
                                        case 16:
                                        case 32:
                                            original_value = va_arg(args, s32);
                                            break;
                                        case 64:
                                            original_value = va_arg(args, s64);
                                            break;
                                        default:
                                            trap();
                                    }

                                    auto buffer_slice = s_get_slice(u8, buffer, buffer_i, buffer.length);

                                    switch (format)
                                    {
                                        case INTEGER_FORMAT_HEXADECIMAL:
                                            {
                                                auto written_characters = format_hexadecimal(buffer_slice, original_value);
                                                buffer_i += written_characters;
                                            } break;
                                        case INTEGER_FORMAT_DECIMAL:
                                            {
                                                u64 value;
                                                if (original_value < 0)
                                                {
                                                    buffer_slice.pointer[0] = '-';
                                                    buffer_slice.pointer += 1;
                                                    buffer_slice.length -= 1;
                                                    buffer_i += 1;
                                                    value = (u64)(-(original_value - (original_value == INT64_MIN))) + (original_value == INT64_MIN);
                                                }
                                                else
                                                {
                                                    value = (u64)original_value;
                                                }

                                                auto written_characters = format_decimal(buffer_slice, value);
                                                buffer_i += written_characters;
                                            } break;
                                        case INTEGER_FORMAT_OCTAL:
                                        case INTEGER_FORMAT_BINARY:
                                            trap();
                                    }
                                }
                                else
                                {
                                    String string = va_arg(args, String);
                                    memcpy(buffer.pointer + buffer_i, string.pointer, string.length);
                                    buffer_i += string.length;
                                }

                            } break;
                        case 'u':
                            {
                                it += 1;

                                u8* bit_count_start = it;
                                while (is_decimal_digit(*it))
                                {
                                    it += 1;
                                }

                                u8* bit_count_end = it;
                                u64 bit_count = parse_decimal(slice_from_pointer_range(u8, (u8*)bit_count_start, (u8*)bit_count_end));

                                typedef enum IntegerFormat : u8
                                {
                                    INTEGER_FORMAT_HEXADECIMAL,
                                    INTEGER_FORMAT_DECIMAL,
                                    INTEGER_FORMAT_OCTAL,
                                    INTEGER_FORMAT_BINARY,
                                } IntegerFormat;

                                IntegerFormat format = INTEGER_FORMAT_DECIMAL;

                                if (*it == ':')
                                {
                                    it += 1;
                                    switch (*it)
                                    {
                                        case 'x':
                                            format = INTEGER_FORMAT_HEXADECIMAL;
                                            break;
                                        case 'd':
                                            format = INTEGER_FORMAT_DECIMAL;
                                            break;
                                        case 'o':
                                            format = INTEGER_FORMAT_OCTAL;
                                            break;
                                        case 'b':
                                            format = INTEGER_FORMAT_BINARY;
                                            break;
                                        default:
                                            trap();
                                    }

                                    it += 1;
                                }

                                u64 original_value;
                                switch (bit_count)
                                {
                                    case 8:
                                    case 16:
                                    case 32:
                                        original_value = va_arg(args, u32);
                                        break;
                                    case 64:
                                        original_value = va_arg(args, u64);
                                        break;
                                    default:
                                        trap();
                                }

                                auto buffer_slice = s_get_slice(u8, buffer, buffer_i, buffer.length);

                                switch (format)
                                {
                                    case INTEGER_FORMAT_HEXADECIMAL:
                                        {
                                            auto written_characters = format_hexadecimal(buffer_slice, original_value);
                                            buffer_i += written_characters;
                                        } break;
                                    case INTEGER_FORMAT_DECIMAL:
                                        {
                                            auto written_characters = format_decimal(buffer_slice, original_value);
                                            buffer_i += written_characters;
                                        } break;
                                    case INTEGER_FORMAT_OCTAL:
                                    case INTEGER_FORMAT_BINARY:
                                        trap();
                                }
                            } break;
                        default:
                            buffer.pointer[buffer_i] = '{';
                            buffer_i += 1;
                            continue;
                    }

                    if (*it != brace_close)
                    {
                        failed_execution();
                    }

                    it += 1;
                }
            }
        }

        String final_string = s_get_slice(u8, buffer, 0, buffer_i);
        os_file_write(os_stdout_get(), final_string);
#endif
}


static_assert(sizeof(Arena) == 64);

Arena* arena_init(u64 reserved_size, u64 granularity, u64 initial_size)
{
    Arena* arena = (Arena*)os_reserve(0, reserved_size,
            (OSReserveProtectionFlags) {
                .read = 1,
                .write = 1,
            },
            (OSReserveMapFlags) {
                .priv = 1,
                .anon = 1,
                .noreserve = 1,
            });
    os_commit(arena, initial_size);
    *arena = (Arena){
        .reserved_size = reserved_size,
        .committed = initial_size,
        .commit_position = sizeof(Arena),
        .granularity = granularity,
    };
    return arena;
}

Arena* arena_init_default(u64 initial_size)
{
    return arena_init(default_size, minimum_granularity, initial_size);
}

u8* arena_allocate_bytes(Arena* arena, u64 size, u64 alignment)
{
    u64 aligned_offset = align_forward(arena->commit_position, alignment);
    u64 aligned_size_after = aligned_offset + size;

    if (aligned_size_after > arena->committed)
    {
        u64 committed_size = align_forward(aligned_size_after, arena->granularity);
        u64 size_to_commit = committed_size - arena->committed;
        void* commit_pointer = (u8*)arena + arena->committed;
        os_commit(commit_pointer, size_to_commit);
        arena->committed = committed_size;
    }

    auto* result = (u8*)arena + aligned_offset;
    arena->commit_position = aligned_size_after;
    assert(arena->commit_position <= arena->committed);
    return result;
}

String arena_join_string(Arena* arena, Slice(String) pieces)
{
    u64 size = 0;
    for (u64 i = 0; i < pieces.length; i += 1)
    {
        String piece = pieces.pointer[i];
        size += piece.length;
    }

    u8* pointer = arena_allocate_bytes(arena, size + 1, 1);
    auto* it = pointer;
    for (u64 i = 0; i < pieces.length; i += 1)
    {
        String piece = pieces.pointer[i];
        memcpy(it, piece.pointer, piece.length);
        it += piece.length;
    }
    assert((u64)(it - pointer) == size);
    *it = 0;

    return (String) { .pointer = pointer, .length = size };
}


void arena_reset(Arena* arena)
{
    arena->commit_position = sizeof(Arena);
    memset(arena + 1, 0, arena->committed - sizeof(Arena));
}

#define transmute(D, source) *(D*)&source

String file_read(Arena* arena, String path)
{
    String result = {};
    auto file_descriptor = os_file_open(path, (OSFileOpenFlags) {
        .truncate = 0,
        .executable = 0,
        .write = 0,
        .read = 1,
        .create = 0,
    }, (OSFilePermissions) {
        .readable = 1,
    });

    if (os_file_descriptor_is_valid(file_descriptor))
    {
        auto file_size = os_file_get_size(file_descriptor);
        if (file_size > 0)
        {
            result = (String){
                .pointer = arena_allocate_bytes(arena, file_size, 64),
                    .length = file_size,
            };

            // TODO: big files
            // TODO: result codes
            os_file_read(file_descriptor, result, file_size);
        }
        else
        {
            result.pointer = (u8*)&result;
        }

        // TODO: check result
        os_file_close(file_descriptor);
    }


    return result;
}

void file_write(FileWriteOptions options)
{
    print("Writing file \"{s}\"...\n", options.path);
    auto fd = os_file_open(options.path, (OSFileOpenFlags) {
        .write = 1,
        .truncate = 1,
        .create = 1,
        .executable = options.executable,
    }, (OSFilePermissions) {
        .readable = 1,
        .writable = 1,
        .executable = options.executable,
    });
    assert(os_file_descriptor_is_valid(fd));

    os_file_write(fd, options.content);
    os_file_close(fd);
}

void run_command(Arena* arena, CStringSlice arguments, char* envp[])
{
    print("Running command:\n");
    assert(arguments.length > 0);
    assert(arguments.pointer[arguments.length - 1] == 0);
    for (u32 i = 0; i < arguments.length - 1; i += 1)
    {
        char* argument = arguments.pointer[i];
        print("{cstr} ", argument);
    }
    print("\n");

#if _WIN32
    auto start_timestamp = timestamp();

    u32 length = 0;
    for (u32 i = 0; i < arguments.length; i += 1)
    {
        auto argument = arguments.pointer[i];
        if (argument)
        {
            auto string_len = strlen(argument);
            length += cast_to(u32, u64, string_len + 1);
        }
    }

    char* bytes = (char*)arena_allocate_bytes(arena, length, 1);
    u32 byte_i = 0;
    for (u32 i = 0; i < arguments.length; i += 1)
    {
        auto argument = arguments.pointer[i];
        if (argument)
        {
            auto len = strlen(argument);
            memcpy(&bytes[byte_i], argument, len);
            byte_i += len;
            bytes[byte_i] = ' ';
            byte_i += 1;
        }
    }
    bytes[byte_i - 1] = 0;
    auto end_timestamp = timestamp();

    PROCESS_INFORMATION process_information = {};
    STARTUPINFOA startup_info = {};
    startup_info.cb = sizeof(startup_info);
    startup_info.dwFlags |= STARTF_USESTDHANDLES;
    startup_info.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    startup_info.hStdError = GetStdHandle(STD_ERROR_HANDLE);

    auto handle_inheritance = 1;
    auto start = timestamp();
    if (CreateProcessA(0, bytes, 0, 0, handle_inheritance, 0, 0, 0, &startup_info, &process_information))
    {
        WaitForSingleObject(process_information.hProcess, INFINITE);
        auto end = timestamp();
        auto ms = resolve_timestamp(start, end, TIME_UNIT_MILLISECONDS);

        print("Process ran in {f64} ms\n", ms);
        DWORD exit_code;
        if (GetExitCodeProcess(process_information.hProcess, &exit_code))
        {
            print("Process ran with exit code: 0x{u32:x}\n", exit_code);
            if (exit_code != 0)
            {
                failed_execution();
            }
        }
        else
        {
            failed_execution();
        }

        CloseHandle(process_information.hProcess);
        CloseHandle(process_information.hThread);
    }
    else
    {
        print("Failure\n");
        auto err = GetLastError();
        LPSTR lpMsgBuf;
        DWORD bufSize = FormatMessageA(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL,
                err,
                LANG_NEUTRAL, // Use default language
                (LPSTR)&lpMsgBuf,
                0,
                NULL
                );
        unused(bufSize);
        todo();
    }
    unused(start_timestamp);
    unused(end_timestamp);
    unused(envp);
#else
    unused(arena);
    pid_t pid = syscall_fork();

    if (pid == -1)
    {
        trap();
    }

    auto start_timestamp = timestamp();

    if (pid == 0)
    {
        // close(pipes[0]);
        // fcntl(pipes[1], F_SETFD, FD_CLOEXEC);
        auto result = syscall_execve(arguments.pointer[0], arguments.pointer, envp);
#if LINK_LIBC
        print("Execve failed! Error: {cstr}\n", strerror(errno));
#else
        trap();
#endif
        unused(result);
        trap();
    }
    else
    {
        int status = 0;
        int options = 0;
        pid_t result = syscall_waitpid(pid, &status, options);
        auto end_timestamp = timestamp();
        int success = 0;
        if (result == pid)
        {
            print("{cstr} ", arguments.pointer[0]);
            
            if (WIFEXITED(status))
            {
                auto exit_code = WEXITSTATUS(status);
                success = exit_code == 0;
                print("exited with code {u32}\n", exit_code);
            }
            else if (WIFSIGNALED(status))
            {
                auto signal_code = WTERMSIG(status);
                print("was signaled: {u32}\n", signal_code);
            }
            else if (WIFSTOPPED(status))
            {
                auto stopped_code = WSTOPSIG(status);
                print("was stopped: {u32}\n", stopped_code);
            }
            else
            {
                print("terminated unexpectedly with status {u32}\n", status);
            }
        }
        else
        {
            trap();
        }

        if (!success)
        {
            print("Program failed to run!\n");
            failed_execution();
        }
        auto ms = resolve_timestamp(start_timestamp, end_timestamp, TIME_UNIT_MILLISECONDS);
        auto ticks =
#if LINK_LIBC
            0
#else
            cpu_frequency != 0
#endif
            ;
        print("Command run successfully in {f64} {cstr}\n", ms, ticks ? "ticks" : "ms");
    }
#endif
}

void print_string(String message)
{
#ifndef SILENT
    // TODO: check writes
    os_file_write(os_stdout_get(), message);
    // assert(result >= 0);
    // assert((u64)result == message.length);
#else
        unused(message);
#endif
}

#if _WIN32
HANDLE os_windows_get_module_handle()
{
    return GetModuleHandleW(0);
}
#endif
