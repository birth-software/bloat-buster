#pragma once 

#include <std/string.h>
#include <std/format.h>
#include <std/virtual_buffer.h>

#include <std/string.c>
#include <std/format.c>
#include <std/virtual_buffer.c>

#if _WIN32
global_variable u64 cpu_frequency;
#else
#if LINK_LIBC
global_variable struct timespec cpu_resolution;
#else
global_variable u64 cpu_frequency;
#endif
#endif

fn Timestamp os_timestamp()
{
    Timestamp result;

#if _WIN32
    LARGE_INTEGER li;
    QueryPerformanceCounter(&li);
    result.value = u128_from_u64(li.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    result.value = u128_u64_or(u128_shift_left(u128_from_u64(ts.tv_sec), 64), ts.tv_nsec);
#endif

    return result;
}

fn f64 os_resolve_timestamps(Timestamp start, Timestamp end, TimeUnit time_unit)
{
    f64 result;
#if _WIN32
    let(start_tick, (s64)u64_from_u128(start.value));
    let(end_tick, (s64)u64_from_u128(end.value));

    let(seconds, (f64)(end_tick - start_tick) / cpu_frequency);

    switch (time_unit)
    {
        case TIME_UNIT_NANOSECONDS:
            result = seconds * 1000000000.0;
            break;
        case TIME_UNIT_MICROSECONDS:
            result = seconds * 1000000.0;
            break;
        case TIME_UNIT_MILLISECONDS:
            result = seconds * 1000.0;
            break;
        case TIME_UNIT_SECONDS:
            result = seconds;
            break;
    }
#else
    let(segmented_nanoseconds, (s64)u64_from_u128(end.value) - (s64)u64_from_u128(start.value));
    let(segmented_seconds, (s64)u128_shift_right_by_64(end.value) - (s64)u128_shift_right_by_64(start.value));

    if (segmented_nanoseconds < 0)
    {
        segmented_seconds -= 1;
        segmented_nanoseconds += 1000000000;
    }

    let(total_ns, segmented_seconds * 1000000000 + segmented_nanoseconds);

    switch (time_unit)
    {
        case TIME_UNIT_NANOSECONDS:
            result = total_ns;
            break;
        case TIME_UNIT_MICROSECONDS:
            result = total_ns / 1000.0;
            break;
        case TIME_UNIT_MILLISECONDS:
            result = total_ns / 1000000.0;
            break;
        case TIME_UNIT_SECONDS:
            result = total_ns / 1000000000.0;
            break;
    }
#endif

    return result;
}

fn FileDescriptor os_stdout_get()
{
#if _WIN32
    let(handle, GetStdHandle(STD_OUTPUT_HANDLE));
    assert(handle != INVALID_HANDLE_VALUE);
    return handle;
#else
    return 1;
#endif
}

fn String path_dir(String string)
{
    String result = {};
    let(index, string_last_ch(string, '/'));
    if (index != STRING_NO_MATCH)
    {
        result = s_get_slice(u8, string, 0, index);
    }

    return result;
}

fn String path_base(String string)
{
    String result = {};
    let(index, string_last_ch(string, '/'));
    if (index != STRING_NO_MATCH)
    {
        result = s_get_slice(u8, string, index + 1, string.length);
    }
#if _WIN32
    if (!result.pointer)
    {
        index = string_last_ch(string, '\\');
        if (index != STRING_NO_MATCH)
        {
            result = s_get_slice(u8, string, index + 1, string.length);
        }
    }
#endif

    return result;
}

fn String path_no_extension(String string)
{
    String result = {};
    let(index, string_last_ch(string, '.'));
    if (index != STRING_NO_MATCH)
    {
        result = s_get_slice(u8, string, 0, index);
    }

    return result;
}

#if LINK_LIBC == 0
#ifdef __linux__
fn forceinline long syscall0(long n)
{
    long ret;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n) : "rcx", "r11", "memory");
    return ret;
}

fn forceinline long syscall1(long n, long a1)
{
    long ret;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1) : "rcx", "r11", "memory");
    return ret;
}

fn forceinline long syscall2(long n, long a1, long a2)
{
    long ret;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2)
    : "rcx", "r11", "memory");
    return ret;
}

fn forceinline long syscall3(long n, long a1, long a2, long a3)
{
    long ret;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
    "d"(a3) : "rcx", "r11", "memory");
    return ret;
}

fn forceinline long syscall4(long n, long a1, long a2, long a3, long a4)
{
    long ret;
    register long r10 __asm__("r10") = a4;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
    "d"(a3), "r"(r10): "rcx", "r11", "memory");
    return ret;
}

fn forceinline long syscall5(long n, long a1, long a2, long a3, long a4, long a5)
{
    long ret;
    register long r10 __asm__("r10") = a4;
    register long r8 __asm__("r8") = a5;
    __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
    "d"(a3), "r"(r10), "r"(r8) : "rcx", "r11", "memory");
    return ret;
}

fn forceinline long syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6)
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
fn void* posix_mmap(void* address, size_t length, int protection_flags, int map_flags, int fd, signed long offset)
{
#if LINK_LIBC
    return mmap(address, length, protection_flags, map_flags, fd, offset);
#else 
#ifdef __linux__
    return (void*) syscall6(syscall_x86_64_mmap, (s64)address, cast_to(s64, length), protection_flags, map_flags, fd, offset);
#else
#error "Unsupported operating system for static linking" 
#endif
#endif
}

fn int syscall_mprotect(void *address, size_t length, int protection_flags)
{
#if LINK_LIBC
    return mprotect(address, length, protection_flags);
#else 
#ifdef __linux__
    return cast_to(s32, syscall3(syscall_x86_64_mprotect, (s64)address, cast_to(s64, length), protection_flags));
#else
    return mprotect(address, length, protection_flags);
#endif
#endif
}

fn int syscall_open(const char *file_path, int flags, int mode)
{
#if LINK_LIBC
    return open(file_path, flags, mode);
#else
#ifdef __linux__
    return cast_to(s32, syscall3(syscall_x86_64_open, (s64)file_path, flags, mode));
#else
    return open(file_path, flags, mode);
#endif
#endif
}

fn int syscall_close(int fd)
{
#if LINK_LIBC
    return close(fd);
#else
#ifdef __linux__
    return cast_to(s32, syscall1(syscall_x86_64_close, fd));
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
    return cast_to(s32, syscall2(syscall_x86_64_fstat, fd, (s64)buffer));
#else
    return fstat(fd, buffer);
#endif
#endif
}

fn ssize_t syscall_read(int fd, void* buffer, size_t bytes)
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

fn ssize_t syscall_write(int fd, const void *buffer, size_t bytes)
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

fn int syscall_mkdir(String path, u32 mode)
{
    assert(path.pointer[path.length] == 0);
#if LINK_LIBC
    return mkdir((char*)path.pointer, mode);
#else
    return cast_to(s32, syscall2(syscall_x86_64_mkdir, (s64)path.pointer, (s64)mode));
#endif
}

fn int syscall_rmdir(String path)
{
    assert(path.pointer[path.length] == 0);
#if LINK_LIBC
    return rmdir((char*)path.pointer);
#else
    return cast_to(s32, syscall1(syscall_x86_64_rmdir, (s64)path.pointer));
#endif
}

fn int syscall_unlink(String path)
{
    assert(path.pointer[path.length] == 0);
#if LINK_LIBC
    return unlink((char*)path.pointer);
#else
    return cast_to(s32, syscall1(syscall_x86_64_unlink, (s64)path.pointer));
#endif
}

fn pid_t syscall_fork()
{
#if LINK_LIBC
    return fork();
#else
    return cast_to(s32, syscall0(syscall_x86_64_fork));
#endif

}

fn signed long syscall_execve(const char* path, char *const argv[], char *const envp[])
{
#if LINK_LIBC
    return execve(path, argv, envp);
#else
    return syscall3(syscall_x86_64_execve, (s64)path, (s64)argv, (s64)envp);
#endif
}

fn pid_t syscall_waitpid(pid_t pid, int* status, int options)
{
#if LINK_LIBC
    return waitpid(pid, status, options);
#else
    return cast_to(s32, syscall4(syscall_x86_64_wait4, pid, (s64)status, options, 0));
#endif
}

fn int syscall_gettimeofday(struct timeval* tv, struct timezone* tz)
{
#if LINK_LIBC
    return gettimeofday(tv, tz);
#else
    return cast_to(s32, syscall2(syscall_x86_64_gettimeofday, (s64)tv, (s64)tz));
#endif
}

BB_NORETURN BB_COLD fn void syscall_exit(int status)
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

fn u64 os_timer_freq()
{
    return 1000 * 1000;
}

fn u64 os_timer_get()
{
#if _WIN32
    LARGE_INTEGER large_integer;
    QueryPerformanceCounter(&large_integer);
    return (u64)large_integer.QuadPart;
#else
    struct timeval tv;
    syscall_gettimeofday(&tv, 0);
    let(result, os_timer_freq() * cast_to(u64, tv.tv_sec) + cast_to(u64, tv.tv_usec));
    return result;
#endif
}

FileDescriptor os_file_descriptor_invalid()
{
#if _WIN32
    return INVALID_HANDLE_VALUE;
#else
    return -1;
#endif
}

fn u8 os_file_descriptor_is_valid(FileDescriptor fd)
{
#if _WIN32
    return fd != INVALID_HANDLE_VALUE;
#else
    return fd >= 0;
#endif
}

fn FileDescriptor os_file_open(String path, OSFileOpenFlags flags, OSFilePermissions permissions)
{
    assert(path.pointer[path.length] == 0);
#if _WIN32
    unused(permissions);

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

    let(handle, CreateFileA(string_to_c(path), dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile));
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
    let(result, syscall_open((char*)path.pointer, posix_flags, posix_permissions));
    return result;
#endif
}

fn u64 os_file_get_size(FileDescriptor fd)
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
    let_cast(u64, size, stat_buffer.st_size);
    return size;
#endif
}

fn void os_file_write(FileDescriptor fd, String content)
{
#if _WIN32
    DWORD bytes_written = 0;
    BOOL result = WriteFile(fd, content.pointer, cast_to(u32, content.length), &bytes_written, 0);
    assert(result != 0);
#else
    let(result, syscall_write(fd, content.pointer, content.length));
    let(my_errno, strerror(errno));
    unused(my_errno);
    assert(cast_to(u64, result) == content.length);
#endif
}

fn u64 os_file_read(FileDescriptor fd, String buffer, u64 byte_count)
{
    assert(byte_count);
    assert(byte_count <= buffer.length);
    u64 bytes_read = 0;
    if (byte_count <= buffer.length)
    {
#if _WIN32
        DWORD read = 0;
        BOOL result = ReadFile(fd, buffer.pointer, cast_to(u32, byte_count), &read, 0);
        assert(result != 0);
        bytes_read = read;
#else
        let(result, syscall_read(fd, buffer.pointer, byte_count));
        assert(result > 0);
        if (result > 0)
        {
            assign_cast(bytes_read, result);
        }
#endif
    }
    assert(bytes_read == byte_count);
    return bytes_read;
}

fn void os_file_close(FileDescriptor fd)
{
#if _WIN32
    BOOL result = CloseHandle(fd);
    assert(result != 0);
#else
    let(result, syscall_close(fd));
    assert(result == 0);
#endif
}

fn void calibrate_cpu_timer()
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
    u64 cpu_start = os_timestamp();
    u64 os_frequency = os_timer_freq();
    u64 os_elapsed = 0;
    u64 os_start = os_timer_get();
    u64 os_wait_time = os_frequency * miliseconds_to_wait / 1000;

    while (os_elapsed < os_wait_time)
    {
        let(os_end, os_timer_get());
        os_elapsed = os_end - os_start;
    }

    u64 cpu_end = os_timestamp();
    u64 cpu_elapsed = cpu_end - cpu_start;
    cpu_frequency = os_frequency * cpu_elapsed / os_elapsed;
#endif
#endif
#endif
}

fn u8* os_reserve(u64 base, u64 size, OSReserveProtectionFlags protection, OSReserveMapFlags map)
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
#ifdef __linux__
    map_flags |= (map.populate * MAP_POPULATE);
#endif
    u8* result = (u8*)posix_mmap((void*)base, size, protection_flags, map_flags, -1, 0);
    assert(result != MAP_FAILED);
    return result;
#endif
}

fn void os_commit(void* address, u64 size)
{
#if _WIN32
    VirtualAlloc(address, size, MEM_COMMIT, PAGE_READWRITE);
#else
    int result = syscall_mprotect(address, size, PROT_READ | PROT_WRITE);
    assert(result == 0);
#endif
}

fn void os_directory_make(String path)
{
    assert(path.pointer[path.length] == 0);
#if _WIN32
    CreateDirectoryA((char*)path.pointer, 0);
#else
    syscall_mkdir(path, 0755);
#endif
}

fn u8 os_is_being_debugged()
{
    u8 result = 0;
#if _WIN32
    result = IsDebuggerPresent() != 0;
#else
#ifdef __APPLE__
    let(request, PT_TRACE_ME);
#else
    let(request, PTRACE_TRACEME);
#endif
    if (ptrace(request, 0, 0, 0) == -1)
    {
        let(error, errno);
        if (error == EPERM)
        {
            result = 1;
        }
    }
#endif

    return result;
}

BB_NORETURN BB_COLD fn void os_exit(u32 exit_code)
{
    if (exit_code != 0 && os_is_being_debugged())
    {
        trap();
    }
    exit(exit_code);
}

fn void vprint(const char* format, va_list args)
{
    u8 stack_buffer[16*1024];
    String buffer = { .pointer = stack_buffer, .length = array_length(stack_buffer) };
    String final_string = format_string_va(buffer, format, args);
    os_file_write(os_stdout_get(), final_string);
}

fn void print(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    vprint(format, args);
    va_end(args);
}

static_assert(sizeof(Arena) == 64);
global_variable const u64 minimum_position = sizeof(Arena);

fn Arena* arena_initialize(u64 reserved_size, u64 granularity, u64 initial_size)
{
    OSReserveProtectionFlags protection_flags = {
        .read = 1,
        .write = 1,
    };
    OSReserveMapFlags map_flags = {
        .priv = 1,
        .anon = 1,
        .noreserve = 1,
    };
    Arena* arena = (Arena*)os_reserve(0, reserved_size, protection_flags, map_flags);
    os_commit(arena, initial_size);
    *arena = (Arena) {
        .reserved_size = reserved_size,
        .os_position = initial_size,
        .position = minimum_position,
        .granularity = granularity,
    };
    return arena;
}

fn Arena* arena_initialize_default(u64 initial_size)
{
    return arena_initialize(default_size, minimum_granularity, initial_size);
}

fn u8* arena_allocate_bytes(Arena* arena, u64 size, u64 alignment)
{
    u64 aligned_offset = align_forward_u64(arena->position, alignment);
    u64 aligned_size_after = aligned_offset + size;

    if (aligned_size_after > arena->os_position)
    {
        u64 committed_size = align_forward_u64(aligned_size_after, arena->granularity);
        u64 size_to_commit = committed_size - arena->os_position;
        void* commit_pointer = (u8*)arena + arena->os_position;
        os_commit(commit_pointer, size_to_commit);
        arena->os_position = committed_size;
    }

    let(result, (u8*)arena + aligned_offset);
    arena->position = aligned_size_after;
    assert(arena->position <= arena->os_position);
    return result;
}

fn String arena_join_string(Arena* arena, Slice(String) pieces)
{
    u64 size = 0;
    for (u64 i = 0; i < pieces.length; i += 1)
    {
        String piece = pieces.pointer[i];
        size += piece.length;
    }

    u8* pointer = arena_allocate_bytes(arena, size + 1, 1);
    let(it,  pointer);
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

fn String arena_duplicate_string(Arena* arena, String string)
{
    u8* result = arena_allocate(arena, u8, string.length + 1);
    memcpy(result, string.pointer, string.length);
    result[string.length] = 0;

    return (String) {
        .pointer = result,
        .length = string.length,
    };
}

fn void arena_reset(Arena* arena)
{
    arena->position = minimum_position;
    memset(arena + 1, 0, arena->position - minimum_position);
}

fn String file_read(Arena* arena, String path)
{
    String result = {};
    let(file_descriptor, os_file_open(path, (OSFileOpenFlags) {
        .truncate = 0,
        .executable = 0,
        .write = 0,
        .read = 1,
        .create = 0,
    }, (OSFilePermissions) {
        .readable = 1,
    }));

    if (os_file_descriptor_is_valid(file_descriptor))
    {
        let(file_size, os_file_get_size(file_descriptor));
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

fn void file_write(FileWriteOptions options)
{
    let(fd, os_file_open(options.path, (OSFileOpenFlags) {
        .write = 1,
        .truncate = 1,
        .create = 1,
        .executable = options.executable,
    }, (OSFilePermissions) {
        .readable = 1,
        .writable = 1,
        .executable = options.executable,
    }));
    assert(os_file_descriptor_is_valid(fd));

    os_file_write(fd, options.content);
    os_file_close(fd);
}

fn RunCommandResult run_command(Arena* arena, CStringSlice arguments, char* envp[], RunCommandOptions run_options)
{
    unused(arena);
    assert(arguments.length > 0);
    assert(arguments.pointer[arguments.length - 1] == 0);

    RunCommandResult result = {};
    Timestamp start_timestamp = {};
    Timestamp end_timestamp = {};
    f64 ms = 0.0;
    u64 measure_time = run_options.debug;

    if (run_options.debug)
    {
        print("Running command:\n");
        for (u32 i = 0; i < arguments.length - 1; i += 1)
        {
            char* argument = arguments.pointer[i];
            print("{cstr} ", argument);
        }
        print("\n");
    }

#if _WIN32
    u32 length = 0;
    for (u32 i = 0; i < arguments.length; i += 1)
    {
        let(argument, arguments.pointer[i]);
        if (argument)
        {
            let(string_len, strlen(argument));
            length += cast_to(u32, string_len + 1);
        }
    }

    char* bytes = (char*)arena_allocate_bytes(arena, length, 1);
    u32 byte_i = 0;
    for (u32 i = 0; i < arguments.length; i += 1)
    {
        let(argument, arguments.pointer[i]);
        if (argument)
        {
            let(len, strlen(argument));
            memcpy(&bytes[byte_i], argument, len);
            byte_i += cast_to(u32, len);
            bytes[byte_i] = ' ';
            byte_i += 1;
        }
    }
    bytes[byte_i - 1] = 0;

    PROCESS_INFORMATION process_information = {};
    STARTUPINFOA startup_info = {};
    startup_info.cb = sizeof(startup_info);
    startup_info.dwFlags |= STARTF_USESTDHANDLES;
    startup_info.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    startup_info.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    let(handle_inheritance, 1);

    if (measure_time)
    {
        start_timestamp = os_timestamp();
    }

    if (CreateProcessA(0, bytes, 0, 0, handle_inheritance, 0, 0, 0, &startup_info, &process_information))
    {
        WaitForSingleObject(process_information.hProcess, INFINITE);
        if (measure_time)
        {
            end_timestamp = os_timestamp();
            ms = os_resolve_timestamps(start_timestamp, end_timestamp, TIME_UNIT_MILLISECONDS);
        }


        if (run_options.debug)
        {
            print("Process ran in {f64} ms\n", ms);
        }

        DWORD exit_code;
        if (GetExitCodeProcess(process_information.hProcess, &exit_code))
        {
            if (run_options.debug)
            {
                print("Process ran with exit code: 0x{u32:x}\n", exit_code);
            }

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
        let(err, GetLastError());
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
        print("CreateProcessA call failed: {cstr}\n", lpMsgBuf);
        todo();
    }
#else
    int null_fd;

    if (run_options.use_null_file_descriptor)
    {
        null_fd = run_options.null_file_descriptor;
        assert(os_file_descriptor_is_valid(null_fd));
    }
    else if (run_options.stdout_stream.policy == CHILD_PROCESS_STREAM_IGNORE || run_options.stderr_stream.policy == CHILD_PROCESS_STREAM_IGNORE)
    {
        null_fd = open("/dev/null", O_WRONLY);
        assert(os_file_descriptor_is_valid(null_fd));
    }

    int stdout_pipe[2];
    int stderr_pipe[2];

    if (run_options.stdout_stream.policy == CHILD_PROCESS_STREAM_PIPE && pipe(stdout_pipe) == -1)
    {
        todo();
    }

    if (run_options.stderr_stream.policy == CHILD_PROCESS_STREAM_PIPE && pipe(stderr_pipe) == -1)
    {
        todo();
    }

    pid_t pid = syscall_fork();
    if (pid == -1)
    {
        todo();
    }

    if (measure_time)
    {
        start_timestamp = os_timestamp();
    }

    if (pid == 0)
    {
        switch (run_options.stdout_stream.policy)
        {
            case CHILD_PROCESS_STREAM_PIPE:
                {
                    close(stdout_pipe[0]);
                    dup2(stdout_pipe[1], STDOUT_FILENO);
                    close(stdout_pipe[1]);
                } break;
            case CHILD_PROCESS_STREAM_IGNORE:
                {
                    dup2(null_fd, STDOUT_FILENO);
                    close(null_fd);
                } break;
            case CHILD_PROCESS_STREAM_INHERIT:
                {
                } break;
        }

        switch (run_options.stderr_stream.policy)
        {
            case CHILD_PROCESS_STREAM_PIPE:
                {
                    close(stderr_pipe[0]);
                    dup2(stderr_pipe[1], STDERR_FILENO);
                    close(stderr_pipe[1]);
                } break;
            case CHILD_PROCESS_STREAM_IGNORE:
                {
                    dup2(null_fd, STDERR_FILENO);
                    close(null_fd);
                } break;
            case CHILD_PROCESS_STREAM_INHERIT:
                {
                } break;
        }

        // fcntl(pipes[1], F_SETFD, FD_CLOEXEC);
        let(result, syscall_execve(arguments.pointer[0], arguments.pointer, envp));
        unused(result);
        panic("Execve failed! Error: {cstr}\n", strerror(errno));
    }
    else
    {
        if (run_options.stdout_stream.policy == CHILD_PROCESS_STREAM_PIPE)
        {
            close(stdout_pipe[1]);
        }

        if (run_options.stderr_stream.policy == CHILD_PROCESS_STREAM_PIPE)
        {
            close(stderr_pipe[1]);
        }

        if (run_options.stdout_stream.policy == CHILD_PROCESS_STREAM_PIPE)
        {
            assert(run_options.stdout_stream.capacity);
            ssize_t byte_count = read(stdout_pipe[0], run_options.stdout_stream.buffer, run_options.stdout_stream.capacity);
            assert(byte_count >= 0);
            *run_options.stdout_stream.length = byte_count;

            close(stdout_pipe[0]);
        }

        if (run_options.stderr_stream.policy == CHILD_PROCESS_STREAM_PIPE)
        {
            assert(run_options.stderr_stream.capacity);
            ssize_t byte_count = read(stderr_pipe[0], run_options.stderr_stream.buffer, run_options.stderr_stream.capacity);
            assert(byte_count >= 0);
            *run_options.stderr_stream.length = byte_count;

            close(stderr_pipe[0]);
        }

        int status = 0;
        int options = 0;
        pid_t waitpid_result = syscall_waitpid(pid, &status, options);

        if (measure_time)
        {
            end_timestamp = os_timestamp();
        }

        if (waitpid_result == pid)
        {
            if (run_options.debug)
            {
                print("{cstr} ", arguments.pointer[0]);
            }

            if (WIFEXITED(status))
            {
                let(exit_code, WEXITSTATUS(status));
                result.termination_code = exit_code;
                result.termination_kind = PROCESS_TERMINATION_EXIT;

                if (run_options.debug)
                {
                    print("exited with code {u32}\n", exit_code);
                }
            }
            else if (WIFSIGNALED(status))
            {
                let(signal_code, WTERMSIG(status));
                result.termination_code = signal_code;
                result.termination_kind = PROCESS_TERMINATION_SIGNAL;

                if (run_options.debug)
                {
                    print("was signaled: {u32}\n", signal_code);
                }
            }
            else if (WIFSTOPPED(status))
            {
                let(stop_code, WSTOPSIG(status));
                result.termination_code = stop_code;
                result.termination_kind = PROCESS_TERMINATION_STOP;

                if (run_options.debug)
                {
                    print("was stopped: {u32}\n", stop_code);
                }
            }
            else
            {
                result.termination_kind = PROCESS_TERMINATION_UNKNOWN;

                if (run_options.debug)
                {
                    print("terminated unexpectedly with status {u32}\n", status);
                }
            }
        }
        else if (waitpid_result == -1)
        {
            let(waitpid_error, errno);
            print("Error waiting for process termination: {u32}\n", waitpid_error);
            trap();
        }
        else
        {
            todo();
        }

        let(success, result.termination_kind == PROCESS_TERMINATION_EXIT && result.termination_code == 0);
        if (run_options.debug && !success)
        {
            print("{cstr} failed to run successfully!\n", arguments.pointer[0]);
        }

        if (run_options.debug)
        {
            ms = os_resolve_timestamps(start_timestamp, end_timestamp, TIME_UNIT_MILLISECONDS);
            u32 ticks = 0;
#if LINK_LIBC == 0
            ticks = cpu_frequency != 0;
#endif
            print("Command run {cstr} in {f64} {cstr}\n", success ? "successfully" : "with errors", ms, ticks ? "ticks" : "ms");
        }

        if (!run_options.use_null_file_descriptor && os_file_descriptor_is_valid(null_fd))
        {
            close(null_fd);
        }
    }
#endif

    return result;
}

fn void print_string(String message)
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

fn String os_get_environment_variable(const char* name)
{
    String result = {};
    char* env = getenv(name);
    if (env)
    {
        result = cstr(env);
    }

    return result;
}

#ifndef _WIN32
fn u64 os_readlink(String path, String buffer)
{
    u64 result = 0;
    assert(path.pointer[path.length] == 0);
    let(sys_result, readlink(string_to_c(path), string_to_c(buffer), buffer.length));
    if (sys_result > 0)
    {
        assign_cast(result, sys_result);
    }

    return result;
}

fn String os_readlink_allocate(Arena* arena, String path)
{
    String result = {};
    u8 buffer[4096];
    let(bytes, os_readlink(path, (String)array_to_slice(buffer)));

    if (bytes > 0)
    {
        result.pointer = arena_allocate(arena, u8, bytes + 1);
        result.length = bytes;
        memcpy(result.pointer, buffer, bytes);
        result.pointer[bytes] = 0;
    }

    return result;
}

fn String os_realpath(String path, String buffer)
{
    String result = {};
    assert(path.pointer[path.length] == 0);
    char* system_result = realpath(string_to_c(path), string_to_c(buffer));
    if (system_result)
    {
        result = cstr(system_result);
    }

    return result;
}
#endif

fn void os_free(void* pointer)
{
    free(pointer);
}

#if _WIN32
fn HANDLE os_windows_get_module_handle()
{
    return GetModuleHandleW(0);
}
#endif

// TODO: structure this better
#if _WIN32
fn OSLibrary os_library_load(const char* library_name)
{
    OSLibrary library = {};
    library.handle = LoadLibraryA(library_name);
    return library;
}

fn OSSymbol os_symbol_load(OSLibrary library, const char* symbol_name)
{
    OSSymbol symbol = (OSSymbol)GetProcAddress(library.handle, symbol_name);
    return symbol;
}
#else
fn OSLibrary os_library_load(const char* library_name)
{
    OSLibrary library = {};
    library.handle = dlopen(library_name, RTLD_NOW | RTLD_LOCAL);
    return library;
}

fn OSSymbol os_symbol_load(OSLibrary library, const char* symbol_name)
{
    OSSymbol symbol = dlsym(library.handle, symbol_name);
    return symbol;
}
#endif

fn u8 os_library_is_valid(OSLibrary library)
{
    return library.handle != 0;
}

fn String file_find_in_path(Arena* arena, String file, String path_env, String extension)
{
    String result = {};
    assert(path_env.pointer);

    String path_it = path_env;
    u8 buffer[4096];

#if _WIN32
    u8 env_path_separator = ';';
    u8 path_separator = '\\';
#else
    u8 env_path_separator = ':';
    u8 path_separator = '/';
#endif

    while (path_it.length)
    {
        let(index, string_first_ch(path_it, env_path_separator));
        index = unlikely(index == STRING_NO_MATCH) ? path_it.length : index;
        let(path_chunk, s_get_slice(u8, path_it, 0, index));

        u64 i = 0;

        memcpy(&buffer[i], path_chunk.pointer, path_chunk.length);
        i += path_chunk.length;

        buffer[i] = path_separator;
        i += 1;

        memcpy(&buffer[i], file.pointer, file.length);
        i += file.length;

        if (extension.length)
        {
            memcpy(&buffer[i], extension.pointer, extension.length);
            i += extension.length;
        }

        buffer[i] = 0;
        i += 1;

        let(total_length, i - 1);
        OSFileOpenFlags flags = {
            .read = 1,
        };
        OSFilePermissions permissions = {
            .readable = 1,
            .writable = 1,
        };

        String path = { .pointer = buffer, .length = total_length };

        FileDescriptor fd = os_file_open(path, flags, permissions);

        if (os_file_descriptor_is_valid(fd))
        {
            os_file_close(fd);
            result.pointer = arena_allocate(arena, u8, total_length + 1);
            memcpy(result.pointer, buffer, total_length + 1);
            result.length = total_length;
            break;
        }

        String new_path = s_get_slice(u8, path_it, index + (index != path_it.length), path_it.length);
        assert(new_path.length < path_env.length);
        path_it = new_path;
    }

    return result;
}

fn String executable_find_in_path(Arena* arena, String executable, String path_env)
{
    String extension = {};
#if _WIN32
    extension = strlit(".exe");
#endif
    return file_find_in_path(arena, executable, path_env, extension);
}

