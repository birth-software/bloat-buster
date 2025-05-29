#include <lib.hpp>
using uid_t = u32;
using gid_t = u32;
using off_t = s64;
using ino_t = u64;
using dev_t = u64;

struct timespec 
{
    s64 seconds;
    s64 nanoseconds;
};

struct Stat
{
    dev_t dev;
    ino_t ino;
    u64 nlink;

    u32 mode;
    uid_t uid;
    gid_t gid;
    u32 _0;
    dev_t rdev;
    off_t size;
    s64 blksize;
    s64 blocks;

    timespec atim;
    timespec mtim;
    timespec ctim;
    s64 _1[3];
};

extern "C" s32 fstat(s32, Stat*);
extern "C" s32 fork();
extern "C" s32 dup2(s32, s32);
extern "C" s32 execve(const char* path_name, const char* const argv[], char* const envp[]);
extern "C" s32 waitpid(s32 pid, int* wstatus, int options);

u64 os_file_size(s32 fd)
{
    Stat stat;
    auto result = fstat(fd, &stat);
    assert(result == 0);
    return (u64)stat.size;
}

fn u8 EXITSTATUS(u32 s)
{
    return (u8)((s & 0xff00) >> 8);
}

fn u32 TERMSIG(u32 s)
{
    return s & 0x7f;
}

fn u32 STOPSIG(u32 s)
{
    return EXITSTATUS(s);
}

fn bool IFEXITED(u32 s)
{
    return TERMSIG(s) == 0;
}

fn bool IFSTOPPED(u32 s)
{
    return u16(((s & 0xffff) * 0x10001) >> 8) > 0x7f00;
}

fn bool IFSIGNALED(u32 s)
{
    return (s & 0xffff) - 1 < 0xff;
}
Execution os_execute(Arena* arena, Slice<char* const> arguments, Slice<char* const> environment, ExecuteOptions options)
{
    unused(arena);
    assert(arguments.pointer[arguments.length] == 0);
    assert(environment.pointer[environment.length] == 0);

    Execution execution = {};

    s32 null_file_descriptor = -1;
    if (options.null_file_descriptor >= 0)
    {
        null_file_descriptor = options.null_file_descriptor;
    }
    else if (options.policies[0] == ExecuteStandardStreamPolicy::ignore || options.policies[1] == ExecuteStandardStreamPolicy::ignore)
    {
        trap();
    }

    int pipes[standard_stream_count][2];

    for (int i = 0; i < 2; i += 1)
    {
        if (options.policies[i] == ExecuteStandardStreamPolicy::pipe)
        {
            trap();
        }
    }

    auto pid = fork();

    switch (pid)
    {
        case -1:
            {
                trap();
            } break;
        case 0: // Child process
            {
                for (u64 i = 0; i < standard_stream_count; i += 1)
                {
                    auto fd = (s32)i + 1;
                    switch (options.policies[i])
                    {
                        case ExecuteStandardStreamPolicy::inherit:
                            {
                            } break;
                        case ExecuteStandardStreamPolicy::pipe:
                            {
                                close(pipes[i][0]);
                                dup2(pipes[i][1], fd);
                                close(pipes[i][1]);
                            } break;
                        case ExecuteStandardStreamPolicy::ignore:
                            {
                                dup2(null_file_descriptor, fd);
                                close(null_file_descriptor);
                            } break;
                    }
                }

                auto result = execve(arguments[0], arguments.pointer, environment.pointer);

                if (result != -1)
                {
                    unreachable();
                }

                trap();
            } break;
        default:
            {
                for (u64 i = 0; i < standard_stream_count; i += 1)
                {
                    if (options.policies[i] == ExecuteStandardStreamPolicy::pipe)
                    {
                        close(pipes[i][1]);
                    }
                }

                if (options.policies[0] == ExecuteStandardStreamPolicy::pipe || options.policies[1] == ExecuteStandardStreamPolicy::pipe)
                {
                    trap();
                }

                for (u64 i = 0; i < standard_stream_count; i += 1)
                {
                    if (options.policies[i] == ExecuteStandardStreamPolicy::pipe)
                    {
                        trap();
                    }
                }

                int status = 0;
                auto waitpid_result = waitpid(pid, &status, 0);
                
                if (waitpid_result == pid)
                {
                    if (IFEXITED(status))
                    {
                        execution.termination_kind = TerminationKind::exit;
                        execution.termination_code = EXITSTATUS(status);
                    }
                    else if (IFSIGNALED(status))
                    {
                        execution.termination_kind = TerminationKind::signal;
                        execution.termination_code = TERMSIG(status);
                    }
                    else if (IFSTOPPED(status))
                    {
                        execution.termination_kind = TerminationKind::stop;
                        execution.termination_code = STOPSIG(status);
                    }
                    else
                    {
                        execution.termination_kind = TerminationKind::unknown;
                    }

                    if (options.null_file_descriptor < 0 && null_file_descriptor >= 0)
                    {
                        close(null_file_descriptor);
                    }
                }
                else if (waitpid_result == -1)
                {
                    trap();
                }
                else
                {
                    trap();
                }
            } break;
    }

    return execution;
}
