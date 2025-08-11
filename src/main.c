#if 1
#include <compiler.h>

int main(int argc, const char* argv[], char** envp)
{
    bool result = compiler_main(argc, argv, envp);
    int result_code = result ? 0 : 1;
    return 0;
}
#else
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <linux/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    struct io_uring ring;
    if (io_uring_queue_init(8, &ring, 0) < 0) {
        perror("io_uring_queue_init");
        return 1;
    }

    struct statx st;
    char *buf = NULL;

    /* ----------------- Chain: OPEN → STATX → READ → CLOSE ----------------- */
    struct io_uring_sqe *sqe;

    /* 1. OPEN */
    sqe = io_uring_get_sqe(&ring);
    io_uring_prep_openat(sqe, AT_FDCWD, argv[1], O_RDONLY, 0);
    sqe->user_data = 1;
    sqe->flags |= IOSQE_IO_LINK;

    /* 2. STATX */
    sqe = io_uring_get_sqe(&ring);
    io_uring_prep_statx(sqe, -1, "", AT_EMPTY_PATH, STATX_SIZE, &st);
    sqe->user_data = 2;
    sqe->flags |= IOSQE_IO_LINK;

    /* 3. READ (size will be filled after STATX) — we allocate later */
    // We can't know size before statx finishes unless we buffer chain.
    // For the demo, let's just read 1 MiB max.
    size_t max_read = 1024 * 1024;
    buf = malloc(max_read);
    if (!buf) {
        perror("malloc");
        return 1;
    }
    sqe = io_uring_get_sqe(&ring);
    io_uring_prep_read(sqe, -1, buf, max_read, 0);
    sqe->user_data = 3;
    sqe->flags |= IOSQE_IO_LINK;

    /* 4. CLOSE */
    sqe = io_uring_get_sqe(&ring);
    io_uring_prep_close(sqe, -1);
    sqe->user_data = 4;

    /* ----------------- Submit and process completions ----------------- */
    int ret = io_uring_submit(&ring);
    if (ret < 0) {
        fprintf(stderr, "io_uring_submit: %s\n", strerror(-ret));
        return 1;
    }

    struct io_uring_cqe *cqe;
    int pending = 4;

    while (pending > 0) {
        ret = io_uring_wait_cqe(&ring, &cqe);
        if (ret < 0) {
            fprintf(stderr, "wait_cqe: %s\n", strerror(-ret));
            break;
        }

        unsigned long long id = cqe->user_data;
        int res = cqe->res;

        if (res < 0) {
            fprintf(stderr, "Request %llu failed: %s\n",
                    id, strerror(-res));
        } else {
            if (id == 1) {
                printf("OPEN: fd=%d\n", res);
            } else if (id == 2) {
                printf("STATX: file size=%lld bytes\n", (long long) st.stx_size);
            } else if (id == 3) {
                printf("READ: got %d bytes\n", res);
                fwrite(buf, 1, res, stdout);
                printf("\n");
            } else if (id == 4) {
                printf("CLOSE: done\n");
            }
        }

        io_uring_cqe_seen(&ring, cqe);
        pending--;
    }

    free(buf);
    io_uring_queue_exit(&ring);
    return 0;
}
#endif
