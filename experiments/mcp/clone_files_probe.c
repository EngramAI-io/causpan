#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    int channel[2];
    if (pipe(channel) != 0) { perror("pipe"); return 1; }

    struct clone_args args = {0};
    args.flags = CLONE_FILES;
    args.exit_signal = SIGCHLD;
    pid_t child = (pid_t)syscall(SYS_clone3, &args, sizeof(args));
    if (child < 0) { perror("clone3(CLONE_FILES)"); return 77; }

    if (child == 0) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) _exit(2);
        if (write(channel[1], &fd, sizeof(fd)) != sizeof(fd)) _exit(3);
        _exit(0);
    }

    int child_fd = -1;
    ssize_t count = read(channel[0], &child_fd, sizeof(child_fd));
    int status = 0;
    if (waitpid(child, &status, 0) != child) { perror("waitpid"); return 1; }
    if (count != sizeof(child_fd) || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "child failed to create/report socket fd\n"); return 1;
    }
    if (fcntl(child_fd, F_GETFD) < 0) {
        perror("parent cannot see child-created descriptor"); return 1;
    }
    printf("CLONE_FILES shared descriptor visible in parent: fd=%d\n", child_fd);
    if (close(child_fd) != 0) { perror("close shared socket"); return 1; }
    return 0;
}
