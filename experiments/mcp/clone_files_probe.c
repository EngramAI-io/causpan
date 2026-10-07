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

int main(int argc, char **argv) {
    if(argc!=3){fprintf(stderr,"usage: %s SLOTS_FILE SLOT\n",argv[0]);return 2;}
    char *end=NULL;
    long slot=strtol(argv[2],&end,10);
    if(end==argv[2]||*end||errno==ERANGE||slot<0||slot>99999){fprintf(stderr,"invalid slot\n");return 2;}
    int data=open(argv[1],O_RDWR);
    if(data<0){perror("open slots file");return 1;}
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
        char payload[64];
        int length=snprintf(payload,sizeof(payload),"clone-files:%ld",slot);
        if(length<0||(size_t)length>=sizeof(payload))_exit(4);
        if(pwrite(data,payload,(size_t)length,slot*128)!=(ssize_t)length)_exit(5);
        if (write(channel[1], &fd, sizeof(fd)) != sizeof(fd)) _exit(3);
        _exit(0);
    }

    int child_fd = -1;
    int status = 0;
    if (waitpid(child, &status, 0) != child) { perror("waitpid"); return 1; }
    /* The message fits in the pipe. Reap first so a failed child cannot leave
       us blocked while our shared table still holds the pipe writer open. */
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "child failed before reporting socket fd\n"); return 1;
    }
    ssize_t count = read(channel[0], &child_fd, sizeof(child_fd));
    if (count != sizeof(child_fd)) {
        fprintf(stderr, "child failed to create/report socket fd\n"); return 1;
    }
    if (fcntl(child_fd, F_GETFD) < 0) {
        perror("parent cannot see child-created descriptor"); return 1;
    }
    char payload[64]={0},expected[64];
    int length=snprintf(expected,sizeof(expected),"clone-files:%ld",slot);
    if(length<0||pread(data,payload,(size_t)length,slot*128)!=(ssize_t)length||memcmp(payload,expected,(size_t)length)){
        fprintf(stderr,"parent could not verify child write\n");return 1;
    }
    printf("verified clone-files slot %ld; shared descriptor fd=%d\n",slot,child_fd);
    if (close(child_fd) != 0) { perror("close shared socket"); return 1; }
    close(channel[0]);close(channel[1]);close(data);
    return 0;
}
