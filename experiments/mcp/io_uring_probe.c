#define _GNU_SOURCE
/* Minimal direct ring fixture, deliberately independent of liburing. */
#include <errno.h>
#include <fcntl.h>
#include <linux/io_uring.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <unistd.h>

static void fail(const char *what) { perror(what); exit(1); }
static unsigned acquire(unsigned *p) { return __atomic_load_n(p, __ATOMIC_ACQUIRE); }
static void release(unsigned *p, unsigned v) { __atomic_store_n(p, v, __ATOMIC_RELEASE); }
static void snapshot(const char *directory,const char *name,const void *data,size_t size) {
  char path[4096];
  if(snprintf(path,sizeof(path),"%s/%s",directory,name)>=(int)sizeof(path)) exit(1);
  int output=open(path,O_WRONLY|O_CREAT|O_EXCL,0600);
  if(output<0) fail("snapshot open");
  if(write(output,data,size)!=(ssize_t)size) fail("snapshot write");
  if(close(output)) fail("snapshot close");
}
int main(int argc, char **argv) {
  if (argc != 2 && argc != 3 && argc != 4) { fprintf(stderr, "usage: io_uring_probe NEW_FILE | EXISTING_FILE SLOT [REPLACEMENT_FILE]\n"); return 2; }
  unsigned long slot = 0;
  if (argc >= 3) {
    char *end; errno=0; slot=strtoul(argv[2], &end, 10);
    if (errno || *end || !*argv[2] || slot > 9999) return 2;
  }
  uint64_t base_offset = slot * 512;
  struct io_uring_params p = {0};
  int ring = syscall(__NR_io_uring_setup, 8, &p);
  if (ring < 0) fail("io_uring_setup");
  size_t sq_size = p.sq_off.array + p.sq_entries * sizeof(unsigned);
  size_t cq_size = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
  int single = (p.features & IORING_FEAT_SINGLE_MMAP) != 0;
  size_t map_size = single && cq_size > sq_size ? cq_size : sq_size;
  char *sq = mmap(NULL, map_size, PROT_READ|PROT_WRITE, MAP_SHARED, ring, IORING_OFF_SQ_RING);
  if (sq == MAP_FAILED) fail("mmap sq");
  char *cq = single ? sq : mmap(NULL, cq_size, PROT_READ|PROT_WRITE, MAP_SHARED, ring, IORING_OFF_CQ_RING);
  if (cq == MAP_FAILED) fail("mmap cq");
  struct io_uring_sqe *sqes = mmap(NULL, p.sq_entries*sizeof(*sqes), PROT_READ|PROT_WRITE, MAP_SHARED, ring, IORING_OFF_SQES);
  if (sqes == MAP_FAILED) fail("mmap sqes");
  const char *collector=getenv("CAUSPAN_RING_INHERITED_COLLECTOR");
  if(collector) {
    pid_t child=fork();if(child<0) fail("fork collector worker");
    if(child>0) {
      int status;
      for(int phase=0;phase<2;++phase) {
        if(waitpid(child,&status,WUNTRACED)!=child || !WIFSTOPPED(status) || WSTOPSIG(status)!=SIGSTOP) {
          kill(child,SIGKILL);waitpid(child,&status,0);return 1;
        }
        if(!phase) {
          snapshot(collector,"sq.bin",sq,sq_size);
          snapshot(collector,"sqes.bin",sqes,p.sq_entries*sizeof(*sqes));
        } else snapshot(collector,"cq.bin",cq,cq_size);
        if(kill(child,SIGCONT)) fail("resume worker");
      }
      if(waitpid(child,&status,0)!=child || !WIFEXITED(status)) return 1;
      return WEXITSTATUS(status);
    }
    if(setenv("CAUSPAN_RING_SNAPSHOT","1",1)) fail("snapshot mode");
  }
  int fd = open(argv[1], argc == 2 ? O_CREAT|O_EXCL|O_RDWR : O_RDWR, 0600);
  if (fd < 0) fail("open fixture");
  unsigned *tail=(unsigned *)(sq+p.sq_off.tail), *mask=(unsigned *)(sq+p.sq_off.ring_mask);
  unsigned *array=(unsigned *)(sq+p.sq_off.array);
  unsigned start=acquire(tail);
  char a[]="uring-A", b[]="uring-B", scratch[8];
  for (unsigned i=0; i<3; ++i) {
    unsigned index=(start+i)&*mask;
    struct io_uring_sqe *entry=&sqes[index];
    memset(entry,0,sizeof(*entry));
    entry->opcode=i==2 ? IORING_OP_READ : IORING_OP_WRITE;
    entry->fd=i==2 ? -1 : fd;
    entry->addr=(uintptr_t)(i==0 ? a : i==1 ? b : scratch);
    entry->len=7;
    entry->off=base_offset+i*128;
    entry->user_data=101+i;
    array[index]=index;
    printf("{\"kind\":\"sqe\",\"user_data\":%llu,\"opcode\":%u,\"fd\":%d,\"offset\":%llu,\"length\":%u,\"flags\":%u}\n",
      (unsigned long long)entry->user_data,entry->opcode,entry->fd,(unsigned long long)entry->off,entry->len,entry->flags);
  }
  fflush(stdout);
  if (argc == 4) {
    if (close(fd) != 0) fail("close prepared descriptor");
    int replacement=open(argv[3],O_RDWR);
    if (replacement<0) fail("open replacement");
    if (replacement!=fd) { fprintf(stderr,"descriptor number was not reused\n"); return 1; }
  }
  release(tail,start+3);
  if (getenv("CAUSPAN_RING_SNAPSHOT")) {
    const char *export_socket=getenv("CAUSPAN_RING_EXPORT_FD");
    if (export_socket) {
      char byte='R';struct iovec iov={.iov_base=&byte,.iov_len=1};
      union { struct cmsghdr alignment; char bytes[CMSG_SPACE(sizeof(int))]; } control={0};
      struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1,.msg_control=control.bytes,.msg_controllen=sizeof(control.bytes)};
      struct cmsghdr *cmsg=CMSG_FIRSTHDR(&msg);
      cmsg->cmsg_level=SOL_SOCKET;cmsg->cmsg_type=SCM_RIGHTS;cmsg->cmsg_len=CMSG_LEN(sizeof(int));
      int exported=getenv("CAUSPAN_RING_EXPORT_CONTROL") ? fd : ring;
      memcpy(CMSG_DATA(cmsg),&exported,sizeof(exported));
      if(sendmsg(atoi(export_socket),&msg,0)!=1) fail("export ring descriptor");
    }
    fprintf(stderr,"{\"sq\":%llu,\"cq\":%llu,\"sqes\":%llu,\"sq_size\":%zu,\"cq_size\":%zu,\"sq_entries\":%u,\"cq_entries\":%u,\"sq_head\":%u,\"sq_tail\":%u,\"sq_mask\":%u,\"sq_array\":%u,\"cq_head\":%u,\"cq_tail\":%u,\"cq_mask\":%u,\"cqes\":%u}\n",
      (unsigned long long)(uintptr_t)sq,(unsigned long long)(uintptr_t)cq,
      (unsigned long long)(uintptr_t)sqes,sq_size,cq_size,p.sq_entries,p.cq_entries,
      p.sq_off.head,p.sq_off.tail,p.sq_off.ring_mask,p.sq_off.array,
      p.cq_off.head,p.cq_off.tail,p.cq_off.ring_mask,p.cq_off.cqes);
    fflush(stderr);raise(SIGSTOP);
  }
  int submitted=syscall(__NR_io_uring_enter,ring,3,3,IORING_ENTER_GETEVENTS,NULL,0);
  if (submitted!=3) { fprintf(stderr,"submission count: %d errno: %d\n",submitted,errno); return 1; }
  if (getenv("CAUSPAN_RING_SNAPSHOT")) raise(SIGSTOP);
  unsigned *cq_head=(unsigned *)(cq+p.cq_off.head), *cq_tail=(unsigned *)(cq+p.cq_off.tail);
  unsigned cq_mask=*(unsigned *)(cq+p.cq_off.ring_mask), head=acquire(cq_head);
  struct io_uring_cqe *cqes=(struct io_uring_cqe *)(cq+p.cq_off.cqes);
  unsigned seen=0;
  while (head != acquire(cq_tail)) {
    struct io_uring_cqe entry=cqes[head&cq_mask];
    printf("{\"kind\":\"cqe\",\"user_data\":%llu,\"result\":%d,\"flags\":%u}\n",
      (unsigned long long)entry.user_data,entry.res,entry.flags);
    if (entry.user_data<101 || entry.user_data>103 || (seen&(1u<<(entry.user_data-101)))) return 1;
    if (entry.res != (entry.user_data==103 ? -EBADF : 7) || entry.flags) return 1;
    seen |= 1u<<(entry.user_data-101);
    ++head;
  }
  release(cq_head,head);
  if (seen!=7) { fprintf(stderr,"incomplete CQ: %u\n",seen); return 1; }
  close(fd);
  munmap(sqes,p.sq_entries*sizeof(*sqes));
  if (!single) munmap(cq,cq_size);
  munmap(sq,map_size);
  close(ring);
  return 0;
}
