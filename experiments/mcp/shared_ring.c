#define _GNU_SOURCE
/* Controlled persistent shared-ring worker. Trusted job identity is separate from slot. */
#include <errno.h>
#include <fcntl.h>
#include <linux/io_uring.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

static void fail(const char *why) { perror(why); exit(1); }
static unsigned acquire(unsigned *p) { return __atomic_load_n(p,__ATOMIC_ACQUIRE); }
static void release(unsigned *p,unsigned v) { __atomic_store_n(p,v,__ATOMIC_RELEASE); }
static void emit(int fd,const char *text) {
  size_t n=strlen(text);
  if(write(fd,text,n)!=(ssize_t)n) fail("observation write");
}
struct job { unsigned long long context; char id[80]; unsigned slot; uint64_t ids[3]; };
static void marker(int fd,const char *kind,const struct job *job) {
  char line[512];
  int n=snprintf(line,sizeof(line),"{\"csp\":1,\"kind\":\"%s\",\"request\":%llu,\"operation\":0,\"pointer\":0,\"tid\":%ld,\"status\":0,\"job\":\"%s\"}\n",kind,job->context,syscall(SYS_gettid),job->id);
  if(n<0 || (size_t)n>=sizeof(line)) exit(1);
  emit(fd,line);
}
int main(int argc,char **argv) {
  if(argc!=5 && argc!=6) { fprintf(stderr,"usage: shared_ring FILE MARKERS OBSERVATIONS BATCH_WIDTH [IDLE_FLUSH_MS]\n"); return 2; }
  char *end; errno=0; unsigned long width=strtoul(argv[4],&end,10);
  if(errno || *end || !width || width>128) return 2;
  unsigned long idle_ms=0;
  if(argc==6) {
    errno=0;idle_ms=strtoul(argv[5],&end,10);
    if(errno || *end || idle_ms>60000) return 2;
  }
  /* Avoid stdio read-ahead hiding complete lines from poll. Input is the
     trusted dispatcher's complete newline-terminated job protocol. */
  if(idle_ms && setvbuf(stdin,NULL,_IONBF,0)) return 1;
  int file=open(argv[1],O_RDWR), markers=open(argv[2],O_WRONLY|O_CREAT|O_APPEND,0600), observations=open(argv[3],O_WRONLY|O_CREAT|O_APPEND,0600);
  if(file<0 || markers<0 || observations<0) fail("open");
  struct io_uring_params p={0};
  int ring=syscall(__NR_io_uring_setup,512,&p);
  if(ring<0) fail("io_uring_setup");
  size_t sq_size=p.sq_off.array+p.sq_entries*sizeof(unsigned), cq_size=p.cq_off.cqes+p.cq_entries*sizeof(struct io_uring_cqe);
  int single=(p.features&IORING_FEAT_SINGLE_MMAP)!=0;
  size_t map_size=single && cq_size>sq_size ? cq_size : sq_size;
  char *sq=mmap(NULL,map_size,PROT_READ|PROT_WRITE,MAP_SHARED,ring,IORING_OFF_SQ_RING);
  if(sq==MAP_FAILED) fail("mmap sq");
  char *cq=single?sq:mmap(NULL,cq_size,PROT_READ|PROT_WRITE,MAP_SHARED,ring,IORING_OFF_CQ_RING);
  if(cq==MAP_FAILED) fail("mmap cq");
  struct io_uring_sqe *sqes=mmap(NULL,p.sq_entries*sizeof(*sqes),PROT_READ|PROT_WRITE,MAP_SHARED,ring,IORING_OFF_SQES);
  if(sqes==MAP_FAILED) fail("mmap sqes");
  unsigned *sq_tail=(unsigned *)(sq+p.sq_off.tail), *sq_head=(unsigned *)(sq+p.sq_off.head);
  unsigned sq_mask=*(unsigned *)(sq+p.sq_off.ring_mask), *array=(unsigned *)(sq+p.sq_off.array);
  unsigned *cq_tail=(unsigned *)(cq+p.cq_off.tail), *cq_head=(unsigned *)(cq+p.cq_off.head);
  unsigned cq_mask=*(unsigned *)(cq+p.cq_off.ring_mask);
  struct io_uring_cqe *cqes=(struct io_uring_cqe *)(cq+p.cq_off.cqes);
  struct job jobs[128]; char a[]="uring-A",b[]="uring-B",scratch[128][8];
  char *input=NULL; size_t capacity=0; uint64_t next_id=1,batch=0;
  for(;;) {
    unsigned count=0;
    while(count<width) {
      if(count && idle_ms) {
        struct pollfd pending={.fd=STDIN_FILENO,.events=POLLIN};
        int ready;
        do { ready=poll(&pending,1,(int)idle_ms); } while(ready<0 && errno==EINTR);
        if(ready<0) fail("poll jobs");
        if(!ready) break;
      }
      if(getline(&input,&capacity,stdin)<0) break;
      struct job *job=&jobs[count]; char extra;
      if(sscanf(input,"%llu %79s %u %c",&job->context,job->id,&job->slot,&extra)!=3 || !job->context || job->slot>9999) return 2;
      if(strspn(job->id,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-/")!=strlen(job->id)) return 2;
      ++count;
    }
    if(!count) break;
    if(count!=width && !idle_ms) { fprintf(stderr,"partial batch at EOF\n"); return 1; }
    ++batch; unsigned start=acquire(sq_tail);
    if(start-acquire(sq_head)+3*count>p.sq_entries) return 1;
    for(unsigned j=0;j<count;++j) {
      marker(markers,"IPC_ENTER",&jobs[j]);
      for(unsigned i=0;i<3;++i) {
        unsigned index=(start+j*3+i)&sq_mask; struct io_uring_sqe *entry=&sqes[index];
        memset(entry,0,sizeof(*entry));entry->opcode=i==2?IORING_OP_READ:IORING_OP_WRITE;
        entry->fd=i==2?-1:file;entry->addr=(uintptr_t)(i==0?a:i==1?b:scratch[j]);
        entry->off=(uint64_t)jobs[j].slot*512+i*128;entry->len=7;entry->user_data=next_id++;
        jobs[j].ids[i]=entry->user_data;array[index]=index;
        char line[512];
        int n=snprintf(line,sizeof(line),"{\"kind\":\"sqe\",\"user_data\":%llu,\"opcode\":%u,\"fd\":%d,\"offset\":%llu,\"length\":7,\"flags\":0,\"batch\":%llu}\n",(unsigned long long)entry->user_data,entry->opcode,entry->fd,(unsigned long long)entry->off,(unsigned long long)batch);
        if(n<0 || (size_t)n>=sizeof(line)) return 1;
        emit(observations,line);
      }
      marker(markers,"IPC_LEAVE",&jobs[j]);
    }
    release(sq_tail,start+3*count);
    int submitted=syscall(__NR_io_uring_enter,ring,3*count,3*count,IORING_ENTER_GETEVENTS,NULL,0);
    if(submitted!=(int)(3*count)) { fprintf(stderr,"short ring submit %d\n",submitted); return 1; }
    unsigned head=acquire(cq_head), completions=0; unsigned char seen[128][3]={{0}};
    while(head!=acquire(cq_tail)) {
      struct io_uring_cqe entry=cqes[head&cq_mask]; int found=0;
      for(unsigned j=0;j<count;++j) for(unsigned i=0;i<3;++i) if(jobs[j].ids[i]==entry.user_data) {
        if(seen[j][i] || entry.flags || entry.res!=(i==2?-EBADF:7)) return 1;
        seen[j][i]=1;found=1;
      }
      if(!found) return 1;
      char line[256];
      int n=snprintf(line,sizeof(line),"{\"kind\":\"cqe\",\"user_data\":%llu,\"result\":%d,\"flags\":%u,\"batch\":%llu}\n",(unsigned long long)entry.user_data,entry.res,entry.flags,(unsigned long long)batch);
      if(n<0 || (size_t)n>=sizeof(line)) return 1;
      emit(observations,line);++head;++completions;
    }
    release(cq_head,head);
    if(completions!=3*count) return 1;
    for(unsigned j=0;j<count;++j) printf("{\"slot\":%u,\"job\":\"%s\"}\n",jobs[j].slot,jobs[j].id);
    fflush(stdout);
  }
  free(input);close(file);close(markers);close(observations);
  munmap(sqes,p.sq_entries*sizeof(*sqes));if(!single)munmap(cq,cq_size);munmap(sq,map_size);close(ring);
  return 0;
}
