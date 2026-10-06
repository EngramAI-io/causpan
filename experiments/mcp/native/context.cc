// Research instrumentation for the verified Node 24.20.0 AArch64 libuv ABI.
// Patches in-memory code only. Refuses unknown instruction sequences.
#include <node_api.h>
#include <uv.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <mutex>
#include <unordered_map>
#include <atomic>

struct Work;
using WorkFn = void (*)(Work*);
using DoneFn = void (*)(Work*, int);
using SubmitFn = void (*)(void*, Work*, int, WorkFn, DoneFn);
struct Record { uint64_t request, operation; WorkFn work; DoneFn done; };
static std::mutex records_mutex;
static std::unordered_map<Work*, Record> records;
static std::atomic<uint64_t> next_operation{1};
static thread_local uint64_t current_request = 0;
static thread_local uint64_t current_operation = 0;
static int output_fd = -1;
static thread_local long cached_tid=0;
static void after_fork_child(){cached_tid=0;}
static SubmitFn original_submit = nullptr;
using QueueFn=int (*)(uv_loop_t*,uv_work_t*,uv_work_cb,uv_after_work_cb);
static QueueFn original_queue=nullptr;

static void emit(const char* kind, uint64_t request, uint64_t operation, uintptr_t pointer=0, int status=0) {
  if (output_fd < 0) return;
  int saved = errno;
  if(!cached_tid)cached_tid=syscall(SYS_gettid);
  char line[320];
  int len = snprintf(line, sizeof(line), "{\"csp\":1,\"kind\":\"%s\",\"request\":%llu,\"operation\":%llu,\"pointer\":%llu,\"tid\":%ld,\"status\":%d}\n",
    kind, (unsigned long long)request, (unsigned long long)operation,
    (unsigned long long)pointer, cached_tid, status);
  // One bounded write per record. Capture failure is fatal, never silently lose context.
  ssize_t result;
  do { result = write(output_fd, line, len); } while (result < 0 && errno == EINTR);
  if (result != len) _exit(86);
  errno = saved;
}
static void set_context(uint64_t request, uint64_t operation, const char* kind) {
  current_request = request;
  current_operation = operation;
  emit(kind, request, operation);
}
static Record lookup(Work* work, bool erase) {
  std::lock_guard<std::mutex> lock(records_mutex);
  auto it = records.find(work);
  if (it == records.end()) { emit("INVARIANT_FAILURE", 0, 0, (uintptr_t)work); _exit(87); }
  Record record = it->second;
  if (erase) records.erase(it);
  return record;
}
static void wrapped_work(Work* work) {
  Record record = lookup(work, false);
  auto previous_request = current_request;
  auto previous_operation = current_operation;
  set_context(record.request, record.operation, "WORK_ENTER");
  record.work(work);
  set_context(previous_request, previous_operation, "WORK_LEAVE");
}
static void wrapped_done(Work* work, int status) {
  // Remove before invoking done: Node may free or immediately reuse the work address.
  Record record = lookup(work, true);
  auto previous_request = current_request;
  auto previous_operation = current_operation;
  set_context(record.request, record.operation, "DONE_ENTER");
  emit("COMPLETE", record.request, record.operation, (uintptr_t)work, status);
  if(record.done) record.done(work, status);
  set_context(previous_request, previous_operation, "DONE_LEAVE");
}
static void wrapped_submit(void* loop, Work* work, int kind, WorkFn fn, DoneFn done) {
  Record record{current_request, next_operation.fetch_add(1), fn, done};
  {
    std::lock_guard<std::mutex> lock(records_mutex);
    if (!records.emplace(work, record).second) { emit("DUPLICATE_WORK",0,0,(uintptr_t)work); _exit(88); }
  }
  emit("SUBMIT", record.request, record.operation, (uintptr_t)work);
  original_submit(loop, work, kind, wrapped_work, wrapped_done);
}
static void queued_work(uv_work_t* work) { wrapped_work(reinterpret_cast<Work*>(work)); }
static void queued_done(uv_work_t* work,int status) { wrapped_done(reinterpret_cast<Work*>(work),status); }
static int wrapped_queue(uv_loop_t* loop,uv_work_t* work,uv_work_cb fn,uv_after_work_cb done) {
  auto key=reinterpret_cast<Work*>(work);
  Record record{current_request,next_operation.fetch_add(1),reinterpret_cast<WorkFn>(fn),reinterpret_cast<DoneFn>(done)};
  {
    std::lock_guard<std::mutex> lock(records_mutex);
    if(!records.emplace(key,record).second){emit("DUPLICATE_WORK",0,0,(uintptr_t)work);_exit(88);}
  }
  emit("SUBMIT",record.request,record.operation,(uintptr_t)work);
  return original_queue(loop,work,queued_work,queued_done);
}
static napi_value fail(napi_env env, const char* text) { napi_throw_error(env, nullptr, text); return nullptr; }
static napi_value install(napi_env env, napi_callback_info info) {
#ifndef __aarch64__
  return fail(env, "Only verified AArch64 Node builds supported");
#else
  size_t argc=2; napi_value args[2]; napi_get_cb_info(env,info,&argc,args,nullptr,nullptr);
  if(argc!=2 || original_submit) return fail(env,"install needs address and output path, once");
  uint64_t address; bool lossless;
  if(napi_get_value_bigint_uint64(env,args[0],&address,&lossless)!=napi_ok || !lossless)
    return fail(env,"invalid symbol address");
  char path[4096]; size_t length;
  if(napi_get_value_string_utf8(env,args[1],path,sizeof(path),&length)!=napi_ok || length>=sizeof(path)-1)
    return fail(env,"invalid output path");
  // The first 16 bytes contain no PC-relative instructions in this exact prologue.
  const uint32_t expected[4]={0xa9bc7bfd,0x910003fd,0xa90153f3,0xaa0103f4};
  void* target=(void*)address;
  if(memcmp(target,expected,sizeof(expected))) return fail(env,"uv__work_submit prologue mismatch: unsupported binary");
  output_fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_APPEND|O_CLOEXEC,0600);
  if(output_fd<0) return fail(env,"cannot create native event file");
  size_t page=sysconf(_SC_PAGESIZE);
  auto trampoline=(unsigned char*)mmap(nullptr,page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  if(trampoline==MAP_FAILED) return fail(env,"mmap failed");
  memcpy(trampoline,target,16);
  // ldr x16, .+8 ; br x16 ; absolute target. x16 is ABI scratch.
  uint32_t jump[2]={0x58000050,0xd61f0200};
  memcpy(trampoline+16,jump,8);
  uint64_t resume=address+16;
  memcpy(trampoline+24,&resume,8);
  __builtin___clear_cache((char*)trampoline,(char*)trampoline+32);
  if(mprotect(trampoline,page,PROT_READ|PROT_EXEC)) return fail(env,"trampoline mprotect failed");
  original_submit=(SubmitFn)trampoline;
  auto start=address & ~(page-1);
  if(mprotect((void*)start,page,PROT_READ|PROT_WRITE|PROT_EXEC)) return fail(env,"target mprotect failed");
  memcpy(target,jump,8);
  uint64_t replacement=(uintptr_t)&wrapped_submit;
  memcpy((char*)target+8,&replacement,8);
  __builtin___clear_cache((char*)target,(char*)target+16);
  if(mprotect((void*)start,page,PROT_READ|PROT_EXEC)) return fail(env,"restore mprotect failed");
  if(pthread_atfork(nullptr,nullptr,after_fork_child))return fail(env,"atfork registration failed");
  emit("INSTALL",0,0,address);
  // Compiler inlining bypasses uv__work_submit inside uv_queue_work in this binary.
  // Leave its initial cbz instruction intact and hook the following prologue.
  uint64_t queue_address=(uintptr_t)&uv_queue_work+4;
  const uint32_t queue_expected[4]={0xa9bd7bfd,0x910003fd,0xa90153f3,0xaa0103f3};
  if(memcmp((void*)queue_address,queue_expected,16))return fail(env,"uv_queue_work prologue mismatch");
  auto queue_trampoline=(unsigned char*)mmap(nullptr,page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  if(queue_trampoline==MAP_FAILED)return fail(env,"queue trampoline mmap failed");
  memcpy(queue_trampoline,(void*)queue_address,16);memcpy(queue_trampoline+16,jump,8);
  uint64_t queue_resume=queue_address+16;memcpy(queue_trampoline+24,&queue_resume,8);
  __builtin___clear_cache((char*)queue_trampoline,(char*)queue_trampoline+32);
  if(mprotect(queue_trampoline,page,PROT_READ|PROT_EXEC))return fail(env,"queue trampoline mprotect failed");
  original_queue=(QueueFn)queue_trampoline;
  auto queue_start=queue_address & ~(page-1);
  if(mprotect((void*)queue_start,page,PROT_READ|PROT_WRITE|PROT_EXEC))return fail(env,"queue target mprotect failed");
  memcpy((void*)queue_address,jump,8);
  uint64_t queue_replacement=(uintptr_t)&wrapped_queue;
  memcpy((void*)(queue_address+8),&queue_replacement,8);
  __builtin___clear_cache((char*)queue_address,(char*)queue_address+16);
  if(mprotect((void*)queue_start,page,PROT_READ|PROT_EXEC))return fail(env,"queue restore mprotect failed");
  emit("INSTALL_QUEUE",0,0,queue_address);
  napi_value result; napi_get_undefined(env,&result); return result;
#endif
}
static napi_value context(napi_env env,napi_callback_info info) {
  size_t argc=1; napi_value args[1]; napi_get_cb_info(env,info,&argc,args,nullptr,nullptr);
  uint64_t request=0; bool lossless;
  if(argc!=1 || napi_get_value_bigint_uint64(env,args[0],&request,&lossless)!=napi_ok || !lossless)
    return fail(env,"context requires uint64 bigint");
  uint64_t previous=current_request;
  if(request!=current_request || current_operation) set_context(request,0,"JS_CONTEXT");
  napi_value result; napi_create_bigint_uint64(env,previous,&result); return result;
}

// A controlled cancellation workload, separate from the production attribution hook.
struct Probe {
  uv_work_t work;
  napi_env env;
  napi_deferred deferred;
  int fd, delay_ms, cancel_result;
  uint64_t offset;
  ssize_t bytes;
};
static void probe_work(uv_work_t* work) {
  auto p=(Probe*)work->data;
  usleep(p->delay_ms*1000);
  const char content[]="native probe";
  p->bytes=pwrite(p->fd,content,sizeof(content)-1,p->offset);
}
static void probe_done(uv_work_t* work,int status) {
  auto p=(Probe*)work->data;
  napi_handle_scope scope; napi_open_handle_scope(p->env,&scope);
  napi_value result,value; napi_create_object(p->env,&result);
  napi_create_int32(p->env,status,&value);napi_set_named_property(p->env,result,"status",value);
  napi_create_int32(p->env,p->cancel_result,&value);napi_set_named_property(p->env,result,"cancel_result",value);
  napi_create_int64(p->env,p->bytes,&value);napi_set_named_property(p->env,result,"bytes",value);
  napi_resolve_deferred(p->env,p->deferred,result);
  napi_close_handle_scope(p->env,scope);
  delete p;
}
static napi_value queue_probe(napi_env env,napi_callback_info info) {
  size_t argc=4;napi_value args[4];napi_get_cb_info(env,info,&argc,args,nullptr,nullptr);
  if(argc!=4)return fail(env,"queueProbe(fd,offset,delay_ms,cancel)");
  auto p=new Probe{};p->env=env;p->work.data=p;p->cancel_result=1;
  int64_t offset;bool cancel;
  if(napi_get_value_int32(env,args[0],&p->fd)!=napi_ok ||
     napi_get_value_int64(env,args[1],&offset)!=napi_ok || offset<0 ||
     napi_get_value_int32(env,args[2],&p->delay_ms)!=napi_ok || p->delay_ms<0 || p->delay_ms>1000 ||
     napi_get_value_bool(env,args[3],&cancel)!=napi_ok){delete p;return fail(env,"invalid probe arguments");}
  p->offset=offset;
  napi_value promise;napi_create_promise(env,&p->deferred,&promise);
  uv_loop_t* loop;napi_get_uv_event_loop(env,&loop);
  int result=uv_queue_work(loop,&p->work,probe_work,probe_done);
  if(result){delete p;return fail(env,"uv_queue_work failed");}
  if(cancel)p->cancel_result=uv_cancel((uv_req_t*)&p->work);
  return promise;
}

static napi_value init(napi_env env,napi_value exports) {
  napi_property_descriptor props[]={{"install",0,install,0,0,0,napi_default,0},
                                    {"context",0,context,0,0,0,napi_default,0},
                                    {"queueProbe",0,queue_probe,0,0,0,napi_default,0}};
  napi_define_properties(env,exports,3,props); return exports;
}
NAPI_MODULE(NODE_GYP_MODULE_NAME,init)
