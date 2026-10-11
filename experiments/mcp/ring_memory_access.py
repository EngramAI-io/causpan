import argparse,ctypes,json,os,signal,subprocess,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from ring_memory_probe import stopped
parser=argparse.ArgumentParser(description='Diagnose ring mapping reads using a built ring_memory_probe directory')
parser.add_argument('run',type=Path)
root=parser.parse_args().run
class Iovec(ctypes.Structure):_fields_=[('base',ctypes.c_void_p),('length',ctypes.c_size_t)]
libc=ctypes.CDLL(None,use_errno=True)
libc.process_vm_readv.argtypes=[ctypes.c_int,ctypes.POINTER(Iovec),ctypes.c_ulong,ctypes.POINTER(Iovec),ctypes.c_ulong,ctypes.c_ulong]
libc.process_vm_readv.restype=ctypes.c_ssize_t
with (root/'access-stdout').open('w') as out,(root/'access-meta').open('w') as err:
 child=subprocess.Popen([str(root.resolve()/'helper'),str(root.resolve()/'access-fixture')],stdout=out,stderr=err,env={**os.environ,'CAUSPAN_RING_SNAPSHOT':'1'})
 try:
  stopped(child);meta=json.loads((root/'access-meta').read_text());rows=[]
  maps=Path(f'/proc/{child.pid}/maps').read_text();(root/'maps.txt').write_text(maps)
  for name,address in [(n,meta[n]) for n in ['sq','cq','sqes']]+[('ordinary_text',int(maps.split('-')[0],16))]:
   row={'mapping':name,'address':address}
   fd=os.open(f'/proc/{child.pid}/mem',os.O_RDONLY)
   try:
    try:row['proc_mem_bytes']=len(os.pread(fd,16,address))
    except OSError as e:row['proc_mem_errno']=e.errno
   finally:os.close(fd)
   buf=ctypes.create_string_buffer(16);local=Iovec(ctypes.cast(buf,ctypes.c_void_p),16);remote=Iovec(address,16)
   ctypes.set_errno(0);n=libc.process_vm_readv(child.pid,ctypes.byref(local),1,ctypes.byref(remote),1,0)
   row.update(process_vm_readv_bytes=n,process_vm_readv_errno=ctypes.get_errno());rows.append(row)
  report={'valid':False,'stage':'external_memory_access','observations':rows,'limitation':'No SQE/CQE decoding established; cooperative mapping addresses alone do not enable external reads on this host.'}
  (root/'access-report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
 finally:
  child.kill();child.wait()
