// Controlled workloads supply independent syscall-argument oracles for difficult cases.
import { McpServer } from './node_modules/@modelcontextprotocol/sdk/dist/esm/server/mcp.js';
import { StdioServerTransport } from './node_modules/@modelcontextprotocol/sdk/dist/esm/server/stdio.js';
import { z } from './node_modules/zod/index.js';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import { AsyncResource } from 'node:async_hooks';
import { spawn } from 'node:child_process';
import net from 'node:net';
import { setTimeout as sleep } from 'node:timers/promises';

const root=process.argv[2];
const file=await fs.open(`${root}/slots.bin`,'r+');
const pending=new Set();
const errors=[];
let backgroundPromise=Promise.resolve();
const stride=128;
const backgroundSlot=100000;
let tick=0;
const server=new McpServer({name:'causpan-control',version:'1.0.0'});
server.registerTool('tcp_roundtrip',{inputSchema:{slot:z.number().int().min(0).max(99999),port:z.number().int().min(1).max(65535)}},async({slot,port})=>{
  const payload=`causpan-net:${slot}\n`;
  const received=await new Promise((resolve,reject)=>{
    const socket=net.createConnection({host:'127.0.0.1',port});
    let bytes='';
    socket.setEncoding('utf8');
    socket.on('connect',()=>socket.end(payload));
    socket.on('data',chunk=>{bytes+=chunk;});
    socket.on('error',reject);
    socket.on('end',()=>resolve(bytes));
  });
  if(received!==payload)throw new Error('TCP read-back mismatch');
  return {content:[{type:'text',text:'TCP round trip complete'}]};
});
const without=fn=>globalThis.causpanContext ? globalThis.causpanContext.withoutRequest(fn) : fn();
// Intentionally outside any request and on the same file descriptor as request work.
const background=setInterval(()=>without(()=>{
  backgroundPromise=backgroundPromise.then(async()=>{
    await file.write(Buffer.from(`background:${tick++}`),0,12,backgroundSlot*stride);
  }).catch(e=>errors.push(String(e)));
}),10);
const io=async({slot,rounds,delay_ms,nested})=>{
  const content=Buffer.from(`slot:${slot}`.padEnd(32,'.'));
  for(let round=0;round<rounds;round++) {
    await sleep(delay_ms+(slot%3));
    if(nested) {
      // Exercise nested synchronous async-resource scope and restoration afterward.
      const resource=new AsyncResource('CAUSPAN_NESTED');
      resource.runInAsyncScope(()=>fsSync.statSync(`${root}/slots.bin`));
      resource.emitDestroy();
    }
    await file.write(content,0,content.length,slot*stride);
    const read=Buffer.alloc(content.length);
    await file.read(read,0,read.length,slot*stride);
    if(!read.equals(content))throw new Error(`slot ${slot} read-back mismatch`);
  }
  return {content:[{type:'text',text:`verified slot ${slot}`} ]};
};
server.registerTool('slot_io',{inputSchema:{slot:z.number().int().min(0).max(99999),
  rounds:z.number().int().min(1).max(20).default(3),delay_ms:z.number().int().min(0).max(100).default(1),
  nested:z.boolean().default(false),detached:z.boolean().default(false)}},async args=>{
  const job=io(args);
  if(!args.detached)return job;
  pending.add(job);
  job.catch(e=>errors.push(String(e))).finally(()=>pending.delete(job));
  return {content:[{type:'text',text:`scheduled slot ${args.slot}`} ]};
});
server.registerTool('spawn_slot',{inputSchema:{slot:z.number().int().min(0).max(99999)}},async({slot})=>{
  const program='import os,sys; f=os.open(sys.argv[1],os.O_RDWR); os.pwrite(f,("child:"+sys.argv[2]).encode(),int(sys.argv[2])*128); os.close(f)';
  await new Promise((resolve,reject)=>{
    const child=spawn('python3.11',['-c',program,`${root}/slots.bin`,String(slot)],{stdio:'ignore'});
    child.on('error',reject);child.on('exit',code=>code===0?resolve():reject(new Error(`child exit ${code}`)));
  });
  return {content:[{type:'text',text:`spawned slot ${slot}`} ]};
});
let batchQueue=[];
let batchTimer=null;
server.registerTool('batch_io',{inputSchema:{slot:z.number().int().min(0).max(99999),joined:z.boolean().default(false)}},({slot,joined})=>new Promise((resolve,reject)=>{
  batchQueue.push({slot,joined,context:globalThis.causpanContext?.current()??0n,resolve,reject});
  if(batchTimer)return;
  batchTimer=setTimeout(async()=>{
    batchTimer=null;
    const entries=batchQueue.splice(0).sort((a,b)=>a.slot-b.slot);
    try{
      if(entries.some((entry,i)=>entry.slot!==entries[0].slot+i))throw new Error('batch oracle needs contiguous slots');
      const buffer=Buffer.alloc(entries.length*stride);
      entries.forEach((entry,i)=>buffer.write(`slot:${entry.slot}`,i*stride));
      const perform=()=>file.write(buffer,0,buffer.length,entries[0].slot*stride);
      if(entries[0].joined){
        if(!globalThis.causpanContext?.withParents)throw new Error('join instrumentation unavailable');
        await globalThis.causpanContext.withParents(entries.map(entry=>entry.context),perform);
      }else await perform();
      for(const entry of entries)entry.resolve({content:[{type:'text',text:`batched slot ${entry.slot}`} ]});
    }catch(error){for(const entry of entries)entry.reject(error);}
  },15);
}));
server.registerTool('fail_probe',{inputSchema:{slot:z.number().int().min(0).max(99999)}},async({slot})=>{
  const readonly=await fs.open(`${root}/slots.bin`,'r');
  try{
    const result=await globalThis.causpanContext.queueProbe(readonly.fd,slot*stride,0,false);
    if(result.bytes!==-1)throw new Error('expected a rejected write to readonly descriptor');
    return {content:[{type:'text',text:JSON.stringify(result)}],structuredContent:result};
  }finally{await readonly.close();}
});
server.registerTool('cancel_probe',{inputSchema:{slot:z.number().int().min(0).max(99999),cancel:z.boolean()}},async({slot,cancel})=>{
  if(!globalThis.causpanContext)throw new Error('cancel_probe requires instrumentation addon');
  const result=await globalThis.causpanContext.queueProbe(file.fd,slot*stride,25,cancel);
  return {content:[{type:'text',text:JSON.stringify(result)}],structuredContent:result};
});
server.registerTool('barrier',{inputSchema:{}},async()=>{
  await Promise.allSettled([...pending]);
  await backgroundPromise;
  if(errors.length)throw new Error(errors.join('; '));
  return {content:[{type:'text',text:'all work drained'}]};
});
process.stdin.on('end',async()=>{
  clearInterval(background);
  await Promise.allSettled([...pending]);
  await backgroundPromise;
  await file.close();
});
await server.connect(new StdioServerTransport());
