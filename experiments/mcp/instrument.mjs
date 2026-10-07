// Attribution uses AsyncLocalStorage (set by this module), never client-supplied
// request parameters. The _meta field is passed through to the tool but ignored
// for context binding — see Protocol override below.
import { AsyncLocalStorage, createHook } from 'node:async_hooks';
import { createRequire } from 'node:module';
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { Protocol } from './node_modules/@modelcontextprotocol/sdk/dist/esm/shared/protocol.js';
const require=createRequire(import.meta.url);
const native=require('./native/context.node');
const build=JSON.parse(fs.readFileSync(new URL('./native/build.json',import.meta.url)));
if(process.arch!=='arm64' || process.versions.node!==build.versions.node ||
   createHash('sha256').update(fs.readFileSync(process.execPath)).digest('hex')!==build.sha256)
  throw new Error('Unsupported Node binary: rebuild and verify instrumentation');
const run=process.env.CAUSPAN_RUN;
if(!run) throw new Error('CAUSPAN_RUN required');
const REQUEST_MAP_MODE = 0o600;   // owner read+write only for request-map.jsonl
const mapfd=fs.openSync(`${run}/request-map.jsonl`,'wx',REQUEST_MAP_MODE);
const storage=new AsyncLocalStorage();
let next=1n;
const owners=new Map();
native.install(BigInt(build.address),`${run}/native-events.jsonl`);
const sync=()=>native.context(storage.getStore()??0n);
const stack=[];
createHook({before:()=>stack.push(native.context(storage.getStore()??0n)),
            after:()=>native.context(stack.pop()??0n)}).enable();
const original=Protocol.prototype._onrequest;
Protocol.prototype._onrequest=function(request,extra) {
  if(request.method!=='tools/call') return original.call(this,request,extra);
  // Context is assigned by this trusted wrapper, not by the client request.
  // The _meta field (if present) is passed through to the tool but not used here.
  const context=next++;
  owners.set(context,new Set([context]));
  fs.writeSync(mapfd,JSON.stringify({kind:'request',context:Number(context),rpc_id:request.id,
    method:request.method,tool:request.params?.name})+'\n');
  return storage.run(context,()=>{
    sync();
    try { return original.call(this,request,extra); }
    finally { native.context(0n); }
  });
};
// Allows the controlled workload to create unattributed background work deliberately.
function withParents(parents,fn) {
  const roots=new Set();
  for(const parent of parents){
    const known=owners.get(parent);
    if(!known)throw new Error('Unknown provenance parent');
    for(const root of known)roots.add(root);
  }
  if(!roots.size)throw new Error('A provenance join needs parents');
  let context;
  if(roots.size===1)context=[...roots][0];
  else{
    context=next++;
    owners.set(context,roots);
    fs.writeSync(mapfd,JSON.stringify({kind:'join',context:Number(context),parents:[...roots].map(Number)})+'\n');
  }
  return storage.run(context,()=>{
    const previous=native.context(context);
    try{return fn();}finally{native.context(previous);}
  });
}
globalThis.causpanContext={withParents,current:()=>storage.getStore()??0n,queueProbe:native.queueProbe,withoutRequest:fn=>{
  const previous=storage.getStore()??0n;
  try{return storage.run(undefined,()=>{sync();return fn();});}
  finally{native.context(previous);}
}};
