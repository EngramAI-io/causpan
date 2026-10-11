// Deterministic MCP replay through the SDK's in-memory transport.
// This exercises real protocol dispatch, not an LLM or stdio transport.
import net from 'node:net';
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';
const base=pathToFileURL(process.env.CAUSPAN_MCP_ROOT+'/').href;
const {McpServer}=await import(base+'node_modules/@modelcontextprotocol/sdk/dist/esm/server/mcp.js');
const {Client}=await import(base+'node_modules/@modelcontextprotocol/sdk/dist/esm/client/index.js');
const {InMemoryTransport}=await import(base+'node_modules/@modelcontextprotocol/sdk/dist/esm/inMemory.js');
const {z}=await import(base+'node_modules/zod/index.js');
const oracle=[];
const watcherActions=[];
const server=new McpServer({name:'native-ring-replay',version:'1.0.0'});
const sharedMode=process.env.CAUSPAN_SHARED_WATCHER==='1';
let acceptedShared;
const listener=net.createServer(socket=>{if(sharedMode)acceptedShared=socket;else socket.end('ok');});
await new Promise(resolve=>listener.listen(0,'127.0.0.1',resolve));
let active=0,maxActive=0;
let sharedSocket,sharedPayload,sharedTokens=[];
let sharedActionTurn=0;
if(sharedMode){
  sharedSocket=net.connect(listener.address().port,'127.0.0.1');
  await new Promise((resolve,reject)=>{sharedSocket.once('connect',resolve);sharedSocket.once('error',reject);});
  sharedPayload=new Promise((resolve,reject)=>{
    let data='';sharedSocket.on('data',chunk=>data+=chunk);
    sharedSocket.on('error',reject);sharedSocket.on('end',()=>resolve(data));
  });
  await new Promise(resolve=>setImmediate(resolve));
}
server.registerTool('roundtrip',{inputSchema:{token:z.string()}},async({token})=>{
  active++;maxActive=Math.max(maxActive,active);
  const context=String(globalThis.causpanContext.current());
  let payload;
  if(sharedMode){
    if(sharedTokens.length===0)setImmediate(()=>{sharedActionTurn++;});
    sharedTokens.push(token);
    oracle.push({kind:'socket',token,fd:sharedSocket._handle.fd});
    const stopped=sharedSocket._handle.readStop();
    watcherActions.push({token,turn:sharedActionTurn,action:'stop',result:stopped,fd:sharedSocket._handle.fd});
    if(stopped!==0)throw Error('controlled readStop failed: '+stopped);
    const result=sharedSocket._handle.readStart();
    watcherActions.push({token,turn:sharedActionTurn,action:'start',result,fd:sharedSocket._handle.fd});
    if(result!==0)throw Error('controlled readStart failed: '+result);
    if(sharedTokens.length===Number(process.argv[2]))setImmediate(()=>acceptedShared.end('ok'));
    payload=await sharedPayload;
  }else payload=await new Promise((resolve,reject)=>{
    const socket=net.connect(listener.address().port,'127.0.0.1');
    socket.once('connect',()=>oracle.push({kind:'socket',token,fd:socket._handle.fd}));
    let data='';socket.on('data',chunk=>data+=chunk);
    socket.on('error',reject);socket.on('end',()=>resolve(data));
  });
  if(payload!=='ok')throw Error('payload mismatch');
  active--;
  return {content:[{type:'text',text:JSON.stringify({context,payload})}]};
});
if(process.env.CAUSPAN_MCP_STDIO==='1'){
  const {StdioServerTransport}=await import(base+'node_modules/@modelcontextprotocol/sdk/dist/esm/server/stdio.js');
  await server.connect(new StdioServerTransport());
  process.stdin.on('end',async()=>{
    fs.writeFileSync(process.env.CAUSPAN_RUN+'/socket-oracle.json',JSON.stringify(oracle,null,2));
    fs.writeFileSync(process.env.CAUSPAN_RUN+'/mcp-overlap.json',JSON.stringify({maxActive}));
    await server.close();listener.close();
  });
}else{
const client=new Client({name:'native-ring-replay-client',version:'1.0.0'});
const [a,b]=InMemoryTransport.createLinkedPair();
const send=b.send.bind(b);
b.send=(message,...rest)=>{
  if(message.method==='tools/call')oracle.push({kind:'request',rpc_id:message.id,token:message.params.arguments.token});
  return send(message,...rest);
};
await server.connect(a);await client.connect(b);
const count=Number(process.argv[2]);
if(!Number.isInteger(count)||count<1||count>1000)throw Error('invalid count');
const responses=[];
const concurrency=Number(process.env.CAUSPAN_MCP_CONCURRENCY||1);
if(!Number.isInteger(concurrency)||concurrency<1||concurrency>count)throw Error('invalid concurrency');
if(sharedMode&&concurrency!==count)throw Error('shared watcher requires a single concurrent batch');
for(let start=0;start<count;start+=concurrency){
  const batch=await Promise.all(Array.from({length:Math.min(concurrency,count-start)},(_,index)=>
    client.callTool({name:'roundtrip',arguments:{token:'replay-'+(start+index)}})));
  if(batch.some(response=>response.isError)){
    fs.writeFileSync(process.env.CAUSPAN_RUN+'/mcp-failed-responses.json',JSON.stringify(batch,null,2));
    throw Error('MCP tool failed');
  }
  responses.push(...batch);
}
if(sharedMode)fs.writeFileSync(process.env.CAUSPAN_RUN+'/watcher-action-oracle.json',JSON.stringify(watcherActions,null,2));
fs.writeFileSync(process.env.CAUSPAN_RUN+'/socket-oracle.json',JSON.stringify(oracle,null,2));
fs.writeFileSync(process.env.CAUSPAN_RUN+'/mcp-overlap.json',JSON.stringify({count,concurrency,maxActive}));
fs.writeFileSync(process.env.CAUSPAN_RUN+'/mcp-responses.json',JSON.stringify(responses,null,2));
await client.close();await server.close();
await new Promise(resolve=>listener.close(resolve));

}
