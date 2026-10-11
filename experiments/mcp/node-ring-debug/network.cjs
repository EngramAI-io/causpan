const net=require('node:net');
(async()=>{
  const server=net.createServer(socket=>socket.end('ok'));
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const count=Number(process.argv[2]||4);
  if(!Number.isInteger(count)||count<1||count>1000)throw Error('invalid connection count');
  for(let i=0;i<count;i++) await new Promise((resolve,reject)=>{
    const socket=net.connect(server.address().port,'127.0.0.1');
    let data='';socket.on('data',chunk=>data+=chunk);
    socket.on('error',reject);socket.on('end',()=>data==='ok'?resolve():reject(Error('payload mismatch')));
  });
  await new Promise(resolve=>server.close(resolve));
})().catch(error=>{console.error(error);process.exitCode=1});
