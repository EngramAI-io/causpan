const fs=require('node:fs/promises');
(async()=>{for(let i=0;i<3;i++){const f=await fs.open(process.argv[2],'r');await f.read(Buffer.alloc(16),0,16,0);await f.close();}})().catch(e=>{console.error(e);process.exitCode=1});
