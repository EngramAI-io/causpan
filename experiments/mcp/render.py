#!/usr/bin/env python3
"""Render a standalone, interactive syscall timeline from an actual captured run."""
import argparse
import hashlib
import json
from pathlib import Path

PAGE=r'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Causpan evidence viewer</title><style>
body{font:15px system-ui,sans-serif;margin:28px;background:#f6f8fb;color:#152436}main{max-width:1250px;margin:auto}h1{font-size:28px;margin-bottom:8px}p{line-height:1.55}.panel{background:white;border:1px solid #dce2ea;border-radius:10px;padding:18px;margin:16px 0}select,button{padding:8px;font:inherit}label{margin-right:16px}.muted{color:#5f6d7b}canvas{width:100%;display:block}table{width:100%;border-collapse:collapse;font-size:13px}td,th{text-align:left;border-bottom:1px solid #e4e8ef;padding:8px;vertical-align:top}td{overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}.scroll{overflow:auto;max-height:600px}.bad{color:#b3261e}.pill{display:inline-block;background:#edf2fc;border-radius:5px;padding:4px 8px;margin:3px}a{color:#1757ad}</style>
<main><h1>Causpan evidence viewer</h1><p id="run" class="muted"></p><div id="summary"></div>
<p>Each point is an observed filesystem syscall entry. Shading shows the selected MCP request interval; attribution comes from propagated runtime context, not the shading. A syscall can have multiple request parents.</p>
<div class="panel"><label>Request <select id="request"></select></label><label><input type="checkbox" id="background"> Show background events</label><p id="detail"></p><pre id="arguments"></pre></div>
<div class="panel scroll"><canvas id="timeline"></canvas></div>
<div class="panel"><h2>Captured filesystem events</h2><p id="counts" class="muted"></p><div class="scroll"><table><thead><tr><th>Relative ms</th><th>PID / TID</th><th>Syscall / return</th><th>Request parents</th><th>Resource</th><th>Evidence</th></tr></thead><tbody id="events"></tbody></table></div></div>
<p class="muted">This view shows selected fixture-path events. Startup and other syscalls remain in the raw captures. A structural capture check is not an independent accuracy proof; consult the oracle report where available.</p></main>
<script id="data" type="application/json">__DATA__</script><script>
const D=JSON.parse(document.getElementById('data').textContent),Q=id=>document.getElementById(id);
Q('run').textContent=D.run;
for(const [key,value] of Object.entries({validated:D.validation.valid,captureValid:D.report.valid,requests:D.report.requests,joins:D.report.joins||0,...D.report.fixture_score})){const span=document.createElement('span');span.className='pill';span.textContent=key+': '+value;Q('summary').append(span)}
if(!D.validation.valid){const warning=document.createElement('p');warning.className='bad';warning.textContent='Unvalidated evidence: '+D.validation.errors.join('; ');Q('summary').append(warning)}
const all=document.createElement('option');all.value='';all.textContent='All requests';Q('request').append(all);
D.calls.forEach((call,i)=>{const option=document.createElement('option');option.value=String(i);option.textContent=JSON.stringify(call.id)+' · '+call.tool;Q('request').append(option)});
const time=(ns,base)=>Number(BigInt(ns)-BigInt(base))/1e6;
function draw(){
 if(!D.calls.length){Q('detail').textContent='No completed request records are available.';Q('counts').textContent='No request timeline';return}
 const call=Q('request').value===''?null:D.calls[Number(Q('request').value)];
 let events=D.events.filter(e=>call?(e.request_ids||[]).some(id=>JSON.stringify(id)===JSON.stringify(call.id)):e.request_ids.length);
 let base=call?call.start_ns:D.calls[0].start_ns;
 if(Q('background').checked){const end=call?events.reduce((v,e)=>BigInt(e.timestamp_ns)>v?BigInt(e.timestamp_ns):v,BigInt(call.end_ns)):BigInt(D.calls[D.calls.length-1].end_ns);events=events.concat(D.events.filter(e=>!e.request_ids.length&&BigInt(e.timestamp_ns)>=BigInt(base)&&BigInt(e.timestamp_ns)<=end))}
 events.sort((a,b)=>BigInt(a.timestamp_ns)<BigInt(b.timestamp_ns)?-1:1);
 Q('detail').textContent=call?call.tool+' · request '+JSON.stringify(call.id)+' · '+time(call.end_ns,call.start_ns).toFixed(3)+' ms observed interval':'Select a request to inspect its worker handoffs and effects.';
 Q('arguments').textContent=call?JSON.stringify(call.arguments,null,2):'';
 const tids=[...new Set(events.map(e=>e.tid))].sort((a,b)=>a-b),end=Math.max(1,...events.map(e=>time(e.timestamp_ns,base)),call?time(call.end_ns,base):0),start=Math.min(0,...events.map(e=>time(e.timestamp_ns,base)));
 const canvas=Q('timeline');canvas.width=1180;canvas.height=Math.max(150,80+tids.length*32);const ctx=canvas.getContext('2d');ctx.clearRect(0,0,canvas.width,canvas.height);ctx.font='12px system-ui';const x=t=>120+(t-start)/(end-start+0.1)*1010;
 for(let i=0;i<=5;i++){const t=start+(end-start)*i/5;ctx.strokeStyle='#e1e6ed';ctx.beginPath();ctx.moveTo(x(t),30);ctx.lineTo(x(t),canvas.height-30);ctx.stroke();ctx.fillStyle='#5f6d7b';ctx.fillText(t.toFixed(2)+' ms',x(t)-16,canvas.height-10)}
 tids.forEach((tid,i)=>{const y=48+i*32;ctx.fillStyle='#37465a';ctx.fillText('TID '+tid,8,y+4);if(call){ctx.fillStyle='#e8eefb';ctx.fillRect(x(0),y-12,x(time(call.end_ns,base))-x(0),24)}});
 events.forEach(e=>{const y=48+tids.indexOf(e.tid)*32;ctx.fillStyle=e.request_ids.length>1?'#923eaa':e.request_ids.length?'#176ac6':'#9da8b5';ctx.beginPath();ctx.arc(x(time(e.timestamp_ns,base)),y,4,0,Math.PI*2);ctx.fill()});
 Q('events').replaceChildren();Q('counts').textContent=events.length+' displayed events · blue: one request · purple: multiple parents · gray: background';
 for(const e of events){const tr=document.createElement('tr');const values=[time(e.timestamp_ns,base).toFixed(3),e.pid+' / '+e.tid,e.syscall+' → '+e.return_value,JSON.stringify(e.request_ids),e.paths.join('\n')];for(const value of values){const td=document.createElement('td');td.textContent=value;tr.append(td)}const td=document.createElement('td');const a=document.createElement('a');a.href='traces/'+e.source.split(':')[0];a.textContent=e.source;td.append(a);const div=document.createElement('div');div.textContent='context '+e.context+' · work '+e.operation+' · '+e.origin;td.append(div);tr.append(td);Q('events').append(tr)}
}
Q('request').addEventListener('change',draw);Q('background').addEventListener('change',draw);draw();
</script></html>'''

def render(run):
    report=json.loads((run/'causal-report.json').read_text())
    errors=[]
    manifest=json.loads((run/'manifest.json').read_text())
    if manifest.get('status')!='complete':errors.append('run did not complete')
    if not report.get('valid'):errors.append('capture validation failed')
    for name in ['control-score.json','batch-score.json','fileops-score.json','network-score.json']:
        if (run/name).exists() and not json.loads((run/name).read_text()).get('valid'):
            errors.append('independent evaluation failed: '+name)
    for name,digest in report.get('output_sha256',{}).items():
        if hashlib.sha256((run/name).read_bytes()).hexdigest()!=digest:
            errors.append('output integrity mismatch: '+name)
    calls=list(map(json.loads,(run/'tool-calls.jsonl').read_text().splitlines()))
    selected={row['source'] for row in map(json.loads,(run/'attribution.jsonl').read_text().splitlines())}
    events=[row for row in map(json.loads,(run/'causal-attribution.jsonl').read_text().splitlines()) if row['source'] in selected]
    for event in events:
        event['timestamp_ns']=str(event['timestamp_ns'])
        event.setdefault('request_ids',[event['request_id']] if event['request_id'] is not None else [])
    for call in calls:
        call['start_ns']=str(call['start_ns']);call['end_ns']=str(call['end_ns'])
    if json.loads((run/'causal-report.json').read_text())!=report:
        raise ValueError('Analysis changed while rendering; retry after it completes')
    data=json.dumps(dict(run=str(run),calls=calls,events=events,report=report,
                         validation=dict(valid=not errors,errors=errors))).replace('<','\\u003c')
    path=run/'report.html';path.write_text(PAGE.replace('__DATA__',data));print(path)
    return path

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('run',type=Path)
    render(p.parse_args().run.resolve())
