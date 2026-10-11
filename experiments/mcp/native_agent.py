"""Launch the established Codex CLI agent against the native stdio bridge."""
import json
import subprocess
import sys
import time


def capture(command,env,run,here,count):
    (run/'native-launch.json').write_text(json.dumps(dict(command=command,
        environment={k:v for k,v in env.items() if k.startswith('CAUSPAN_')}),indent=2)+'\n')
    prompt=('Use only causpan_native MCP tools. Discover them if needed. Do not use shell, code execution, other servers, or delegation. '
            'Call roundtrip exactly once for each token: '+', '.join('agent-'+str(i) for i in range(count))+'. '
            'Verify each result contains payload ok, report the results and stop.')
    (run/'prompt.txt').write_text(prompt+'\n')
    sandbox=run/'agent-workspace';sandbox.mkdir()
    config={'mcp_servers.causpan_native.command':sys.executable,
            'mcp_servers.causpan_native.args':[str(here/'native_stdio_proxy.py'),str(run)],
            'mcp_servers.causpan_native.required':True,
            'mcp_servers.causpan_native.tools.roundtrip.approval_mode':'approve',
            'mcp_servers.causpan_native.startup_timeout_sec':60,
            'mcp_servers.causpan_native.tool_timeout_sec':60,'approval_policy':'never'}
    cmd=['codex','exec','--ignore-user-config','--ephemeral','--skip-git-repo-check','--json','--sandbox','read-only','-C',str(sandbox)]
    for key,value in config.items():cmd+=['-c',key+'='+json.dumps(value)]
    cmd += [prompt]
    with (run/'agent.jsonl').open('w') as out,(run/'agent.stderr').open('w') as err:
        subprocess.run(cmd,stdin=subprocess.DEVNULL,stdout=out,stderr=err,check=True,timeout=240)
    deadline=time.monotonic()+25
    while not (run/'bridge-status.json').exists() and time.monotonic()<deadline:time.sleep(.1)
    if json.loads((run/'bridge-status.json').read_text())['status']!='complete':raise RuntimeError('native bridge incomplete')
    protocol=json.loads((run/'stdio-protocol.json').read_text())
    calls=[r['message'] for r in protocol if r['direction']=='send' and r['message'].get('method')=='tools/call']
    if len(calls)!=count or {m['params']['arguments']['token'] for m in calls}!={'agent-'+str(i) for i in range(count)}:
        raise ValueError('agent did not execute required distinct tools')
    return 0
