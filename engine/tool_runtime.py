#!/usr/bin/env python3
"""Local MCP health and metadata-only tool usage."""
from __future__ import annotations
import argparse,json,os,subprocess,sys
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent; RUNTIME=ROOT/'runtime'
def browser_session():
 """Does Playwright have a session to reuse, and for which engagement?

 The MCP server is launched once per session with its flags fixed, and it inherits
 the cwd of the Claude Code session — so an engagement chosen later in the session
 cannot change the browser's profile. Printing the mode here is what makes that
 visible before a login is spent rather than after.
 """
 sys.path.insert(0,str(ROOT/'engine'))
 try:
  from identity import storage_state_for  # type: ignore
  path=storage_state_for()
 except Exception: return None
 if path is None:
  return {'mode':'isolated','detail':'no session reuse — start the session inside '
          'Targets/<name>/ or set CBH_PROJECT before launching, or the browser logs in again '
          'every run'}
 profile=path.parent/'browser-profile'
 return {'mode':'persistent','engagement':path.parent.name,'profile':str(profile),
         'exists':profile.is_dir(),
         'detail':('reusing the stored session' if profile.is_dir() else
                   'fresh profile — this run\'s login will be kept')}
def caido_up(quiet=True):
 # health.mjs --start only launches the Burp bridge; the Caido MCP needs caido-cli
 # itself listening, and that does not survive a reboot. Idempotent (2026-10-16).
 s=ROOT/'scripts'/'caido-up.sh'
 if not s.is_file(): return 127
 try: p=subprocess.run(['bash',str(s)]+(['--quiet'] if quiet else []),text=True,capture_output=True,timeout=45)
 except Exception: return 1
 if p.returncode and not quiet: print((p.stderr or '').strip(),file=sys.stderr)
 return p.returncode
def doctor(start=False,as_json=False,only=None):
 if start and only in (None,'caido'): caido_up(quiet=as_json)
 c=['node',str(RUNTIME/'health.mjs')]+(['--start'] if start else [])+([f'--only={only}'] if only else [])
 try:p=subprocess.run(c,cwd=RUNTIME,text=True,capture_output=True,timeout=240 if start else 45)
 except subprocess.TimeoutExpired: print('tool doctor timed out',file=sys.stderr); return 124
 raw=p.stdout.strip()
 if as_json: print(raw or json.dumps({'checks':[],'error':p.stderr[-500:]}))
 else:
  try:
   for x in json.loads(raw).get('checks',[]):
    print(f"{'READY' if x.get('status')=='ready' else 'FAILED':6} {x['name']:<10} {len(x.get('tools',[]))} tools ({x.get('duration_ms','?')} ms)")
    if x.get('error'): print('       '+x['error'])
   b=browser_session()
   if b: print(f"{'SESSION':6} playwright  {b['mode']}"
               f"{' for '+b['engagement'] if b.get('engagement') else ''} — {b['detail']}")
  except json.JSONDecodeError: print(raw or p.stderr,file=sys.stderr)
 return p.returncode
def record_usage(session,tool,status):
 if not session or not tool:return
 safe=''.join(c if c.isalnum() or c in '._-' else '_' for c in session)[:120] or 'unknown'; sys.path.insert(0,str(ROOT/'engine')); from paths import memory_dir; d=memory_dir()/'tool-usage'/f'{safe}.jsonl'; d.parent.mkdir(parents=True,exist_ok=True)
 with d.open('a',encoding='utf-8') as f:f.write(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'tool':tool[:160],'status':status},ensure_ascii=False)+'\n')
 os.chmod(d,0o600)
def main(argv=None):
 p=argparse.ArgumentParser(prog='cbh tools'); s=p.add_subparsers(dest='action',required=True); d=s.add_parser('doctor'); d.add_argument('--start',action='store_true'); d.add_argument('--json',dest='as_json',action='store_true'); d.add_argument('--only',choices=['burpmcp','caido','playwright']); u=s.add_parser('record'); u.add_argument('session'); u.add_argument('tool'); u.add_argument('status'); a=p.parse_args(argv)
 return doctor(a.start,a.as_json,a.only) if a.action=='doctor' else (record_usage(a.session,a.tool,a.status) or 0)
if __name__=='__main__': raise SystemExit(main())
