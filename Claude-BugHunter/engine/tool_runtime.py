#!/usr/bin/env python3
"""Local MCP health and metadata-only tool usage."""
from __future__ import annotations
import argparse,json,os,subprocess,sys
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent; RUNTIME=ROOT/'runtime'
def doctor(start=False,as_json=False,only=None):
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
  except json.JSONDecodeError: print(raw or p.stderr,file=sys.stderr)
 return p.returncode
def record_usage(session,tool,status):
 if not session or not tool:return
 safe=''.join(c if c.isalnum() or c in '._-' else '_' for c in session)[:120] or 'unknown'; d=ROOT.parent/'hunt-memory'/'tool-usage'/f'{safe}.jsonl'; d.parent.mkdir(parents=True,exist_ok=True)
 with d.open('a',encoding='utf-8') as f:f.write(json.dumps({'at':datetime.now(timezone.utc).isoformat(),'tool':tool[:160],'status':status},ensure_ascii=False)+'\n')
 os.chmod(d,0o600)
def main(argv=None):
 p=argparse.ArgumentParser(prog='cbh tools'); s=p.add_subparsers(dest='action',required=True); d=s.add_parser('doctor'); d.add_argument('--start',action='store_true'); d.add_argument('--json',dest='as_json',action='store_true'); d.add_argument('--only',choices=['burpmcp','playwright']); u=s.add_parser('record'); u.add_argument('session'); u.add_argument('tool'); u.add_argument('status'); a=p.parse_args(argv)
 return doctor(a.start,a.as_json,a.only) if a.action=='doctor' else (record_usage(a.session,a.tool,a.status) or 0)
if __name__=='__main__': raise SystemExit(main())
