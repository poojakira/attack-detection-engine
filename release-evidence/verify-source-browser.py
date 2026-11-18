import datetime, json, os, subprocess, time, urllib.request
from pathlib import Path
out=Path(__file__).parent
source=Path('/workspace/work/candidates/attack-detection-engine')
command=['/workspace/work/envs/attack/bin/python','-m','detection_engine.platform.local','--dashboard',str(source/'dashboard-ui/dist'),'--username','synthetic-analyst','--password-stdin']
env=dict(os.environ,AEGIS_DATABASE_URL='postgresql+psycopg://aegis:synthetic-local-db-only@127.0.0.1:55432/aegis_qa01_final')
subprocess.run(['docker','exec','attack-workbench-pg-20261117','createdb','-U','aegis','aegis_qa01_final'],check=True)
start=datetime.datetime.now(datetime.timezone.utc).isoformat()
with (out/'source-server.log').open('w') as log:
 server=subprocess.Popen(command,cwd=source,env=env,stdin=subprocess.PIPE,stdout=log,stderr=subprocess.STDOUT,text=True)
 server.stdin.write('SyntheticLocalEvaluation-42\n');server.stdin.close()
 try:
  for _ in range(100):
   try:
    with urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=1) as response: health=json.load(response)
    break
   except OSError: time.sleep(.1)
  else: raise RuntimeError('server startup failed')
  assert health['source']['clean'] is True
  assert health['source']['commit']==subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip()
  (out/'health.json').write_text(json.dumps(health,indent=2))
  result=subprocess.run(['/workspace/work/tooling/venv/bin/python',str(out/'run-command.py'),'browser','/workspace/work/tooling/venv/bin/python',str(source/'scripts/browser-workbench.py'),'--evidence',str(out/'browser')],cwd=source)
  if result.returncode: raise RuntimeError('browser acceptance failed')
 finally:
  server.terminate();server.wait(timeout=10)
  (out/'source-server-run.json').write_text(json.dumps({'command':command,'started_at':start,'finished_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'expected_shutdown':True,'exit_code':server.returncode},indent=2))
