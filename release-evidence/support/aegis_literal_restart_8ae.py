from pathlib import Path
import subprocess,os,signal,time,json,urllib.request,hashlib,datetime
root=Path('/workspace/work/candidates/attack-detection-engine');out=Path('/workspace/work/evidence/attack-detection-engine/launcher-orchestration-8ae9090');prior=json.loads((out/'browser-result.json').read_text());now=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat();started=now();log=(out/'restart-launcher.log').open('w');process=subprocess.Popen(['./scripts/local-workbench.sh'],cwd=root,stdin=subprocess.PIPE,stdout=log,stderr=subprocess.STDOUT,start_new_session=True,text=True);process.stdin.write('SYNTHETIC_LOCAL_EVALUATION_ONLY_20261117\n');process.stdin.flush();client=urllib.request.build_opener(urllib.request.ProxyHandler({}));base='http://127.0.0.1:8000'
def request(path,payload=None,token=None):
 headers={'Content-Type':'application/json'}
 if token:headers['Authorization']='Bearer '+token
 data=None if payload is None else json.dumps(payload).encode()
 return client.open(urllib.request.Request(base+path,data=data,headers=headers),timeout=10)
try:
 for _ in range(160):
  if process.poll() is not None:raise RuntimeError('Launcher exited; inspect restart-launcher.log')
  try:
   with request('/health') as response:health=json.load(response)
   break
  except OSError:time.sleep(.5)
 else:raise RuntimeError('Restart startup deadline')
 with request('/api/v1/auth/token',{'username':'local-analyst','password':'SYNTHETIC_LOCAL_EVALUATION_ONLY_20261117'}) as response:token=json.load(response)['access_token']
 with request('/api/v1/workbench/cases/'+prior['case_id'],token=token) as response:case=json.load(response)
 assert len(case['runs'])==2 and case['runs'][-1]['run_id']==prior['run_id']
 with request('/api/v1/workbench/cases/'+prior['case_id']+'/runs/'+prior['run_id']+'/export',token=token) as response:data=response.read()
 assert hashlib.sha256(data).hexdigest()==prior['report_sha256'];report=json.loads(data);assert len(report['events'])==30 and report['config']['bulk_access_threshold']==40 and report['delta']['removed']==1;assert health['source']['commit']==prior['source_commit'] and health['source']['clean'] is True
 result={'source_commit':prior['source_commit'],'utc_start':started,'utc_end':now(),'result':'PASS','command':['./scripts/local-workbench.sh'],'source_status':'CLEAN','checks':['literal restart with existing local PostgreSQL volume','local sign-in after restart','same case and two immutable runs restored','same30 persisted events and threshold40 delta','export bytes exactly match pre-restart SHA256','source clean/commit exact'],'case_id':prior['case_id'],'run_id':prior['run_id'],'report_sha256':prior['report_sha256'],'environment_scope':'Existing isolated dependencies reused; actual pip install and npm ci/build ran. No clean-download-environment claim.'};(out/'restart-result.json').write_text(json.dumps(result,indent=2)+'\n');print(result,flush=True)
finally:
 if process.poll() is None:os.killpg(process.pid,signal.SIGINT)
 try:exit_code=process.wait(timeout=20)
 except subprocess.TimeoutExpired:
  os.killpg(process.pid,signal.SIGTERM);exit_code=process.wait(timeout=10)
 log.close();active=subprocess.check_output(['docker','inspect','-f','{{.State.Running}}','aegis-local-workbench-postgres'],text=True).strip();(out/'restart-stop.json').write_text(json.dumps({'utc':now(),'launcher_exit_code':exit_code,'postgres_running_after_stop':active,'termination':'SIGINT to owned subprocess session'},indent=2)+'\n');print({'launcher_exit_code':exit_code,'postgres_running_after_stop':active},flush=True)
