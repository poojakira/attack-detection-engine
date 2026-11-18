import datetime, json, os, socket, subprocess, time, urllib.request
from pathlib import Path
out=Path(__file__).parent
source=Path('/workspace/work/candidates/attack-detection-engine')
parent=Path('/workspace/work/attack-wheel-smoke-parent')
python=str(parent/'venv/bin/python')
with socket.socket() as probe:
 probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
command=[python,'-m','detection_engine.platform.local','--dashboard',str(source/'dashboard-ui/dist'),'--username','synthetic-analyst','--password-stdin','--port',str(port)]
env=dict(os.environ,AEGIS_DATABASE_URL='postgresql+psycopg://aegis:synthetic-local-db-only@127.0.0.1:55432/aegis_docs_wheel_20261118')
subprocess.run(['docker','exec','attack-workbench-pg-20261117','createdb','-U','aegis','aegis_docs_wheel_20261118'],check=True)
start=datetime.datetime.now(datetime.timezone.utc).isoformat()
base=f'http://127.0.0.1:{port}'

def request(path,body=None,token=None):
 data=None if body is None else json.dumps(body).encode()
 headers={'Content-Type':'application/json'}
 if token: headers['Authorization']='Bearer '+token
 with urllib.request.urlopen(urllib.request.Request(base+path,data=data,headers=headers),timeout=15) as response:
  return json.load(response)

def start_server():
 log=(out/'wheel-server.log').open('a')
 p=subprocess.Popen(command,cwd=parent,env=env,stdin=subprocess.PIPE,stdout=log,stderr=subprocess.STDOUT,text=True)
 p.stdin.write('SyntheticLocalEvaluation-42\n');p.stdin.close()
 for _ in range(100):
  try: health=request('/health');break
  except OSError: time.sleep(.1)
 else: raise RuntimeError('wheel server startup failed')
 assert health['source']=={'commit':'UNKNOWN','clean':None}, health
 return p,log,health

p,log,health=start_server()
try:
 token=request('/api/v1/auth/token',{'username':'synthetic-analyst','password':'SyntheticLocalEvaluation-42'})['access_token']
 sample=request('/api/v1/workbench/sample',token=token)['input_text']
 first=request('/api/v1/workbench/cases',{'title':'Installed wheel synthetic smoke','input_text':sample},token)
 assert len(first['events'])==30 and len(first['findings'])==1
 second=request('/api/v1/workbench/cases/'+first['case_id']+'/runs',{'config':{'bulk_access_threshold':40},'expected_run_id':first['run_id']},token)
 assert second['findings']==[] and second['delta']['removed']==1
 p.terminate();p.wait(timeout=10);log.close()
 p,log,health=start_server()
 token=request('/api/v1/auth/token',{'username':'synthetic-analyst','password':'SyntheticLocalEvaluation-42'})['access_token']
 saved=request('/api/v1/workbench/cases/'+first['case_id'],token=token)
 assert len(saved['runs'])==2
 exported=request('/api/v1/workbench/cases/'+first['case_id']+'/runs/'+second['run_id']+'/export',token=token)
 assert exported==second
 module=json.loads(subprocess.check_output([python,'-c','import json,detection_engine;print(json.dumps({"module":detection_engine.__file__,"version":detection_engine.__version__}))'],cwd=parent,env=env,text=True))
 assert str(parent/'venv') in module['module']
 unrelated=subprocess.check_output(['git','rev-parse','HEAD'],cwd=parent,text=True).strip()
 assert unrelated != health['source']['commit']
 result={'status':'passed','started_at':start,'finished_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'module':module,'unrelated_parent_head':unrelated,'installed_health':health,'checks':['wheel imported outside source','packaged migrations clean startup','canonical detector/correlation and PostgreSQL persistence','same-input configuration rerun delta','actual API process restart and migration idempotency','saved case and export after restart','UNKNOWN installed provenance despite unrelated enclosing Git HEAD'],'input_sha256':first['input_sha256'],'config_sha256':second['config_sha256']}
 (out/'installed-wheel.json').write_text(json.dumps(result,indent=2))
finally:
 p.terminate();p.wait(timeout=10);log.close()
