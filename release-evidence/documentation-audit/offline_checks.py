import subprocess,json,pathlib,datetime
r=pathlib.Path('/workspace/work/candidates/attack-detection-engine');o=pathlib.Path('/workspace/work/doc-reconciliation/attack-detection-engine');results=[]
base=['docker','run','--rm','-i','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','512m','--cpus','1','--pids-limit','128','--tmpfs','/home/verifier:uid=1000,gid=1000,mode=700,size=16m','--tmpfs','/tmp:rw,noexec,nosuid,size=16m','--mount',f'type=bind,src={r},dst=/repo,readonly','--mount','type=bind,src=/workspace/work/envs/attack/lib/python3.12/site-packages,dst=/deps,readonly','--mount','type=bind,src=/workspace/work/references/attack-v19.2,dst=/attack-data,readonly','--env','PYTHONDONTWRITEBYTECODE=1','--env','PYTHONPATH=/repo:/deps','--env','ATTACK_DATA_DIR=/attack-data','--workdir','/repo','sha256:5fdc90be02864ceb9c58f1083247dc31460f109468b8409c34526c59a55a9741','python','-m','detection_engine.cli']
for args,data,expected in [(['--help'],None,0),(['--input','-','--output','-','--fail-on','high'],'{}\n',0),(['--input','-','--output','-','--fail-on','high'],'[]\n',2)]:
 command=base+args;p=subprocess.run(command,input=data,text=True,capture_output=True,timeout=60);results.append({'command':command,'stdin':data,'expected_exit':expected,'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr,'passed':p.returncode==expected})
code='''from detection_engine.platform.connectors.fhir_auditevent import FhirAuditEventConnector
c=FhirAuditEventConnector()
e={"resourceType":"AuditEvent","recorded":"2026-11-18T10:00:00.125Z","agent":[{"who":{"reference":"Practitioner/synthetic-actor"}}],"entity":[{"what":{"reference":"Patient/synthetic-patient"}}]}
r=c.parse(e,organization_id="synthetic-docs",max_items=1000)
assert len(r.items)==1 and not r.items[0].error
attrs=r.items[0].event.normalized_attributes
assert attrs["action"]=="unknown" and attrs["outcome"]=="unknown"
e["action"]="R";e["outcome"]="0"
r=c.parse(e,organization_id="synthetic-docs",max_items=1000)
assert r.items[0].event.normalized_attributes["action"]=="read"
assert r.items[0].event.normalized_attributes["outcome"]=="success"
e["recorded"]="2026-11-18T10:00:00"
r=c.parse(e,organization_id="synthetic-docs",max_items=1000)
assert r.items[0].error
print("Synthetic fractional-time/UNKNOWN/explicit READ-SUCCESS and no-timezone controls passed")'''
p=subprocess.run(['/workspace/work/envs/attack/bin/python','-c',code],cwd=r,text=True,capture_output=True,timeout=30);results.append({'command':['/workspace/work/envs/attack/bin/python','-c',code],'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr,'passed':p.returncode==0})
command=['/workspace/work/envs/attack/bin/python','-m','detection_engine.platform.local','--help'];p=subprocess.run(command,cwd=r,text=True,capture_output=True,timeout=30);results.append({'command':command,'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr,'passed':p.returncode==0})
result={'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=r,text=True).strip(),'source_status':subprocess.check_output(['git','status','--porcelain'],cwd=r,text=True),'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'checks':results,'limits':['CLI helper reused installed dependencies and local checksum-verified ATT&CK bundles; no clean install or image build.','Container had no network, read-only source/dependencies/data and writable ephemeral default HOME; no host HOME override.','No database mutation, cloud, dataset download or supplied native code execution.']};(o/'offline-checks-final.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps([{'exit':v['exit'],'passed':v['passed'],'stdout':v['stdout'][-1000:],'stderr':v['stderr'][-1000:]} for v in results],indent=2));raise SystemExit(not all(v['passed'] for v in results))
