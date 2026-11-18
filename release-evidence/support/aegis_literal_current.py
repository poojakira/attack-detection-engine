from pathlib import Path
import subprocess,json,os,time,signal,urllib.request,datetime
root=Path('/workspace/work/candidates/attack-detection-engine');out=Path('/workspace/work/evidence/attack-detection-engine/launcher-orchestration-8ae9090');private=Path('/workspace/work/private-runtime-backups/aegis-8ae9090');private.mkdir(parents=True,exist_ok=True);os.chmod(private,0o700)
container='attack-workbench-pg-20261117';now=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat()
dbs=subprocess.check_output(['docker','exec',container,'psql','-U','aegis','-d','postgres','-At','-c','SELECT datname FROM pg_database WHERE NOT datistemplate ORDER BY datname'],text=True).splitlines()
for db in dbs:
    path=private/(db+'.dump')
    with path.open('wb') as f:subprocess.run(['docker','exec',container,'pg_dump','-U','aegis','-Fc','-d',db],stdout=f,check=True)
    os.chmod(path,0o600)
subprocess.run(['docker','stop',container],check=True,stdout=subprocess.DEVNULL)
process=None
try:
    with (out/'launcher.log').open('w') as log:
        process=subprocess.Popen(['./scripts/local-workbench.sh'],cwd=root,stdin=subprocess.PIPE,stdout=log,stderr=subprocess.STDOUT,start_new_session=True,text=True)
        process.stdin.write('SYNTHETIC_LOCAL_EVALUATION_ONLY_20261117\n');process.stdin.flush()
        for _ in range(220):
            if process.poll() is not None:raise RuntimeError('Launcher exited; inspect log')
            try:
                with urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=1) as response:health=json.load(response)
                assert health['source']['commit']=='8ae9090b560871d1e584d717734693bb570fffae' and health['source']['clean'];break
            except OSError:time.sleep(.5)
        else:raise RuntimeError('Startup deadline')
        subprocess.run(['/workspace/work/tooling/venv/bin/python','/workspace/work/tooling/aegis_literal_browser_8ae.py'],check=True)
        os.killpg(process.pid,signal.SIGINT);exit_code=process.wait(timeout=25)
        active=subprocess.check_output(['docker','inspect','-f','{{.State.Running}}','aegis-local-workbench-postgres'],text=True).strip();assert exit_code==0 and active=='false'
        (out/'stop.json').write_text(json.dumps({'utc':now(),'launcher_exit_code':exit_code,'postgres_running_after_stop':active,'termination':'SIGINT to owned subprocess session'},indent=2)+'\n');process=None
    subprocess.run(['/workspace/work/tooling/venv/bin/python','/workspace/work/tooling/aegis_literal_restart_8ae.py'],check=True)
finally:
    if process is not None and process.poll() is None:
        os.killpg(process.pid,signal.SIGINT)
        try:process.wait(timeout=25)
        except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGTERM);process.wait(timeout=10)
    subprocess.run(['docker','start',container],check=True,stdout=subprocess.DEVNULL)
    for _ in range(60):
        if subprocess.run(['docker','exec',container,'pg_isready','-U','aegis'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:break
        time.sleep(.5)
    existing=subprocess.check_output(['docker','exec',container,'psql','-U','aegis','-d','postgres','-At','-c','SELECT datname FROM pg_database WHERE NOT datistemplate'],text=True).splitlines()
    for db in dbs:
        if db not in existing:subprocess.run(['docker','exec',container,'createdb','-U','aegis',db],check=True)
        with (private/(db+'.dump')).open('rb') as f:subprocess.run(['docker','exec','-i',container,'pg_restore','-U','aegis','--clean','--if-exists','--exit-on-error','-d',db],stdin=f,check=True,stdout=subprocess.DEVNULL)
    (out/'review-database-preservation.json').write_text(json.dumps({'utc':now(),'scope':'Disposable task PostgreSQL databases only','private_backup_retained':True,'database_count':len(dbs),'all_pg_dump_exit_codes':0,'all_pg_restore_exit_codes':0,'original_container_running':True,'no_backup_bytes_or_credentials_published':True},indent=2)+'\n')
print('Current-source literal launcher/browser/stop/restart completed; review databases restored',flush=True)
