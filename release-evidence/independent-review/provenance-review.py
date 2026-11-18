import datetime, hashlib, json, pathlib, subprocess, sys, zipfile
from importlib import metadata
ROOT=pathlib.Path('/workspace/work/candidates/attack-detection-engine')
OUT=pathlib.Path('/workspace/work/reviews/attack-detection-engine/closure-8ae9090')
core=metadata.distribution('attack-v19-core')
import detection_engine
maps=[]
for name in ['app.js.map','app.css.map']:
    p=ROOT/'dashboard-ui/dist/assets'/name
    source_map=json.loads(p.read_text()); checked=[];mismatched=[]
    for rel,content in zip(source_map['sources'],source_map['sourcesContent']):
        source=(p.parent/rel).resolve()
        if source.is_relative_to(ROOT/'dashboard-ui/src'):
            checked.append(source.relative_to(ROOT).as_posix())
            if source.read_text()!=content:mismatched.append(rel)
    maps.append({'map':name,'source_files_compared':checked,'mismatched':mismatched})
result={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'python':sys.version,'source_module':detection_engine.__file__,'app_version':metadata.version('attack-detection-engine'),'core_version':core.version,'core_direct_url':json.loads(core.read_text('direct_url.json')),'ui_source_map_comparisons':maps,'lock_sha256':{n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in ['requirements.lock','dashboard-ui/package-lock.json']},'served_build_sha256':{p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((ROOT/'dashboard-ui/dist').rglob('*')) if p.is_file()},'git_status_after':subprocess.check_output(['git','-C',str(ROOT),'status','--porcelain'],text=True)}
(OUT/'provenance.json').write_text(json.dumps(result,indent=2)+'\n')
assert result['core_direct_url']['vcs_info']['commit_id']=='087accffc7d9ba7e2c086b9ef72ef7ac6f23c29b'
assert not any(m['mismatched'] for m in maps) and result['git_status_after']==''
print(json.dumps({'source_maps_checked':sum(len(m['source_files_compared']) for m in maps),'mismatches':0,'source_clean':True}))
