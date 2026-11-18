import hashlib, json, pathlib, subprocess, datetime, xml.etree.ElementTree as ET, zipfile
root=pathlib.Path('/workspace/work/candidates/attack-detection-engine')
ev=pathlib.Path('/workspace/work/evidence/attack-detection-engine/final')
out=pathlib.Path('/workspace/work/reviews/attack-detection-engine/closure-8ae9090')
m=json.loads((ev/'manifest.json').read_text())
bad=[]
for name, item in m['artifacts'].items():
    p=ev/name
    if not p.is_file() or p.stat().st_size!=item['bytes'] or hashlib.sha256(p.read_bytes()).hexdigest()!=item['sha256']:
        bad.append(name)
git=lambda *a:subprocess.check_output(['git','-C',str(root),*a],text=True).strip()
wheel=ev/'packages/attack_detection_engine-1.1.0-py3-none-any.whl'
with zipfile.ZipFile(wheel) as z:
    code_names=[n for n in z.namelist() if n.startswith('detection_engine/') and n.endswith('.py')]
    mismatches=[n for n in code_names if z.read(n)!=(root/n).read_bytes()]
    migration_names=[n for n in z.namelist() if '/migrations/' in n]
junit=ET.parse(ev/'junit.xml').getroot()
report={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'commit':git('rev-parse','HEAD'),'branch':git('branch','--show-current'),'status':git('status','--porcelain'),'artifact_count':len(m['artifacts']),'artifact_mismatches':bad,'manifest_sha256':hashlib.sha256((ev/'manifest.json').read_bytes()).hexdigest(),'wheel_python_files':len(code_names),'wheel_source_mismatches':mismatches,'wheel_migration_files':len(migration_names),'junit_suites':[n.attrib for n in junit.iter('testsuite')],'coverage_line_rate':ET.parse(ev/'coverage.xml').getroot().attrib.get('line-rate')}
(out/'baseline.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
assert not bad and not mismatches and report['commit']=='8ae9090b560871d1e584d717734693bb570fffae' and report['status']==''
