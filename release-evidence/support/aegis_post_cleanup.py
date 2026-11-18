from pathlib import Path
import subprocess,json,datetime,xml.etree.ElementTree as ET
root=Path('/workspace/work/candidates/attack-detection-engine');out=Path('/workspace/work/evidence/attack-detection-engine/post-cleanup');out.mkdir(exist_ok=True)
assert json.loads(Path('/workspace/work/branch-governance/aegis-merged-cleanup.json').read_text())['deleted']
subprocess.run(['/workspace/work/tooling/venv/bin/python','/workspace/work/tooling/aegis_literal_current.py'],check=True)
prior=json.loads(Path('/workspace/work/evidence/attack-detection-engine/final/tests-run.json').read_text());cmd=[x.replace('/workspace/work/evidence/attack-detection-engine/final',str(out)).replace('attack-regression-final','attack-regression-post-cleanup') for x in prior['command']]
now=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat();start=now()
with (out/'tests.log').open('w') as f:p=subprocess.run(cmd,cwd=root,stdout=f,stderr=subprocess.STDOUT)
result={'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'source_clean':not subprocess.check_output(['git','status','--porcelain'],cwd=root,text=True).strip(),'utc_start':start,'utc_end':now(),'command':cmd,'exit_code':p.returncode,'scope':'Full relevant regression after six remote merged-branch deletions. Literal launcher/browser/restart repeated immediately before this run; hosted CI separately queued, not passing.'}
if (out/'junit.xml').exists():
    cases=ET.parse(out/'junit.xml').findall('.//testcase');result['tests']={'total':len(cases),'failed':sum(c.find('failure') is not None for c in cases),'errors':sum(c.find('error') is not None for c in cases),'skipped':sum(c.find('skipped') is not None for c in cases)}
(out/'run.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result['tests']),flush=True);assert p.returncode==0
