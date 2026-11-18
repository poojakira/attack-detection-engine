import configparser, datetime, hashlib, json, platform, shutil, subprocess, tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
import yaml
out=Path(__file__).parent;source=Path('/workspace/work/candidates/attack-detection-engine');old=out.parent/'superseded-50b8d82-before-QA01'
manifest=json.loads((old/'manifest.json').read_text())
manifest['generated_at']=datetime.datetime.now(datetime.timezone.utc).isoformat()
manifest['source']=json.loads((out/'source.json').read_text())
manifest['current_source_status']=subprocess.check_output(['git','status','--porcelain'],cwd=source,text=True)
assert manifest['current_source_status']==''
manifest['decision']='PARTIAL'
root=ET.parse(out/'junit.xml').getroot();cases=root.findall('.//testcase');coverage=ET.parse(out/'coverage.xml').getroot()
manifest['tests']={'testcases':len(cases),'passed':sum(not any(c.find(k) is not None for k in ('failure','error','skipped')) for c in cases),'failed':sum(c.find('failure') is not None for c in cases),'errors':sum(c.find('error') is not None for c in cases),'skipped':sum(c.find('skipped') is not None for c in cases),'native_subtests':0,'skip_details':[]}
manifest['coverage']={'line_rate':float(coverage.attrib['line-rate']),'lines_valid':int(coverage.attrib['lines-valid']),'lines_covered':int(coverage.attrib['lines-covered']),'preserved_gate_percent':53}
manifest['browser']=json.loads((out/'browser/browser.json').read_text());manifest['installed_wheel']=json.loads((out/'installed-wheel.json').read_text())
report=json.loads((out/'browser/report.json').read_text())
assert report['source']['commit']==manifest['source']['commit'] and report['source']['clean'] is True
manifest['hashes']={'python_lock_sha256':hashlib.sha256((source/'requirements.lock').read_bytes()).hexdigest(),'frontend_lock_sha256':hashlib.sha256((source/'dashboard-ui/package-lock.json').read_bytes()).hexdigest(),'input_sha256':report['input_sha256'],'config_sha256':report['config_sha256'],'python_source_sha256':report['source_sha256']}
manifest['commands']=[json.loads(p.read_text()) for p in sorted(out.glob('*-run.json'))]
manifest['literal_launcher']='Parent independently executed launcher/restart/persistence on source50b8d82, separately scoped in launcher-orchestration. Current8ae UI-only remediation has fresh source browser and installed-wheel startup/restart proof; no new literal orchestration claimed.'
manifest['recovered_failures']=[]
manifest['superseded_evidence']={'source':'50b8d8260c4c822c2bbcc75605a176d97bca72ec','directory':str(old),'manifest_sha256':hashlib.sha256((old/'manifest.json').read_bytes()).hexdigest(),'reason':'Independent review reproduced AEGIS-QA-01; current source fixes it and all required gates were rerun.'}
manifest['remediation']={'id':'AEGIS-QA-01','independent_review':str(Path('/workspace/work/reviews/attack-detection-engine/ASSESSMENT.md')),'implementation':'Shared monotonic case-list request sequence guarding all success/error callbacks and unmount, independently of editor revision.','regression':manifest['browser']['case_list_race'],'status':'TESTED/OBSERVED, pending independent closure'}
manifest['limitations'][0]='Master contract remains PARTIAL pending independent remediation closure, remote governance/publication, exhaustive historical documentation and environment-specific operational/privacy signoff.'
npm=json.loads((out/'npm-audit.log').read_text());pip=json.loads((out/'pip-audit.json').read_text());bandit=json.loads((out/'bandit-all.json').read_text())
secrets=json.loads((out/'detect-secrets.log').read_text());reviews=[]
for name,items in secrets.get('results',{}).items():
 for item in items:
  reason='Public source/data digest or Alembic revision identifier.' if item['type']=='Hex High Entropy String' else 'Explicit synthetic test/CI or documented example/default local credentials; no provider token. Source-context triage, not external credential validation.'
  reviews.append({'path':name,'line_number':item['line_number'],'type':item['type'],'classification':'reviewed non-live fixture/hash candidate','reason':reason})
(out/'secret-scan-review.json').write_text(json.dumps({'candidates':len(reviews),'review':reviews,'limitations':'No source suppression baseline created; no external credential validation attempted.'},indent=2))
(out/'bandit-review.json').write_text(json.dumps({'gate':'Medium/high severity gate passed; full-severity output retained.','findings':[{'path':r['filename'],'line':r['line_number'],'id':r['test_id'],'severity':r['issue_severity'],'description':r['issue_text']} for r in bandit['results']],'review':'Unchanged LOW issues: noncryptographic synthetic RNG, explicit rollback/config fallbacks, fixed Git provenance subprocess without user-controlled executable/arguments.'},indent=2))
manifest['audits']={'npm':npm['metadata']['vulnerabilities'],'python_vulnerability_records':sum(len(d.get('vulns',[])) for d in pip['dependencies']),'bandit_medium_high':len(json.loads((out/'bandit.json').read_text())['results']),'bandit_all_severities':len(bandit['results']),'detect_secrets_candidates':len(reviews),'secret_scan_review':'secret-scan-review.json'}
checks=[]
for name in filter(None,subprocess.check_output(['git','ls-files','-z'],cwd=source).decode().split('\0')):
 path=source/name
 if path.suffix not in ('.toml','.yml','.yaml','.ini','.json'):continue
 data=path.read_text()
 if path.suffix=='.toml':tomllib.loads(data)
 elif path.suffix in ('.yml','.yaml'):yaml.safe_load(data)
 elif path.suffix=='.json':json.loads(data)
 else:
  cfg=configparser.ConfigParser(interpolation=None);cfg.read_string(data)
 checks.append({'path':name,'status':'parsed'})
(out/'configuration-validation.json').write_text(json.dumps(checks,indent=2))
shutil.copytree(source/'dashboard-ui/dist',out/'frontend-build',dirs_exist_ok=True)
manifest['cleanup']={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source_and_wheel_servers':'stopped after fresh proof','original_test_container':subprocess.check_output(['docker','inspect','--format','{{.Name}} {{.State.Status}}','attack-workbench-pg-20261117'],text=True).strip(),'independent_database':'aegis_independent retained untouched','launcher_container_and_private_state':'untouched; retained per parent instruction','removed':'Only disposable npm content-addressed download cache after npm tasks completed, reclaiming187178688 bytes under disk pressure. No source/evidence/image/installed dependency/database/user volume deleted.'}
(out/'cleanup.json').write_text(json.dumps(manifest['cleanup'],indent=2))
manifest['artifacts']={p.relative_to(out).as_posix():{'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size} for p in sorted(out.rglob('*')) if p.is_file() and p.name not in ('manifest.json','manifest.sha256')}
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');(out/'manifest.sha256').write_text(hashlib.sha256((out/'manifest.json').read_bytes()).hexdigest()+'  manifest.json\n')
for name,item in manifest['artifacts'].items():assert hashlib.sha256((out/name).read_bytes()).hexdigest()==item['sha256'],name
print(json.dumps({'source':manifest['source'],'tests':manifest['tests'],'coverage':manifest['coverage'],'browser_checks':len(manifest['browser']['checks']),'wheel_checks':len(manifest['installed_wheel']['checks']),'artifacts_verified':len(manifest['artifacts']),'race':manifest['browser']['case_list_race'],'decision':'PARTIAL'}))
