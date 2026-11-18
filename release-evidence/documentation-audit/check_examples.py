import ast,json,pathlib,subprocess,datetime,sys
from markdown_it import MarkdownIt
r=pathlib.Path('/workspace/work/candidates/attack-detection-engine');out=pathlib.Path('/workspace/work/doc-reconciliation/attack-detection-engine');parser=MarkdownIt('commonmark');checks=[]
for name in ['README.md','RUNBOOK.md','AUTOMOTIVE_SECURITY.md','HEALTHCARE_SECURITY.md','PLATFORM.md','THREAT_MODEL.md','PRODUCTION.md','PRODUCT_VALIDATION.md','SECURITY.md','CONTRIBUTING.md','docs/WORKBENCH.md','docs/EVIDENCE.md']:
 for i,t in enumerate(parser.parse((r/name).read_text())):
  if t.type!='fence':continue
  language=t.info.split()[0] if t.info else ''
  entry={'document':name,'token':i,'language':language,'check':'not executed'}
  if language in ['sh','bash','shell']:
   p=subprocess.run(['bash','-n'],input=t.content,text=True,capture_output=True);entry.update(check='shell syntax only; not executed',exit=p.returncode,stderr=p.stderr)
  elif language=='json':json.loads(t.content);entry['check']='JSON syntax only; not schema or runtime'
  elif language=='python':
   ast.parse(t.content);entry['check']='Python syntax only'
   if name in ['AUTOMOTIVE_SECURITY.md','HEALTHCARE_SECURITY.md']:
    p=subprocess.run(['/workspace/work/envs/attack/bin/python','-c',t.content],cwd=r,text=True,capture_output=True,timeout=30);entry.update(check='executed actual fenced synthetic/offline example; no DB, download or supplied native execution',exit=p.returncode,stdout=p.stdout,stderr=p.stderr)
  checks.append(entry)
result={'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=r,text=True).strip(),'source_status':subprocess.check_output(['git','status','--porcelain'],cwd=r,text=True),'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'checks':checks,'limits':['Shell/deployment/test/clinical-data commands were syntax-checked only.','No database mutation, live credentials, clinical data, vehicle interaction or supplied native execution.','Regression/browser/build/security suite is separate after candidate freeze.']};(out/'examples-final.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2));sys.exit(any(c.get('exit',0) for c in checks))
