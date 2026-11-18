import asyncio, datetime, hashlib, importlib.util, json, pathlib, subprocess, zipfile
from playwright.async_api import async_playwright,expect
HERE=pathlib.Path(__file__).parent
spec=importlib.util.spec_from_file_location('review',HERE/'independent-review.py');r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
checks=[]
def record(name,**kwargs):
    checks.append({'check':name,'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),**kwargs})
    (HERE/'supplementary-results.json').write_text(json.dumps({'checks':checks},indent=2)+'\n')
async def main():
    r.start()
    async with async_playwright() as pw:
        browser=await pw.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox'])
        page=await browser.new_page();await page.goto(r.BASE);await r.sign_in(page)
        # Editing while the only initial list is pending must not discard it.
        arrived=asyncio.Event();release=asyncio.Event()
        async def hold_list(route):
            response=await route.fetch();arrived.set();await release.wait();await route.fulfill(response=response)
        await page.route('**/api/v1/workbench/cases',hold_list)
        await page.reload();await asyncio.wait_for(arrived.wait(),10)
        await page.get_by_label('Investigation title',exact=True).fill('Synthetic typing during initial list')
        await page.get_by_label('FHIR JSON',exact=True).fill('{"synthetic":"draft"}')
        release.set();await expect(page.get_by_label('Saved investigation',exact=True).locator('option')).not_to_have_count(1)
        await page.unroute('**/api/v1/workbench/cases')
        record('initial actual case list remains usable after ordinary title/input edits')
        # A superseded initial error must not replace successful post-import state.
        arrived=asyncio.Event();release=asyncio.Event();seen=0
        async def old_failure(route):
            nonlocal seen
            if route.request.method=='GET':
                seen+=1
                if seen==1:
                    await route.fetch();arrived.set();await release.wait()
                    await route.fulfill(status=503,content_type='application/json',body='{"detail":"Controlled stale list response"}')
                    return
            await route.continue_()
        await page.route('**/api/v1/workbench/cases',old_failure)
        await page.reload();await asyncio.wait_for(arrived.wait(),10)
        sample=json.loads(r.api('GET','/api/v1/workbench/sample',r.login('independent-analyst'))[1])['input_text']
        await page.get_by_role('button',name='Load synthetic sample',exact=True).click()
        await expect(page.get_by_label('FHIR JSON',exact=True)).to_have_value(sample)
        await page.get_by_label('Investigation title',exact=True).fill('Synthetic stale error closure')
        async with page.expect_response(lambda x:x.request.method=='POST' and x.url.endswith('/cases')) as info:
            await page.get_by_role('button',name='Import and investigate',exact=True).click()
        created=await (await info.value).json()
        await expect(page.get_by_label('Saved investigation',exact=True).locator(f'option[value="{created["case_id"]}"]')).to_have_count(1)
        release.set();await page.wait_for_timeout(250)
        assert await page.get_by_role('alert').count()==0
        assert await page.get_by_label('Saved investigation',exact=True).locator(f'option[value="{created["case_id"]}"]').count()==1
        await page.unroute('**/api/v1/workbench/cases')
        record('controlled stale list error cannot overwrite successful fresh list or show obsolete alert',case_id=created['case_id'],note='Synthetic 503 injected as an ordinary failed request; data import/list requests use real API/PostgreSQL.')
        await browser.close()
    r.stop()
    # Independently start the separately installed wheel in its unrelated Git parent.
    parent=pathlib.Path('/workspace/work/attack-wheel-smoke-parent');wheelpy=parent/'venv/bin/python'
    identity=json.loads(subprocess.check_output([str(wheelpy),'-c','import detection_engine,json;from detection_engine.platform.provenance import source_provenance,source_hash; print(json.dumps({"module":detection_engine.__file__,"source":source_provenance(),"source_sha256":source_hash()}))'],cwd=parent,text=True))
    assert identity['source']=={'commit':'UNKNOWN','clean':None} and str(parent/'venv') in identity['module']
    whl=pathlib.Path('/workspace/work/evidence/attack-detection-engine/final/packages/attack_detection_engine-1.1.0-py3-none-any.whl')
    installed=pathlib.Path(identity['module']).parent.parent
    with zipfile.ZipFile(whl) as z:
        modules=[n for n in z.namelist() if n.startswith('detection_engine/') and n.endswith('.py')]
        assert all(z.read(n)==(installed/n).read_bytes() for n in modules)
    record('independent installed wheel identity and 47-module byte equality to freshly hashed release artifact',identity=identity,python_files=len(modules))
    exists=subprocess.check_output(['docker','exec','attack-workbench-pg-20261117','psql','-U','aegis','-d','postgres','-Atc',"select 1 from pg_database where datname='aegis_independent_closure_wheel'"],text=True).strip()
    if not exists:subprocess.run(['docker','exec','attack-workbench-pg-20261117','createdb','-U','aegis','aegis_independent_closure_wheel'],check=True,capture_output=True)
    r.ENV=dict(r.ENV,AEGIS_DATABASE_URL=r.URL.replace('/aegis_independent','/aegis_independent_closure_wheel'))
    r.PY=str(wheelpy);r.start(cwd=parent)
    health=json.loads(r.api('GET','/health')[1]);assert health['source']=={'commit':'UNKNOWN','clean':None}
    token=r.login('independent-analyst');sample=json.loads(r.api('GET','/api/v1/workbench/sample',token)[1])['input_text']
    status,raw,_=r.api('POST','/api/v1/workbench/cases',token,{'title':'Synthetic wheel closure — Ω','input_text':sample})
    first=json.loads(raw);assert status==201 and len(first['events'])==30 and len(first['findings'])==1 and first['source_sha256']==identity['source_sha256']
    prefix='/api/v1/workbench/cases/'+first['case_id']
    status,raw,_=r.api('POST',prefix+'/runs',token,{'config':{'bulk_access_threshold':40},'expected_run_id':first['run_id']})
    second=json.loads(raw);assert status==201 and second['delta']['removed']==1 and not second['findings']
    _,before,headers=r.api('GET',prefix+'/runs/'+second['run_id']+'/export',token)
    checksum=hashlib.sha256(before).hexdigest();assert checksum=={k.lower():v for k,v in headers.items()}.get('x-report-sha256')
    r.stop();r.start(cwd=parent);token=r.login('independent-analyst')
    assert len(json.loads(r.api('GET',prefix,token)[1])['runs'])==2
    _,after,_=r.api('GET',prefix+'/runs/'+second['run_id']+'/export',token);assert before==after
    record('independent installed wheel migrations, canonical workflow/delta, actual restart, persistence and Unicode export byte checksum',case_id=first['case_id'],source=health['source'],report_sha256=checksum)
    r.stop()
    print(json.dumps({'supplementary_checks':len(checks),'failures':0}))
try:asyncio.run(main())
finally:r.stop()
