"""Bounded review of synthetic clinical workflow; no credentials/storage logged."""
import asyncio, copy, datetime, hashlib, json, os, pathlib, subprocess, sys, time, urllib.request, urllib.error
from playwright.async_api import async_playwright, expect

ROOT=pathlib.Path('/workspace/work/candidates/attack-detection-engine')
OUT=pathlib.Path('/workspace/work/reviews/attack-detection-engine/closure-8ae9090')
BASE='http://127.0.0.1:18779'
PY='/workspace/work/envs/attack/bin/python'
PASS='SyntheticIndependentEvaluation-42'
URL='postgresql+psycopg://aegis:synthetic-local-db-only@127.0.0.1:55432/aegis_independent'
ENV=dict(os.environ, AEGIS_DATABASE_URL=URL, PYTHONDONTWRITEBYTECODE='1')
checks=[]; defects=[]; server=None; log=None
def record(name, **details):
    checks.append({'check':name, 'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(), **details})
    (OUT/'runtime-progress.json').write_text(json.dumps({'checks':checks,'defects':defects},indent=2,ensure_ascii=False)+'\n')
def api(method,path, token=None, payload=None):
    headers={'Content-Type':'application/json'}
    if token: headers['Authorization']='Bearer '+token
    req=urllib.request.Request(BASE+path,headers=headers,method=method,data=None if payload is None else json.dumps(payload).encode())
    try:
        with urllib.request.urlopen(req,timeout=15) as r: return r.status,r.read(),dict(r.headers)
    except urllib.error.HTTPError as e:return e.code,e.read(),dict(e.headers)
def login(user):
    status,b,_=api('POST','/api/v1/auth/token',payload={'username':user,'password':PASS})
    assert status==200
    return json.loads(b)['access_token']
def start(cwd=ROOT):
    global server,log
    log=open(OUT/'server.log','ab')
    server=subprocess.Popen([PY,'-m','detection_engine.platform.local','--dashboard',str(ROOT/'dashboard-ui/dist'),'--username','independent-analyst','--password-stdin','--port','18779'],cwd=cwd,env=ENV,stdin=subprocess.PIPE,stdout=log,stderr=log)
    server.stdin.write((PASS+'\n').encode());server.stdin.close()
    for _ in range(100):
        try:
            if api('GET','/health')[0]==200:return
        except (OSError,urllib.error.URLError):pass
        if server.poll() is not None:raise RuntimeError('server exited')
        time.sleep(.1)
    raise RuntimeError('startup timeout')
def stop():
    global server,log
    if server and server.poll() is None:server.terminate();server.wait(timeout=15)
    if log:log.close()
async def sign_in(page):
    await page.get_by_label('Username',exact=True).fill('independent-analyst')
    await page.get_by_label('Password',exact=True).fill(PASS)
    await page.get_by_role('button',name='Sign in',exact=True).click()
    await page.get_by_role('heading',name='Security Investigation Workbench',exact=True).wait_for()
async def main():
    start()
    health=json.loads(api('GET','/health')[1]);assert health['source']=={'commit':'8ae9090b560871d1e584d717734693bb570fffae','clean':True}
    assert health['version']=='1.1.0' and api('GET','/readiness')[0]==200
    (OUT/'health.json').write_text(json.dumps(health,indent=2)+'\n')
    record('fresh source runtime, real PostgreSQL readiness, app/core/rule provenance',health=health)
    seed="from detection_engine.platform import db; from detection_engine.platform.bootstrap import seed_user; import os; e=db.make_engine(); s=db.make_session_factory(e)(); "
    seed+="seed_user(s,user_id='review-auditor',username='review-auditor',password=os.environ['REVIEW_SYNTHETIC_PASSWORD'],role='read_only_auditor',organization_id='local-investigations'); "
    seed+="seed_user(s,user_id='review-foreign',username='review-foreign',password=os.environ['REVIEW_SYNTHETIC_PASSWORD'],role='security_analyst',organization_id='independent-foreign'); s.close();e.dispose()"
    subprocess.run([PY,'-c',seed],cwd=ROOT,env=dict(ENV,REVIEW_SYNTHETIC_PASSWORD=PASS),check=True,capture_output=True)
    token=login('independent-analyst');auditor=login('review-auditor');foreign=login('review-foreign')
    sample=json.loads(api('GET','/api/v1/workbench/sample',token)[1])['input_text']
    async with async_playwright() as pw:
        browser=await pw.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox'])
        page=await browser.new_page(viewport={'width':1440,'height':1050});errors=[]
        page.on('pageerror',lambda e:errors.append(str(e)))
        await page.goto(BASE);await sign_in(page)
        await page.get_by_role('button',name='Load synthetic sample',exact=True).click()
        await expect(page.get_by_label('FHIR JSON',exact=True)).to_have_value(sample)
        title='Synthetic review — Café Ω 東京 🩺'
        await page.get_by_label('Investigation title',exact=True).fill(title)
        async with page.expect_response(lambda r:r.request.method=='POST' and r.url.endswith('/api/v1/workbench/cases')) as pending:
            await page.get_by_role('button',name='Import and investigate',exact=True).click()
        response=await pending.value;assert response.status==201;first=await response.json()
        await expect(page.get_by_test_id('finding-count')).to_have_text('1')
        assert len(first['events'])==30 and first['findings'][0]['rule_id']=='HC-ACCESS-BULK' and len(first['incidents'])==1
        assert first['input_sha256']==hashlib.sha256(sample.encode()).hexdigest() and first['data_origin']=='synthetic'
        await page.get_by_text('HC-ACCESS-BULK',exact=True).click()
        await page.locator('ol.timeline summary').first.click()
        await expect(page.get_by_role('heading',name='Source event',exact=True)).to_be_visible()
        await expect(page.get_by_role('heading',name='Normalized representation',exact=True)).to_be_visible()
        assert 'not proof of unauthorized or malicious access' in await page.locator('section[aria-label="Run evidence"]').inner_text()
        await page.locator('section[aria-label="Run evidence"]').scroll_into_view_if_needed()
        await page.screenshot(path=str(OUT/'workflow.png'),full_page=False)
        (OUT/'run-first.json').write_text(json.dumps(first,ensure_ascii=False,indent=2)+'\n')
        record('independent Chromium import/evidence/timeline',case_id=first['case_id'],run_id=first['run_id'],events=30,findings=1,incidents=1)
        await page.get_by_label('Distinct patient read threshold',exact=True).fill('40')
        await expect(page.get_by_role('button',name='Export reproducible report',exact=True)).to_be_disabled()
        async with page.expect_response(lambda r:r.request.method=='POST' and '/runs' in r.url) as pending:
            await page.get_by_role('button',name='Rerun same dataset',exact=True).click()
        second=await (await pending.value).json()
        await expect(page.get_by_test_id('finding-count')).to_have_text('0')
        assert second['input_sha256']==first['input_sha256'] and second['delta']['removed']==1 and not second['findings']
        assert [e['event_id'] for e in first['events']]==[e['event_id'] for e in second['events']]
        async with page.expect_download() as pending:
            await page.get_by_role('button',name='Export reproducible report',exact=True).click()
        await (await pending.value).save_as(OUT/'unicode-report.json')
        b=(OUT/'unicode-report.json').read_bytes();status,raw,headers=api('GET',f"/api/v1/workbench/cases/{first['case_id']}/runs/{second['run_id']}/export",token)
        assert status==200 and raw==b and json.loads(b)['title']==title
        digest=hashlib.sha256(b).hexdigest();assert digest==headers['x-report-sha256'] if 'x-report-sha256' in headers else digest==headers['X-Report-SHA256']
        record('same input threshold rerun, actual delta and UTF-8 byte checksum',run_id=second['run_id'],removed=1,report_sha256=digest,report_bytes=len(b),unicode_title=title)
        cid=first['case_id'];prefix=f'/api/v1/workbench/cases/{cid}'
        # Controlled ordinary delay: backend has committed, UI response remains pending.
        committed=asyncio.Event();release=asyncio.Event();late=[]
        async def hold_rerun(route):
            res=await route.fetch();late.append(await res.json());committed.set();await release.wait()
            try:await route.fulfill(response=res)
            except Exception:pass
        await page.route('**'+prefix+'/runs',hold_rerun)
        await page.get_by_label('Distinct patient read threshold',exact=True).fill('25')
        await page.get_by_role('button',name='Rerun same dataset',exact=True).click()
        await asyncio.wait_for(committed.wait(),10)
        await expect(page.get_by_role('button',name='Import and investigate',exact=True)).to_be_disabled()
        await page.get_by_label('FHIR JSON',exact=True).fill('{"manual":"wins pending rerun"}')
        release.set();await page.wait_for_timeout(250)
        assert await page.get_by_test_id('finding-count').count()==0
        await page.unroute('**'+prefix+'/runs')
        history=json.loads(api('GET',prefix,token)[1]);assert len(history['runs'])==3
        record('pending committed rerun cancelled by edit; obsolete result absent; database reconciliation retains committed run',runs=3)
        # Reload saved state; delay an export until after a run switch.
        await page.reload();await page.get_by_label('Saved investigation',exact=True).select_option(cid)
        await expect(page.get_by_test_id('finding-count')).to_have_text('1')
        download_started=asyncio.Event();download_release=asyncio.Event();downloads=[]
        page.on('download',lambda d:downloads.append(d.suggested_filename))
        async def hold_export(route):
            res=await route.fetch();download_started.set();await download_release.wait()
            try:await route.fulfill(response=res)
            except Exception:pass
        await page.route('**/export',hold_export)
        await page.get_by_role('button',name='Export reproducible report',exact=True).click()
        await asyncio.wait_for(download_started.wait(),10)
        await page.get_by_label('Run history',exact=True).select_option(second['run_id'])
        download_release.set();await page.wait_for_timeout(250)
        assert not downloads
        await page.unroute('**/export')
        record('pending export superseded by run switch produces no stale download')
        await page.reload();await page.get_by_label('Saved investigation',exact=True).select_option(cid)
        await expect(page.get_by_label('Run history',exact=True).locator('option')).to_have_count(3)
        await page.get_by_label('Run history',exact=True).select_option(first['run_id'])
        await page.get_by_label('Distinct patient read threshold',exact=True).fill('35')
        await page.get_by_role('button',name='Rerun same dataset',exact=True).click()
        await expect(page.get_by_role('alert')).to_contain_text('409')
        assert len(json.loads(api('GET',prefix,token)[1])['runs'])==3
        record('stale historical rerun rejected 409 without extra persisted run')
        # Routine initial case-list delay: retain old list, create new case, then release.
        list_started=asyncio.Event();list_release=asyncio.Event();seen=0
        async def hold_initial_list(route):
            nonlocal seen
            seen+=1
            if seen==1:
                res=await route.fetch();list_started.set();await list_release.wait();await route.fulfill(response=res)
            else:await route.continue_()
        await page.route('**/api/v1/workbench/cases',hold_initial_list)
        await page.reload();await asyncio.wait_for(list_started.wait(),10)
        await page.get_by_role('button',name='Load synthetic sample',exact=True).click()
        await expect(page.get_by_label('FHIR JSON',exact=True)).to_have_value(sample)
        await page.get_by_label('Investigation title',exact=True).fill('Synthetic delayed list case')
        async with page.expect_response(lambda r:r.request.method=='POST' and r.url.endswith('/cases')) as pending:
            await page.get_by_role('button',name='Import and investigate',exact=True).click()
        created=await (await pending.value).json()
        await expect(page.get_by_label('Saved investigation',exact=True).locator(f'option[value="{created["case_id"]}"]')).to_have_count(1)
        list_release.set();await page.wait_for_timeout(250)
        visible=await page.get_by_label('Saved investigation',exact=True).locator(f'option[value="{created["case_id"]}"]').count()
        assert visible, "AEGIS-QA-01 regressed"
        record('AEGIS-QA-01 closed: actual delayed initial list preserves newer persisted case',new_case_visible_after_old_list=bool(visible))
        await page.unroute('**/api/v1/workbench/cases')
        await page.reload();await expect(page.get_by_label('Saved investigation',exact=True).locator(f'option[value="{created["case_id"]}"]')).to_have_count(1)
        assert not errors;record('browser page errors',count=len(errors))
        await browser.close()
    # Benign input semantic checks through real API, independent of sample UI.
    payload=json.loads(sample);items=[]
    for entry in payload['entry']:
        item=copy.deepcopy(entry['resource']);item.pop('action',None);item.pop('outcome',None);items.append(item)
    items.extend([{'resourceType':'Patient','id':'synthetic-unsupported'},None,12])
    status,raw,_=api('POST','/api/v1/workbench/cases',token,{'title':'Synthetic missing optionals mixed entries','input_text':json.dumps(items),'config':{'bulk_access_threshold':2,'denial_streak_threshold':3}})
    optional=json.loads(raw);assert status==201 and optional['connector']['normalized']==30 and optional['connector']['rejected']==3 and not optional['findings']
    assert all(e['normalized']['action']=='unknown' and e['normalized']['outcome']=='unknown' for e in optional['events'])
    (OUT/'optional-semantics.json').write_text(json.dumps(optional,indent=2)+'\n')
    record('missing optional action/outcome preserved unknown; unsupported entries counted',normalized=30,rejected=3,findings=0)
    invalid=copy.deepcopy(items[0]);invalid['action']='not-a-supported-action'
    status,_,_=api('POST','/api/v1/workbench/cases',token,{'title':'Synthetic invalid action','input_text':json.dumps(invalid)})
    assert status==422;record('present unsupported action rejected',status=status)
    assert api('GET',prefix)[0]==401
    assert api('GET',prefix,auditor)[0]==200
    assert api('GET',prefix+'/runs/'+second['run_id']+'/export',auditor)[0]==200
    assert api('POST','/api/v1/workbench/cases',auditor,{'input_text':sample})[0]==403
    assert api('POST',prefix+'/runs',auditor,{'config':{'bulk_access_threshold':40,'denial_streak_threshold':3},'expected_run_id':late[0]['run_id']})[0]==403
    assert api('GET',prefix,foreign)[0]==404
    assert api('GET',prefix+'/runs/'+second['run_id']+'/export',foreign)[0]==404
    assert api('POST',prefix+'/runs',foreign,{'config':{'bulk_access_threshold':40,'denial_streak_threshold':3},'expected_run_id':late[0]['run_id']})[0]==404
    assert json.loads(api('GET','/api/v1/workbench/cases',foreign)[1])['items']==[]
    record('controlled accounts: unauthenticated 401, same-org auditor read/export allowed write 403, foreign org list empty and object/export/rerun 404')
    # Evidence immutability and real process restart; tokens remain solely in memory.
    before=json.loads(api('GET',prefix,token)[1]);stop();start()
    assert api('GET',prefix,token)[0]==401
    token=login('independent-analyst');after=json.loads(api('GET',prefix,token)[1]);assert before==after
    status,again,_=api('GET',prefix+'/runs/'+second['run_id']+'/export',token);assert status==200 and again==b
    record('actual API restart, old token invalidated, login and all persisted reports/export bytes unchanged',runs=len(after['runs']),report_sha256=digest)
    async with async_playwright() as pw:
        browser=await pw.chromium.launch(executable_path='/usr/bin/chromium',headless=True,args=['--no-sandbox'])
        page=await browser.new_page();await page.goto(BASE);await sign_in(page)
        await page.get_by_label('Saved investigation',exact=True).select_option(cid)
        await expect(page.get_by_label('Run history',exact=True).locator('option')).to_have_count(3)
        await page.get_by_label('Run history',exact=True).select_option(second['run_id'])
        await expect(page.get_by_test_id('finding-count')).to_have_text('0')
        await browser.close()
    record('fresh Chromium login after restart restores saved case and historical zero-finding report')
    query="select (select count(*) from workbench_cases), (select count(*) from workbench_runs), (select count(*) from security_events), (select count(*) from detection_findings), (select count(*) from incidents);"
    counts=subprocess.check_output(['docker','exec','attack-workbench-pg-20261117','psql','-U','aegis','-d','aegis_independent','-Atc',query],text=True).strip()
    record('direct PostgreSQL persistence counts',columns=['cases','runs','events','findings','incidents'],values=counts)
    (OUT/'runtime-results.json').write_text(json.dumps({'checks':checks,'defects':defects,'decision':'FOCUSED CHECKS VERIFIED; OVERALL PARTIAL','source':'8ae9090b560871d1e584d717734693bb570fffae'},indent=2,ensure_ascii=False)+'\n')
    print(json.dumps({'checks':len(checks),'defects':len(defects),'decision':'FOCUSED CHECKS VERIFIED; OVERALL PARTIAL'}))
if __name__=='__main__':
    try:asyncio.run(main())
    finally:stop()
