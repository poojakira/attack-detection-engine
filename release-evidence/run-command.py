import datetime, json, os, subprocess, sys
from pathlib import Path
root=Path(__file__).parent
name=sys.argv[1]; command=sys.argv[2:]
start=datetime.datetime.now(datetime.timezone.utc).isoformat()
with (root/(name+'.log')).open('w') as output:
    result=subprocess.run(command,stdout=output,stderr=subprocess.STDOUT)
end=datetime.datetime.now(datetime.timezone.utc).isoformat()
record={'name':name,'command':command,'cwd':os.getcwd(),'started_at':start,'finished_at':end,'exit_code':result.returncode,'log':name+'.log'}
(root/(name+'-run.json')).write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps({'name':name,'exit_code':result.returncode,'started_at':start,'finished_at':end}))
sys.exit(result.returncode)
