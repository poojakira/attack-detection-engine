import subprocess
files=subprocess.check_output(['git','ls-files','-z']).decode().split('\0')
result=subprocess.run(['/workspace/work/security-tools/bin/detect-secrets','scan',*[f for f in files if f]],check=False)
raise SystemExit(result.returncode)
