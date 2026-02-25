# Chunks

**Catégorie :** Cryptographie  
**Fichiers :** `enc_chunks.py`, `challenge.bin`  
**Flag :** `CCOI26{ChUnK5_0f_K3y5_4nd_0ff53t5}`

---

## TL;DR

Chiffrement XOR avec clés faibles (1-80) sur 4 chunks. Récupération des clés via texte clair connu ( `CCOI26{`), contrainte de fin (`}`), et brute-force avec scoring alphabétique pour les chunks du milieu.

---

## Analyse

On a deux fichiers : le script de chiffrement `enc_chunks.py` et le résultat chiffré `challenge.bin` (34 octets).

En lisant le code, je comprends que le flag est découpé en 4 morceaux de taille quasi-égale ([9, 9, 8, 8] vu la taille totale). Chaque morceau est chiffré indépendamment avec sa propre clé aléatoire tirée entre 1 et 80.

Le chiffrement applique : `((octet + position_locale) & 0xFF) ^ clé`

Déjà, 80 valeurs possibles par clé, c'est ridicule. Maximum 80⁴ ≈ 40 millions de combinaisons, mais dans la pratique on peut faire bien mieux avec des contraintes connues.

---

## Stratégie d'attaque

### 1. Premier chunk (début du flag)

Tous les flags CTF commencent par `CCOI26{`. À position 0, pas d'offset, donc :
- `enc[0] = ord('C') ^ k0`
- Donc `k0 = enc[0] ^ ord('C')`

Calcul direct, clé trouvée : **k0 = 67**

Déchiffrement → `"CCOI26{Ch"` ✓

### 2. Dernier chunk (fin du flag)

Le flag se termine par `}`. Je teste les 80 clés possibles et je garde celle qui donne `}` en dernière position.

Résultat : **k3 = 34** → `"0ff53t5}"`

### 3. Chunks du milieu (brute-force intelligent)

Pour les deux chunks restants, je teste toutes les combinaisons (80 × 80 = 6400), mais avec un filtre rapide : je skip immédiatement si le chunk déchiffré contient des caractères bizarres (hors de `[a-zA-Z0-9_{}]`).

Ensuite je score chaque reconstruction complète en comptant les caractères valides. Une seule paire atteint le score maximum 34/34 :

- **k1 = 18** → `"UnK5_0f_"`
- **k2 = 77** → `"K3y5_4nd_"`

---

## Résultat

| Chunk | Clé | Contenu | Méthode |
|-------|-----|---------|---------|
| 0 | 67 | `CCOI26{Ch` | Texte clair connu |
| 1 | 18 | `UnK5_0f_` | Brute-force + scoring |
| 2 | 77 | `K3y5_4nd_` | Brute-force + scoring |
| 3 | 34 | `0ff53t5}` | Contrainte finale |

Flag complet : **`CCOI26{ChUnK5_0f_K3y5_4nd_0ff53t5}`**

Le script complet est dans `solve_chunks_v2.py`.
