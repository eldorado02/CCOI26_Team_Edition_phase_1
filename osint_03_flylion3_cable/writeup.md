# CTF Write-Up — OSINT #03
## FLY-LION3 Cable — Comores & Mayotte Connectivity

**Catégorie :** OSINT  
**Difficulté :** Intermédiaire  
**Maximum de tentatives :** 10  

---

## 🧠 Contexte

Le câble sous-marin FLY-LION3 est une extension de 400 km du réseau LION (Lower Indian Ocean Network) reliant Grande Comore (Moroni) à Mayotte (Mamoudzou). Son financement implique la Banque Mondiale et plusieurs acteurs régionaux.

---

## ❓ Question 1
**Through which financing mechanism did the World Bank fund 100% of Comores Câbles' share in the FLY-LION3 consortium?**

### Méthodologie
- Recherche : `FLY-LION3 World Bank financing Comores Câbles RCIP consortium`
- Sources consultées : documents1.worldbank.org, ewsdata.rightsindevelopment.org, habarizacomores.com

### Résultat
**✅ Réponse : RCIP4 — World Bank**

### Explication
La Banque Mondiale a financé 100% de la part de **Comores Câbles** dans le consortium FLY-LION3 via le programme **RCIP4** *(Regional Communications Infrastructure Program — Phase 4)*, financé par l'IDA (International Development Association). Ce programme visait à réduire les coûts de la bande passante internationale et à étendre les services haut débit aux Comores.

### Sources
- https://documents1.worldbank.org/curated/en/329901557457701987/pdf/Disclosable-Version-of-the-ISR-RCIP4-Regional-Communications-Infrastructure-Program-APL-4-RI-P118213-Sequence-No-13.pdf
- https://ewsdata.rightsindevelopment.org/projects/WB-P166737/pdf/

---

## ❓ Question 2
**On which Comorian beach did the FLY-LION3 cable officially land on February 10, 2019?**

### Méthodologie
- Recherche : `FLY-LION3 cable landing February 2019 Comoros beach Moroni`
- Sources consultées : newsroom.orange.com, orange.com, habarizacomores.com

### Résultat
**✅ Réponse : Plage d'Itsandra, Moroni (Comoros)**

### Explication
Le câble FLY-LION3 a officiellement atterri à la **plage d'Itsandra** à Moroni, Grande Comore, le **10 février 2019**. La station d'atterrissement à Itsandra héberge également le câble EASSy, ce qui crée une redondance pour la connectivité internationale des Comores.

### Sources
- https://newsroom.orange.com/le-cable-sous-marin-tres-haut-debit-fly-lion3-atterrit-a-mayotte/
- https://www.habarizacomores.com/2019/02/fly-lion3-un-cable-de-400-kilometres.html

---

## ❓ Question 3
**Which Orange Marine cable ship carried out the FLY-LION3 landing at Mayotte in February 2019?**

### Méthodologie
- Recherche : `FLY-LION3 Orange Marine cable ship Mayotte landing 2019`
- Sources consultées : la1ere.franceinfo.fr, orange.com, osiris.sn

### Résultat
**✅ Réponse : Léon Thévenin (Orange Marine)**

### Explication
C'est le navire câblier **Léon Thévenin** d'Orange Marine qui a effectué l'atterrissement du câble FLY-LION3 à Mayotte (à Kaweni, Mamoudzou) en février 2019. Ce même navire avait également été mobilisé pour la réparation du câble EASSy à Madagascar en 2017, confirmant son rôle central dans la région de l'océan Indien.

### Sources
- https://la1ere.franceinfo.fr/mayotte/cable-marin-tres-haut-debit-fly-lion-3-vient-arriver-mayotte-683728.html
- https://www.orange.com/en/press-release/high-speed-broadband-submarine-cable-fly-lion3-makes-landfall-in-mayotte-234599

---

## ❓ Question 4
**What is the official commissioning date of the FLY-LION3 cable, as stated in Orange's official press release?**

### Méthodologie
- Recherche : `FLY-LION3 commissioning date official Orange newsroom 2019`
- Sources consultées : newsroom.orange.com, convergedigest.com

### Résultat
**✅ Réponse : October 10, 2019**

### Explication
Bien que l'atterrissement physique ait eu lieu en février 2019 (Comores le 10 février, Mayotte le 25 février), la **mise en service officielle** (*commissioning*) du câble FLY-LION3, telle qu'annoncée dans le communiqué officiel d'Orange sur newsroom.orange.com, est datée du **10 octobre 2019**. Il y a donc un délai de plusieurs mois entre l'atterrissement et la mise en service commerciale.

### Sources
- https://newsroom.orange.com/high-speed-broadband-submarine-cable-fly-lion3-makes-landfall-in-mayotte/
- https://convergedigest.com/fly-lion3-subsea-cable-to-provide/

---

## 📊 Récapitulatif des Flags

| # | Question | Flag |
|---|----------|------|
| 1 | Mécanisme financement Banque Mondiale | `RCIP4 — World Bank` |
| 2 | Plage d'atterrissage aux Comores | `Plage d'Itsandra, Moroni` |
| 3 | Navire Orange Marine à Mayotte | `Léon Thévenin` |
| 4 | Date de mise en service officielle | `October 10, 2019` |