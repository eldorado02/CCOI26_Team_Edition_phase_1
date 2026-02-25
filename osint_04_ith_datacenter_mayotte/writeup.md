# CTF Write-Up — OSINT #04
## ITH SAS — Premier Datacenter de Mayotte

**Catégorie :** OSINT  
**Difficulté :** Intermédiaire  
**Maximum de tentatives :** 10  

---

## 🧠 Contexte

Information Technology Hosting (ITH), opérateur du premier datacenter de proximité de Mayotte, a bénéficié d'un financement multi-partenarial pour sa construction. La Banque des Territoires, l'AFD et le Crédit Agricole Mutuel de La Réunion (CAMR) ont joué un rôle clé.

---

## ❓ Question 1
**What is the current legal form of Information Technology Hosting (ITH)?**

### Méthodologie
- Recherche : `Information Technology Hosting ITH Mayotte forme juridique SIREN`
- Sources consultées : pappers.fr, infonet.fr, annonces-legales.fr

### Résultat
**✅ Réponse : SAS**

### Explication
ITH a été initialement créée comme **SARL** (Société à Responsabilité Limitée). En 2017, lors d'une assemblée générale extraordinaire, la société a été transformée en **SAS** (Société par Actions Simplifiée). Sa forme juridique actuelle est donc **SAS** (ITH SAS), SIREN : 539 973 370, siège : ZI Kaweni, 97600 Mamoudzou, Mayotte.

### Sources
- https://www.pappers.fr/entreprise/ith-information-technology-hosting-539973370
- https://www.annonces-legales.fr/consultation/outre-mer/mayotte-976/INFORMATION-HOSTING-TECHNOLOGY-0271936

---

## ❓ Question 2
**On what date did the Banque des Territoires become a shareholder of ITH SAS?**

### Méthodologie
- Recherche : `Banque des Territoires ITH SAS Mayotte datacenter date prise de participation actionnaire`
- Sources consultées : ith.yt, dcmag.fr, lejournaldesarchipels.com

### Résultat
**✅ Réponse : October 19, 2020**

### Explication
La **Banque des Territoires** (Caisse des Dépôts et Consignations) est devenue actionnaire d'ITH SAS le **19 octobre 2020**, date de la prise de participation en fonds propres. Elle détient environ 44% du capital d'ITH SAS. Le 6 novembre 2020 correspond à la signature officielle des contrats de financement (date différente de l'entrée au capital).

### Sources
- https://www.ith.yt/2020/11/18/financement-du-1er-datacenter-de-mayotte/
- https://dcmag.fr/la-banque-des-territoires-et-ith-sas-inaugurent-le-premier-datacenter-de-proximite-a-mayotte/

---

## ❓ Question 3
**What is the exact amount of the Banque des Territoires' equity investment in ITH SAS?**

### Méthodologie
- Recherche : `Banque des Territoires ITH Mayotte datacenter montant investissement fonds propres`
- Sources consultées : ith.yt, lejournaldesarchipels.com, dcmag.fr

### Résultat
**✅ Réponse : €1.3M**

### Explication
La **Banque des Territoires** a investi **1,3 million d'euros** (1,35M€ précisément) en fonds propres dans ITH SAS. Cet investissement en equity lui permet de détenir environ 44% du capital de la société, faisant d'elle l'actionnaire minoritaire principal aux côtés du fondateur Feyçoil Mouhoussoune.

### Sources
- https://www.ith.yt/2020/11/18/financement-du-1er-datacenter-de-mayotte/
- https://www.lejournaldesarchipels.com/2020/12/10/10-me-pour-le-premier-data-center/

---

## ❓ Question 4
**What is the total external financing (AFD + CAMR) granted to ITH for the datacenter construction?**

### Méthodologie
- Recherche : `ITH datacenter Mayotte AFD CAMR financement prêt FEDER montant total`
- Sources consultées : ith.yt, afd.fr, mayottehebdo.com

### Résultat
**✅ Réponse : €7.5M**

### Explication
Le financement externe total accordé à ITH SAS par l'**AFD** (Agence Française de Développement) et le **CAMR** (Crédit Agricole Mutuel de La Réunion et de Mayotte), sous forme de prêts long-terme et de crédit-relais FEDER, s'élève à **7,5 millions d'euros**. La structure complète du financement (~10M€ total) est :
- AFD + CAMR (prêts long-terme + crédit-relais FEDER) : **7,5M€**
- Banque des Territoires (fonds propres) : **1,3M€**
- FEDER (subvention) : **1,7M€**
- Conseil Départemental de Mayotte : **0,5M€**

### Sources
- https://www.ith.yt/2020/11/18/financement-du-1er-datacenter-de-mayotte/
- https://www.afd.fr/fr/projets/construction-du-premier-data-center-de-mayotte
- https://www.lejournaldesarchipels.com/2020/12/10/10-me-pour-le-premier-data-center/

---

## 📊 Récapitulatif des Flags

| # | Question | Flag |
|---|----------|------|
| 1 | Forme juridique d'ITH | `SAS` |
| 2 | Date entrée Banque des Territoires | `October 19, 2020` |
| 3 | Montant investissement en fonds propres | `€1.3M` |
| 4 | Financement externe total AFD + CAMR | `€7.5M` |