# CTF Write-Up — OSINT #01
## Omega Data Centers — Premier Tier III Datacenter de La Réunion

**Catégorie :** OSINT  
**Difficulté :** Intermédiaire  
**Maximum de tentatives :** 10  

---

## 🧠 Contexte

Le premier datacenter Tier III de La Réunion a été inauguré en novembre 2024. Sa structure actionnariale et technique implique plusieurs acteurs de l'écosystème numérique réunionnais.

---

## ❓ Question 1
**Which Reunionese company holds a 25% stake in Omega Data Centers, alongside the Océinde group?**

### Méthodologie
- Recherche Google/Bing : `Omega Data Centers Réunion actionnaires Océinde 2024`
- Sources consultées : ecoaustral.com, imazpress.com, dcmag.fr

### Résultat
**✅ Réponse : Exodata**

### Explication
Omega Data Centers est une filiale de **THD Group**, la holding télécoms du groupe Océinde. La société réunionnaise **Exodata**, spécialisée dans les services cloud et cybersécurité, détient **25% du capital** d'Omega Data Centers. Le projet a également bénéficié d'un cofinancement par l'AFD et le Crédit Agricole.

### Sources
- https://ecoaustral.com/oceinde-inaugure-le-13-novembre-le-premier-data-center-de-niveau-tier-3/
- https://dcmag.fr/lile-de-la-reunion-a-inaugure-son-premier-datacenter-omega-1/

---

## ❓ Question 2
**On what date was ODC Omega Data Centers registered at the RCS of Saint-Denis de La Réunion?**

### Méthodologie
- Recherche sur les registres officiels : `ODC Omega Data Centers RCS Saint-Denis SIREN`
- Sources consultées : pappers.fr, annuaire-entreprises.data.gouv.fr, data.inpi.fr

### Résultat
**✅ Réponse : 04/05/2023**

### Explication
La société ODC Omega Data Centers (SIREN : 951 710 714) a été créée le **21 avril 2023** et immatriculée au RCS de Saint-Denis de La Réunion en **2023**. Parmi les choix proposés, la date **04/05/2023** correspond à l'immatriculation officielle.

### Sources
- https://www.pappers.fr/entreprise/odc-omega-data-centers-951710714
- https://annuaire-entreprises.data.gouv.fr/entreprise/omega-data-centers-odc-951710714
- https://data.inpi.fr/entreprises/951710714

---

## ❓ Question 3
**Who was the godmother of the Omega 1 inauguration on November 13, 2024?**

### Méthodologie
- Recherche : `Omega 1 datacenter Réunion inauguration marraine 13 novembre 2024`
- Sources consultées : outremers360.com, imazpress.com, la1ere.franceinfo.fr

### Résultat
**✅ Réponse : Eileen Collins**

### Explication
**Eileen Collins**, astronaute américaine et première femme commandante d'une navette spatiale, était la **marraine** de l'inauguration d'Omega 1 le 13 novembre 2024. Nassir Goulamaly est le PDG du groupe Océinde (présent à l'inauguration), et Abdéali Goulamaly en est le président.

### Sources
- https://outremers360.com/bassin-indien-appli/la-reunion-inauguration-de-omega-1-premier-data-center-du-territoire
- https://imazpress.com/actus-reunion/le-port-omega-1-le-premier-data-center-de-la-reunion-est-ne

---

## ❓ Question 4
**What is the target PUE (Power Usage Effectiveness) of Omega 1?**

### Méthodologie
- Recherche : `Omega 1 datacenter Réunion PUE Power Usage Effectiveness cible`
- Sources consultées : dcmag.fr, imazpress.com, ecoaustral.com

### Résultat
**✅ Réponse : 1.38**

### Explication
Le PUE (Power Usage Effectiveness) cible annoncé dans la documentation technique d'Omega 1 est de **1,38**. Cet objectif est atteint grâce à une toiture photovoltaïque (5-6% de la consommation), une optimisation thermique et une enveloppe végétalisée. La moyenne mondiale des datacenters est ~1,6, ce qui positionne Omega 1 au-dessus des standards.

### Sources
- https://dcmag.fr/lile-de-la-reunion-a-inaugure-son-premier-datacenter-omega-1/
- https://ecoaustral.com/le-data-center-omega1-heberge-ses-premiers-clients/

---

## 📊 Récapitulatif des Flags

| # | Question | Flag |
|---|----------|------|
| 1 | Actionnaire 25% | `Exodata` |
| 2 | Date RCS | `04/05/2023` |
| 3 | Marraine inauguration | `Eileen Collins` |
| 4 | PUE cible | `1.38` |