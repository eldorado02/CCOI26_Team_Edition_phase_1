# CTF Write-Up — OSINT #02
## Panne EASSy 2017 — Indian Ocean Internet Outage

**Catégorie :** OSINT  
**Difficulté :** Intermédiaire  
**Maximum de tentatives :** 10  

---

## 🧠 Contexte

Le 25 janvier 2017, l'océan Indien a connu l'une des plus grandes pannes Internet de son histoire. Les détails techniques et opérationnels ont été couverts par des médias spécialisés et des sources de première main, notamment le PDG de Telma.

---

## ❓ Question 1
**Which CEO gave precise technical statements during the EASSy cable repair off Tuléar in February 2017?**

### Méthodologie
- Recherche : `EASSy cable repair 2017 Madagascar CEO Telma Tuléar`
- Sources consultées : rfi.fr, habarizacomores.com, furtherafrica.com

### Résultat
**✅ Réponse : Patrick Pisal Hameda**

### Explication
**Patrick Pisal Hameda**, PDG de **Telma** (principal opérateur internet de Madagascar), est le seul CEO ayant fourni des déclarations techniques précises sur la longueur du câble endommagé et le calendrier des opérations de réparation. Telma était l'opérateur le plus impacté par la coupure, touchant plus de 3 millions d'utilisateurs.

### Sources
- https://www.rfi.fr/fr/afrique/20170207-madagascar-debut-reparations-cable-sous-marin-fournisseur-internet
- https://www.habarizacomores.com/2017/02/madagascar-debut-des-reparations-du.html

---

## ❓ Question 2
**What length of EASSy cable was damaged according to initial sea-side analysis?**

### Méthodologie
- Recherche : `EASSy 2017 Madagascar longueur câble endommagé kilomètres Telma`
- Sources consultées : habarizacomores.com, madamaxi.com, rfi.fr

### Résultat
**✅ Réponse : 8 km damaged**

### Explication
Selon les déclarations de **Patrick Pisal Hameda** lors des opérations de réparation, l'analyse initiale a révélé que **8 kilomètres** de câble sous-marin avaient été endommagés, à une profondeur de 2 600 mètres et à environ 38 km au large de Tuléar (Toliara), sur la côte sud-ouest de Madagascar.

### Sources
- https://www.habarizacomores.com/2017/02/madagascar-debut-des-reparations-du.html
- https://www.madamaxi.com/madagascar-panne-internet-a-madagascar-debut-des-reparations-du-cable-sous-marin-actualites-1546.html

---

## ❓ Question 3
**From which port did the Léon Thévenin cable ship depart to reach the EASSy cable repair site off Tuléar?**

### Méthodologie
- Recherche : `Leon Thévenin cable ship EASSy repair 2017 port departure Madagascar`
- Sources consultées : consultingjulian.com, wikipedia (Léon Thévenin ship), marine.orange.com

### Résultat
**✅ Réponse : Cape Town, South Africa**

### Explication
Le navire câblier **Léon Thévenin** d'Orange Marine est parti de **Cape Town (Afrique du Sud)** pour rejoindre le site de réparation au large de Tuléar. Cape Town est le hub logistique principal d'Orange Marine pour les réparations de câbles dans l'océan Indien et le long de la côte est africaine.

### Sources
- https://www.consultingjulian.com/commentary/madagascar-eassy-undersea-cable-break-impacts-connectivity
- https://en.wikipedia.org/wiki/L%C3%A9on_Th%C3%A9venin_(ship)

---

## ❓ Question 4
**What backup solution did Telma subscribers use during the first 13 days of the 2017 EASSy outage?**

### Méthodologie
- Recherche : `Telma Madagascar EASSy 2017 backup solution LION satellite coupure`
- Sources consultées : rfi.fr, services.yas.mg (communiqué officiel), lexpress.mg

### Résultat
**✅ Réponse : Switch to LION cable (Orange network) and satellite exits**

### Explication
Pendant les 13 premiers jours de coupure (avant l'arrivée du Léon Thévenin), Telma a mis en place deux solutions de secours :
1. **Bascule partielle vers le câble LION** (réseau Orange) avec une bande passante limitée
2. **Sorties satellitaires** pour les clients prioritaires (entreprises, hôpitaux, institutions)

Le câble METISS n'existait pas encore en 2017. Une priorisation des usages a été instaurée (journée : entreprises/institutions ; soir/week-end : grand public).

### Sources
- https://www.rfi.fr/fr/afrique/20170209-connexion-internet-commence-revenir-madagascar
- https://services.yas.mg/data/press/pdf/30-janv_cp_coupure_eassy-a4-01.pdf
- https://lexpress.mg/28/01/2017/cable-eassy-des-interventions-en-haute-mer/

---

## 📊 Récapitulatif des Flags

| # | Question | Flag |
|---|----------|------|
| 1 | CEO avec déclarations techniques | `Patrick Pisal Hameda` |
| 2 | Longueur câble endommagé | `8 km damaged` |
| 3 | Port de départ du Léon Thévenin | `Cape Town, South Africa` |
| 4 | Solution backup pendant la coupure | `Switch to LION cable and satellite exits` |