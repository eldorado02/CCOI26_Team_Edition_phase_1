# CTF Write-Up — OSINT #05
## France Telecom & Mauritius Telecom — Partenariat Stratégique 2000

**Catégorie :** OSINT  
**Difficulté :** Intermédiaire  
**Maximum de tentatives :** 10  

---

## 🧠 Contexte

En novembre 2000, France Telecom est devenu le partenaire stratégique de Mauritius Telecom en acquérant une participation de 40% via un véhicule holding spécifique. Ce partenariat a façonné le paysage télécom de l'océan Indien pendant plus de deux décennies.

---

## ❓ Question 1
**Through which holding subsidiary did France Telecom acquire its 40% stake in Mauritius Telecom in November 2000?**

### Méthodologie
- Recherche : `France Telecom Mauritius Telecom 2000 holding subsidiary acquisition`
- Sources consultées : lexpress.mu, telecom.mu (Corporate Governance), wikiwand.com

### Résultat
**✅ Réponse : Rimcom Ltd**

### Explication
France Telecom a acquis sa participation de 40% dans Mauritius Telecom via sa filiale holding **Rimcom Ltd**. Ce véhicule d'investissement est mentionné dans les documents de gouvernance d'entreprise de Mauritius Telecom et dans les accords d'actionnaires signés en novembre 2000.

### Sources
- https://lexpress.mu/s/article/la-privatisation-de-france-t%C3%A9l%C3%A9com-finalis%C3%A9e
- https://www.telecom.mu/our-company/pdf/CGR.pdf

---

## ❓ Question 2
**What was the amount paid by France Telecom to acquire 40% of Mauritius Telecom, expressed in Mauritian rupees?**

### Méthodologie
- Recherche : `France Telecom Mauritius Telecom 2000 prix acquisition roupies mauriciennes`
- Sources consultées : lexpress.mu, afrik.com

### Résultat
**✅ Réponse : Rs 7.3 billion**

### Explication
Le montant payé par France Telecom pour acquérir 40% de Mauritius Telecom en novembre 2000 s'élevait à environ **7,3 milliards de roupies mauriciennes** (soit ~261 millions USD au taux de change de l'époque). Cette transaction a constitué l'une des plus importantes privatisations partielles de l'histoire des télécoms dans la région de l'océan Indien.

### Sources
- https://lexpress.mu/s/article/la-privatisation-de-france-t%C3%A9l%C3%A9com-finalis%C3%A9e
- https://www.afrik.com/mauritius-telecom-ouvre-son-capital-a-france-telecom

---

## ❓ Question 3
**How many board seats did France Telecom obtain on Mauritius Telecom's board of directors?**

### Méthodologie
- Recherche : `France Telecom Mauritius Telecom board seats directors shareholders agreement`
- Sources consultées : telecom.mu (Corporate Governance PDF), lexpress.mu

### Résultat
**✅ Réponse : 4 seats out of 9**

### Explication
Selon le shareholders' agreement signé en novembre 2000 et les documents de gouvernance officiels de Mauritius Telecom, le conseil d'administration comprend **9 membres** :
- **5 sièges** → Gouvernement de Maurice (lui garantissant la majorité)
- **4 sièges** → France Telecom (via Rimcom Ltd)

Cette structure garantissait au gouvernement mauricien le contrôle stratégique de l'entreprise tout en accordant à France Telecom une influence opérationnelle significative.

### Sources
- https://www.telecom.mu/our-company/pdf/CGR.pdf
- https://lexpress.mu/s/article/mt-letat-et-france-t%C3%A9l%C3%A9com-%C3%A0-parit%C3%A9

---

## ❓ Question 4
**From what date did France Telecom SA officially change its name to become Orange SA?**

### Méthodologie
- Recherche : `France Telecom renamed Orange SA official date`
- Sources consultées : telecoms.com, agenceecofin.com, channelnews.fr, broadbandtvnews.com

### Résultat
**✅ Réponse : July 2013**

### Explication
France Télécom S.A. a officiellement changé son nom en **Orange S.A.** le **1er juillet 2013**. Ce changement a été approuvé lors de l'assemblée générale des actionnaires et visait à unifier l'identité de marque du groupe à l'international. Le nom "Orange" était déjà utilisé comme marque commerciale depuis 2006.

### Sources
- https://www.telecoms.com/communications-service-provider/france-telecom-turns-orange
- https://www.channelnews.fr/france-telecom-devient-orange-le-1er-juillet-2013-15750
- https://www.agenceecofin.com/operateurs/0207-12130-depuis-hier-france-telecom-est-officiellement-devenu-orange

---

## 📊 Récapitulatif des Flags

| # | Question | Flag |
|---|----------|------|
| 1 | Filiale holding d'acquisition | `Rimcom Ltd` |
| 2 | Montant en roupies mauriciennes | `Rs 7.3 billion` |
| 3 | Sièges CA obtenus par France Telecom | `4 seats out of 9` |
| 4 | Date renommage France Telecom → Orange | `July 1, 2013` |