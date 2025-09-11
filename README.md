# 🛡️ IOC Sentinel – Extension Navigateur pour Analystes CTI & SOC

[![Chrome](https://img.shields.io/badge/Chrome-Extension-blue?logo=googlechrome)](https://chrome.google.com/webstore) 
[![Edge](https://img.shields.io/badge/Edge-Extension-green?logo=microsoftedge)](https://microsoftedge.microsoft.com/addons) 
[![License](https://img.shields.io/badge/license-Custom-orange.svg)](#licence)

**IOC Sentinel** est une extension navigateur légère qui aide les analystes CTI et SOC à extraire, nettoyer et investiguer des Indicateurs de Compromission (IOCs) directement depuis les pages web.  
Fini le copier-coller manuel — obtenez des IOCs propres, prêts à être exportés ou utilisés dans votre SIEM/EDR.

---

## ✨ Fonctionnalités

✅ **Extraction multi-types d’IOC**  
- IPv4, domaines, URLs (`http/https`, `ftp`, `tcp/udp`)  
- Adresses email  
- Artefacts de fichiers (`.exe`, `.dll`, `.bat`, etc.)  
- Hashes : **MD5, SHA1, SHA256** (détection automatique)  

✅ **Dé-obfuscation intelligente**  
- Conversion automatique de `hxxp`, `[.]`, `(.)`, `[@]`, et formats similaires.  

✅ **Gestion & actions IOC**  
- Copier, exporter **CSV/JSON**  
- Ouvrir directement dans **VirusTotal**  
- Générer des requêtes **KQL prêtes à l’emploi** pour Microsoft Defender / Sentinel  

✅ **Gestionnaire de liste blanche**  
- Exclure les IOCs connus légitimes (IPs, domaines, URLs, hashes, emails, fichiers)  
- Supporte les **plages CIDR** et **wildcards** (`*.example.com`)  

✅ **Interface moderne**  
- Toggle mode sombre/clair 🌙☀️  
- Onglets par catégorie avec compteur  
- Actions rapides par IOC et globales  

---

## 🎯 Pourquoi IOC Sentinel ?

- Économise **des heures de copier-coller** en analyse CTI  
- Standardise la collecte IOC au sein du SOC  
- Passez de **blog → IOC hunt** en quelques clics  
- Léger, **aucune dépendance externe**, tout reste dans le navigateur  

---

## 🚀 Installation

### Manuelle
1. Clonez ce dépôt :  
   ```bash
   git clone https://github.com/YOUR_GITHUB_USERNAME/ioc-sentinel.git
   ```
2. Ouvrez **chrome://extensions/** (Chrome) ou **edge://extensions/** (Edge).  
3. Activez le **Mode développeur**.  
4. Cliquez sur **Charger l’extension non empaquetée** et sélectionnez le dossier du projet.  
5. L’icône 🛡️ IOC Sentinel apparaîtra dans votre barre de navigateur.

---

## 📌 Exemple de flux analyste

1. Ouvrir un rapport CTI ou un pastebin contenant des IOCs obfusqués.  
2. IOC Sentinel les **détecte, refang et classe automatiquement**.  
3. Copier/exporter les IOCs ou générer une **requête KQL hunting** en un clic.  
4. Vérifier dans **VirusTotal** ou enrichir via **WHOIS**.  
5. Ajouter les entrées légitimes (Google, Microsoft, etc.) à la **liste blanche**.

---

---

## 📸 Captures d’écran

<img width="753" height="597" alt="image" src="https://github.com/user-attachments/assets/53e18be1-b119-439b-8d83-97c7659f70d3" />


<img width="3284" height="1354" alt="image" src="https://github.com/user-attachments/assets/5d4ee5fb-2e40-4c65-9f7a-934c39ece991" />


<img width="3399" height="448" alt="image" src="https://github.com/user-attachments/assets/d3245e9d-0cfe-4bb6-9000-14f81b1fdc74" />



---

## 📜 Licence

Licence interne / usage SOC.  
À adapter selon les besoins de votre organisation.  

---

## 🤝 Contribuer

Les pull requests et suggestions de fonctionnalités sont bienvenues !  
N’hésitez pas à ouvrir une issue si vous trouvez un bug ou avez une idée 💡.




