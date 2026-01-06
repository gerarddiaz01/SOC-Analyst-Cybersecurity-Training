# 🏭 Projet Fil Rouge : Iron4Software SOC Implementation

![Status](https://img.shields.io/badge/Status-Phase_1_En_Cours-orange?style=flat-square)
![Type](https://img.shields.io/badge/Type-Blue_Team_%26_Architecture-blue?style=flat-square)
![Focus](https://img.shields.io/badge/Focus-Splunk_SIEM-000000?style=flat-square&logo=splunk)

## 📖 Contexte & Scénario
Ce projet simule une mission réelle pour l'entreprise **Iron4Software**, une TPE de 25 salariés éditrice de l'ERP *IronSuite*.
* **Contexte :** Croissance rapide, infrastructure non sécurisée.
* **Mission :** Audit, Durcissement (Hardening), Déploiement SOC (Splunk) et Gestion de Crise.

## 🏗️ Architecture du Lab (État Actuel)
L'infrastructure est déployée via VirtualBox. Le réseau est segmenté via **pfSense**.

| Machine | OS & Rôle | Statut |
| :--- | :--- | :--- |
| **Firewall** | **PfSense** (Gateway, VPN, DNS) | ✅ Déployé |
| **Attaquant** | **Kali Linux** (Red Team Ops) | ✅ Déployé |
| **Victime 1** | **Windows 11 Enterprise** (Client) | ✅ Déployé |
| **Victime 2** | **Ubuntu Desktop** (Serveur Web/App) | ✅ Déployé |
| **AD Server** | **Windows Server 2019** (Active Directory) | ✅ Déployé |
| **SIEM** | **Splunk Enterprise** (Log Management) | ⏳ À faire |

## 📅 Roadmap & Progression (Cycle de vie SOC)

### Phase 1 : Infrastructure & Exposition [En Cours]
*Objectif : Construire une infrastructure vulnérable (Bad configuration by design).*
- [x] Installation de l'hyperviseur et segmentation réseau (PfSense).
- [x] Déploiement des postes clients (Windows 11, Ubuntu).
- [x] Déploiement de la machine attaquante (Kali).
- [x] Installation du Contrôleur de Domaine (Windows Server 2019).
- [ ] Exposition volontaire de services (HTTP, SSH, RDP).
- [ ] **Livrable :** Cartographie + Preuve d'exposition.

### Phase 2 : Audit & Pentest Initial (Red Teaming)
*Objectif : Identifier les failles avant correction.*
- [ ] Scan de vulnérabilités (Nmap, Nessus).
- [ ] Exécution d'attaques : Brute-force (Hydra), SQL Injection, XSS.
- [ ] **Livrable :** 📄 Rapport d'audit initial (Findings & Preuves).

### Phase 3 : Durcissement (Blue Team - Hardening)
*Objectif : Remédier aux failles découvertes.*
- [ ] Mise en place de politiques de mots de passe (GPO) et MFA.
- [ ] Durcissement OS & Fermeture des ports inutiles.
- [ ] Sauvegardes chiffrées.
- [ ] **Livrable :** 📄 Rapport de configuration Avant/Après.

### Phase 4 : Détection & Supervision (Splunk)
*Objectif : Voir l'invisible.*
- [ ] Installation des Forwarders (Linux/Windows) vers Splunk.
- [ ] Création de Dashboards (Authentification, Flux Réseaux).
- [ ] **Règles de Détection (Alerts) :**
    - [ ] Détection Brute-force SSH.
    - [ ] Création de compte admin suspect.
    - [ ] Scan de ports interne.
- [ ] **Livrable :** 📄 Rapport de surveillance (Captures + Règles).

### Phase 5 à 7 : Incident Response & Forensics
- [ ] **Phase 5 (Re-Attaque) :** Vérification de l'efficacité des mesures.
- [ ] **Phase 6 (IR) :** Simulation d'incident (Containment, Eradication, Recovery).
- [ ] **Phase 7 (Forensics) :** Analyse post-mortem, Timeline, IOCs.
- [ ] **Livrables :** 📄 Playbook IR + Rapport Forensique.

### Phase 8 : Management & REX
- [ ] Communication de crise (Simulation direction/clients).
- [ ] Rédaction du Mémoire Final (30 pages).

---

## 📂 Organisation des Dossiers

Ce dépôt reflète la structure des livrables attendus par le jury :

* **`/Evidence`** : Preuves techniques (Logs bruts, PCAP, Screenshots d'attaques).
* **`/Reports`** : Les rapports PDF officiels (Audit, Hardening, Forensics).
* **`/Configs`** : Fichiers de configuration (Règles Splunk SPL, Config PfSense, Scripts).
* **`/Scripts`** : Outils d'automatisation Python/Bash développés pour le projet.

> ⚠️ **Note :** Projet académique réalisé dans le cadre du Master Expert Cybersécurité.