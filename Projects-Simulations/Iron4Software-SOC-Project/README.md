# 🏭 Projet Fil Rouge : Iron4Software SOC Implementation


![Status](https://img.shields.io/badge/Status-En_Cours-orange?style=flat-square)
![Type](https://img.shields.io/badge/Type-Blue_Team_%26_Architecture-blue?style=flat-square)
![Focus](https://img.shields.io/badge/Focus-Splunk_SIEM-000000?style=flat-square&logo=splunk)


## 📖 Contexte & Scénario


Ce projet simule une mission réelle pour l'entreprise **Iron4Software**, une TPE de 25 salariés éditrice de l'ERP *IronSuite* (secteurs aéronautique et santé).


**La Mission :** Face à une croissance rapide, l'entreprise doit renforcer sa sécurité. L'objectif est de réaliser un audit complet, de durcir le système d'information (Hardening), de déployer une supervision SOC (Splunk) et de gérer des incidents de sécurité simulés.


## 🏗️ Architecture du Lab


L'infrastructure est déployée via VirtualBox/VMware et comprend les éléments suivants :


* **Périmètre Réseau :** Firewall PfSense, Segmentation (DMZ, LAN).
* **Systèmes :** Windows Server 2019 (AD), Windows 10 (Client), Ubuntu Server (Web/App).
* **Sécurité & Attaque :** Kali Linux (Audit), Splunk Enterprise (SIEM + Forwarders).


## 📅 Roadmap & Progression


Ce projet suit le cycle de vie complet d'une stratégie de défense (8 Phases).


### Phase 1 : Infrastructure & Exposition (Deployment)
- [ ] Déploiement des 5 VMs (PfSense, WS2019, W10, Ubuntu, Kali).
- [ ] Exposition volontaire des services (HTTP, SSH, RDP, DNS, VPN).
- [ ] Installation des collecteurs de logs (Splunk Universal Forwarders).


### Phase 2 : Audit & Pentest Initial (Red Teaming)
- [ ] Scan de vulnérabilités et cartographie (Nmap).
- [ ] Exécution d'attaques : Brute-force (SSH/RDP), SQL Injection, XSS.
- [ ] **Livrable :** Rapport d'audit initial (Findings & Preuves).


### Phase 3 : Durcissement (Blue Team - Hardening)
- [ ] Mise en place de MFA et politiques de mots de passe.
- [ ] Durcissement des OS et fermeture des ports inutiles.
- [ ] Configuration des sauvegardes chiffrées.
- [ ] **Livrable :** Rapport de configuration Avant/Après.


### Phase 4 : Détection & Supervision (Detection Engineering)
- [ ] Configuration de l'ingestion des logs (Linux, Windows, Network).
- [ ] Création de Dashboards Splunk (Auth, Flux réseaux, Admin activity).
- [ ] **Implémentation des Règles d'Alerte :**
    - [ ] Détection Brute-force SSH.
    - [ ] Détection abus de privilèges Admin.
    - [ ] Détection de ports suspects.


### Phase 5 à 7 : Incident Response & Forensics
- [ ] **Phase 5 (Re-Attaque) :** Vérification de l'efficacité des mesures correctives.
- [ ] **Phase 6 (IR) :** Simulation d'incident, Contention, Éradication, Récupération.
- [ ] **Phase 7 (Forensics) :** Analyse post-mortem, Timeline Splunk, Extraction d'IOCs.


### Phase 8 : Management de Crise
- [ ] Communication de crise (Clients, Direction, CNIL).
- [ ] Retour d'Expérience (REX) et plan d'amélioration.


---


## 📂 Organisation des Dossiers


* `/Evidence` : Captures d'écrans des attaques et logs bruts.
* `/Reports` : Les rapports PDF finaux (Audit, Forensics, REX).
* `/Configs` : Fichiers de configuration (exports Splunk, règles Snort/Sigma, config PfSense).
* `/Scripts` : Scripts d'automatisation utilisés durant le lab.


> ⚠️ **Note :** Ce projet est réalisé dans le cadre du Master Expert Cybersécurité (Datascientest).


