# Projet Fil Rouge : Iron4Software SOC Implementation

![Status](https://img.shields.io/badge/Status-Phase_2_En_Cours-orange?style=flat-square)
![Type](https://img.shields.io/badge/Type-Blue_Team_%26_Architecture-blue?style=flat-square)
![Focus](https://img.shields.io/badge/Focus-Splunk_SIEM-000000?style=flat-square&logo=splunk)

## Contexte & Scénario
Ce projet académique à long terme simule une mission réelle pour l'entreprise **Iron4Software**, une TPE de 25 salariés éditrice de l'ERP *IronSuite*.
* **Contexte :** Croissance rapide, infrastructure non sécurisée.
* **Mission :** Audit, Durcissement (Hardening), Déploiement SOC (Splunk) et Gestion de Crise.

## Architecture du Lab (État Actuel)
L'infrastructure est virtualisée sur un hyperviseur **Proxmox VE**. Le réseau est segmenté via une passerelle **pfSense**.

| Machine | OS & Rôle | Statut |
| :--- | :--- | :--- |
| **pfSense-Gateway** | **pfSense** (Firewall, NAT, DNS) | ✅ Déployé |
| **Kali-Attaquant** | **Kali Linux** (Red Team Ops / Attaquant externe) | ✅ Déployé |
| **Win10-Client** | **Windows 10** (Poste Administrateur) | ✅ Déployé |
| **Ubuntu-Web** | **Ubuntu** (Serveur Web Apache/PHP) | ✅ Déployé |
| **WS2019-AD** | **Windows Server 2019** (Active Directory) | ✅ Déployé |
| **Ubuntu-Splunk** | **Ubuntu** (SIEM - Splunk Enterprise) | ✅ Déployé |

## Roadmap & Progression (Cycle de vie SOC)

### Phase 1 : Infrastructure & Exposition [Fait]
*Objectif : Construire une infrastructure vulnérable (Bad configuration by design).*
- [x] Installation de l'hyperviseur (Proxmox) et segmentation réseau (pfSense).
- [x] Installation du Contrôleur de Domaine (Windows Server 2019).
- [x] Déploiement du poste client (Windows 10) et du serveur web (Ubuntu).
- [x] Déploiement de la machine attaquante (Kali Linux) sur le sous-réseau public simulé.
- [x] **Mise en place des vulnérabilités volontaires :**
  - Mots de passe faibles/par défaut sur les services.
  - Windows Server 2019 : Pare-feu désactivé et service RDP exposé.
  - pfSense : Règle WAN *Allow All* et NAT (Port Forwarding) du port HTTP (80) vers le réseau interne.
  - Serveur Web Ubuntu : Simulation d'une faille d'upload (MITRE T1190) avec un Webshell (`shell.php`) actif à la racine.
- [x] **Livrables :** Cartographie (Schéma réseau) + Preuve d'exposition (Scan Nmap).

### Phase 2 : Audit & Pentest Initial (Red Teaming) [En Cours]
*Objectif : Identifier et exploiter les failles avant correction.*
- [ ] Scan de vulnérabilités et découverte du réseau (Nmap, Nessus).
- [ ] Exécution d'attaques : Accès initial via Webshell, Mouvement latéral (RDP).
- [ ] **Livrable :** Rapport d'audit initial (Findings & Preuves).

### Phase 3 : Durcissement (Blue Team - Hardening)
*Objectif : Remédier aux failles découvertes.*
- [ ] Mise en place de politiques de mots de passe (GPO) et MFA.
- [ ] Durcissement OS & Fermeture des ports inutiles.
- [ ] Mise en place de règles de pare-feu strictes.
- [ ] **Livrable :** Rapport de configuration Avant/Après.

### Phase 4 : Détection & Supervision (Splunk)
*Objectif : Voir l'invisible.*
- [ ] Installation des Splunk Universal Forwarders (Linux/Windows).
- [ ] Création de Dashboards (Authentification, Flux Réseaux).
- [ ] **Règles de Détection (Alerts) :**
    - [ ] Détection de commandes suspectes sur le serveur Web.
    - [ ] Création de compte admin suspect ou Brute-force.
    - [ ] Scan de ports interne.
- [ ] **Livrable :** Rapport de surveillance (Captures + Règles).

### Phase 5 à 7 : Incident Response & Forensics
- [ ] **Phase 5 (Re-Attaque) :** Vérification de l'efficacité des mesures de détection.
- [ ] **Phase 6 (IR) :** Simulation d'incident (Containment, Eradication, Recovery).
- [ ] **Phase 7 (Forensics) :** Analyse post-mortem, Timeline, IOCs.
- [ ] **Livrables :** Playbook IR + Rapport Forensique.

### Phase 8 : Management & REX
- [ ] Communication de crise (Simulation direction/clients).
- [ ] Rédaction du Mémoire Final.

---

## Organisation des Dossiers

Ce dépôt reflète la structure des livrables attendus par le jury :

* **`/Evidence`** : Preuves techniques (Logs bruts, PCAP, Screenshots d'attaques, Scans Nmap).
* **`/Reports`** : Les rapports PDF officiels (Audit, Hardening, Forensics).
* **`/Configs`** : Fichiers de configuration (Règles Splunk SPL, Config pfSense, Scripts YAML).
* **`/Scripts`** : Outils d'automatisation développés pour le projet.

> ⚠️ **Note :** Projet académique réalisé dans le cadre du Master SOC Analyste Cybersécurité.