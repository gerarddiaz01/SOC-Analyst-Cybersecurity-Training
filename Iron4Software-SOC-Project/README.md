# Projet Fil Rouge : Iron4Software SOC Implementation

![Status](https://img.shields.io/badge/Status-Projet_Termin%C3%A9-success?style=flat-square)
![Type](https://img.shields.io/badge/Type-Purple_Team_%26_SOC-blue?style=flat-square)
![Focus](https://img.shields.io/badge/Focus-Splunk_SIEM-000000?style=flat-square&logo=splunk)

Projet réalisé dans le cadre de mon Master SOC Analyst (CyberUniversity x Sorbonne). Ce dépôt documente l'intégralité du cycle de vie SOC simulé sur un home lab Proxmox, de la construction d'une infrastructure volontairement vulnérable jusqu'à la gestion de crise post-incident.

## Contexte & Scénario

Ce projet simule une mission réelle pour **Iron4Software**, une TPE de 25 salariés éditrice de l'ERP *IronSuite*, dont les clients évoluent notamment dans les secteurs de la santé et de l'aéronautique.

Fraîchement recruté comme Analyste SOC au sein d'Iron4Software, je découvre lors de mon état des lieux une infrastructure réseau à plat, dont les serveurs critiques sont dangereusement exposés. Pour obtenir l'accord de la direction afin de restructurer le réseau, je dois dépasser la théorie et fournir des preuves tangibles du risque.

Le projet suit ce fil narratif sur 8 phases : preuve du risque par un pentest réel, durcissement de l'infrastructure, mise en place d'une supervision SIEM, validation des défenses par une seconde attaque, puis gestion complète d'un incident réel (réponse à chaud, analyse forensique à froid, communication de crise et retour d'expérience).

## Vue d'ensemble des 8 phases

| Phase | Objectif | Write-up(s) | Livrable(s) officiel(s) | Captures |
|---|---|---|---|---|
| **1. Architecture & Visibilité** | Construction de l'infrastructure vulnérable by design (AD, poste client, serveur web, pfSense) et déploiement silencieux du SIEM Splunk | [Architecture Réseau](Phase_1/Phase1_01_Architecture_Reseau.md) · [Création des Vulnérabilités](Phase_1/Phase1_02_Creation_Vulnerabilites.md) · [Déploiement SIEM Splunk](Phase_1/Phase1_03_Deploiement_SIEM_Splunk.md) | — | [Architecture Réseau](Extras/Phase1/Architecture-Reseau) · [Création Vulnérabilités](Extras/Phase1/Creation-Vuln%C3%A9rabilit%C3%A9s) · [SIEM Splunk](Extras/Phase1/SIEM-Splunk) |
| **2. Audit Offensif (Pentest)** | Compromission complète de l'infrastructure pour prouver l'exposition à la direction et générer des logs malveillants réels | [Reconnaissance & Accès Initial](Phase_2/Phase2_01_Reconnaissance_et_Acces_Initial.md) · [Pivot & Brute-Force](Phase_2/Phase2_02_Pivot_et_Bruteforce.md) · [Exfiltration & Ransomware](Phase_2/Phase2_03_Exfiltration_et_Ransomware.md) · [Preuves & Logs](Phase_2/Phase2_04_Preuves_Logs.md) | — | [Reconnaissance & Accès](Extras/Phase2/Reconnaissance_Active_et_Acc%C3%A8s) · [Pivot & BruteForce](Extras/Phase2/Pivot_et_BruteForce) · [Exfiltration & Ransomware](Extras/Phase2/Exfiltration_et_Ransomware) · [Preuves & Logs](Extras/Phase2/Preuves_Logs) |
| **3. Durcissement (Hardening)** | Remédiation des failles découvertes : segmentation réseau, GPO, fermeture des ports, règles de pare-feu | [Hardening](Phase_3/Phase3_Hardening.md) | — | [Captures Phase 3](Extras/Phase3) |
| **4. Détection & Supervision Splunk** | Ingénierie de détection à partir des logs de l'attaque initiale : dashboards, règles d'alerte calibrées | [Splunk](Phase_4/Phase4_Splunk.md) | — | [Captures Phase 4](Extras/Phase4) |
| **5. Ré-attaque (Purple Team)** | Rejeu de l'attaque de la Phase 2 pour valider l'efficacité du durcissement et la fiabilité des alertes SIEM | [Re-attaque](Phase_5/Phase5_Re-attaque.md) | — | [Captures Phase 5](Extras/Phase5) |
| **6. Réponse à Incident** | Réaction à chaud face à un incident détecté : containment, éradication, récupération | [Réponse à Incident](Phase_6/Phase6_Reponse_Incident.md) | [Fiche Incident INC-2026-001](Phase_6/INC-2026-001_Fiche_Incident.pdf) · [Playbook IR](Phase_6/Playbook_IR_Iron4Software.pdf) | [Captures Phase 6](Extras/Phase6) |
| **7. Analyse Forensique** | Reconstitution à froid de la timeline d'attaque, extraction des IOC, mapping MITRE ATT&CK | [Analyse Forensique](Phase_7/Phase7_Analyse_Forensique.md) | [Rapport Forensique INC-2026-001](Phase_7/Rapport_Forensique_INC-2026-001.pdf) | [Captures Phase 7](Extras/Phase7) |
| **8. Communication de Crise & REX** | Gestion de l'impact organisationnel : messages prérédigés, gouvernance de crise, retour d'expérience et plan d'amélioration SOC | — | [Plan de Communication de Crise](Phase_8/Plan_Communication_Crise_INC-2026-001.pdf) · [REX Iron4Software](Phase_8/REX_INC-2026-001_Iron4Software.pdf) | — |

## Architecture du Lab (VMs)

Infrastructure virtualisée sur hyperviseur **Proxmox VE**, réseau segmenté via une passerelle **pfSense**.

| Machine | OS & Rôle |
|---|---|
| pfSense-Gateway | pfSense (Firewall, NAT, DNS) |
| Kali-Attaquant | Kali Linux (Red Team Ops / attaquant externe) |
| Win10-Client | Windows 10 (poste administrateur) |
| Ubuntu-Web | Ubuntu (serveur web Apache/PHP) |
| WS2019-AD | Windows Server 2019 (Active Directory) |
| Ubuntu-Splunk | Ubuntu (SIEM, Splunk Enterprise) |

## Organisation du dépôt

```
Iron4Software-SOC-Project/
├── Extras/              # Captures d'écran, classées par phase (sous-divisées pour les phases 1 et 2)
├── Phase_1/ … Phase_8/  # Write-ups Markdown et livrables PDF officiels par phase
└── README.md
```

## Cadre académique

Projet réalisé dans le cadre du Master SOC Analyst (CyberUniversity x Sorbonne), suivi d'un mémoire final et d'une soutenance orale devant jury. Environnement entièrement isolé en home lab, à usage pédagogique et défensif uniquement.