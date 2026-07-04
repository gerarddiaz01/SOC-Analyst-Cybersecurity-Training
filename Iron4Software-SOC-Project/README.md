# Capstone Project: Iron4Software SOC Implementation

![Status](https://img.shields.io/badge/Status-Completed-success?style=flat-square)
![Type](https://img.shields.io/badge/Type-Purple_Team_%26_SOC-blue?style=flat-square)
![Focus](https://img.shields.io/badge/Focus-Splunk_SIEM-000000?style=flat-square&logo=splunk)

A purple team project built as part of my SOC Analyst training (RNCP Level 7). This repository documents a complete, simulated SOC lifecycle on a Proxmox home lab, from building a deliberately vulnerable infrastructure through to post-incident crisis management.

> **Note on language:** this project was completed within my French-language SOC Analyst program. The phase writeups and official deliverables linked below are written in French. This README provides the full overview in English.

## Context & Scenario

This project simulates a real engagement for **Iron4Software**, a 25-person small business publishing the *IronSuite* ERP, whose clients operate in sectors including healthcare and aerospace.

Newly hired as a SOC Analyst at Iron4Software, my initial assessment uncovers a flat network where critical servers are dangerously exposed. To secure management's approval to restructure the network, I have to move past theory and provide tangible proof of the risk.

The project follows that narrative across eight phases: proving the risk with a real pentest, hardening the infrastructure, standing up SIEM monitoring, validating the defenses with a second attack, then fully managing a real incident (live response, cold forensic analysis, crisis communication, and after-action review).

## The Eight Phases

| Phase | Objective | Writeup(s) | Official Deliverable(s) |
|---|---|---|---|
| **1. Architecture & Visibility** | Build the vulnerable-by-design infrastructure (AD, client workstation, web server, pfSense) and silently deploy the Splunk SIEM | [Network Architecture](Phase_1/Phase1_01_Architecture_Reseau.md) · [Vulnerability Creation](Phase_1/Phase1_02_Creation_Vulnerabilites.md) · [Splunk SIEM Deployment](Phase_1/Phase1_03_Deploiement_SIEM_Splunk.md) | None |
| **2. Offensive Audit (Pentest)** | Full compromise of the infrastructure to prove exposure to management and generate real malicious logs | [Reconnaissance & Initial Access](Phase_2/Phase2_01_Reconnaissance_et_Acces_Initial.md) · [Pivot & Brute Force](Phase_2/Phase2_02_Pivot_et_Bruteforce.md) · [Exfiltration & Ransomware](Phase_2/Phase2_03_Exfiltration_et_Ransomware.md) · [Evidence & Logs](Phase_2/Phase2_04_Preuves_Logs.md) | None |
| **3. Hardening** | Remediate the discovered flaws: network segmentation, GPO, port closure, firewall rules | [Hardening](Phase_3/Phase3_Hardening.md) | None |
| **4. Detection & Splunk Monitoring** | Detection engineering from the initial attack logs: dashboards, calibrated alert rules | [Splunk](Phase_4/Phase4_Splunk.md) | None |
| **5. Re-attack (Purple Team)** | Replay the Phase 2 attack to validate hardening effectiveness and SIEM alert reliability | [Re-attack](Phase_5/Phase5_Re-attaque.md) | None |
| **6. Incident Response** | Live reaction to a detected incident: containment, eradication, recovery | [Incident Response](Phase_6/Phase6_Reponse_Incident.md) | [Incident Report INC-2026-001](Phase_6/INC-2026-001_Fiche_Incident.pdf) · [IR Playbook](Phase_6/Playbook_IR_Iron4Software.pdf) |
| **7. Forensic Analysis** | Cold reconstruction of the attack timeline, IOC extraction, MITRE ATT&CK mapping | [Forensic Analysis](Phase_7/Phase7_Analyse_Forensique.md) | [Forensic Report INC-2026-001](Phase_7/Rapport_Forensique_INC-2026-001.pdf) |
| **8. Crisis Communication & After-Action Review** | Manage the organizational impact: pre-drafted messages, crisis governance, lessons learned and SOC improvement plan | None | [Crisis Communication Plan](Phase_8/Plan_Communication_Crise_INC-2026-001.pdf) · [After-Action Review](Phase_8/REX_INC-2026-001_Iron4Software.pdf) |

## Lab Architecture (VMs)

Infrastructure virtualized on **Proxmox VE**, segmented network behind a **pfSense** gateway.

| Machine | OS & Role |
|---|---|
| pfSense-Gateway | pfSense (Firewall, NAT, DNS) |
| Kali-Attaquant | Kali Linux (Red Team ops / external attacker) |
| Win10-Client | Windows 10 (administrator workstation) |
| Ubuntu-Web | Ubuntu (Apache/PHP web server) |
| WS2019-AD | Windows Server 2019 (Active Directory) |
| Ubuntu-Splunk | Ubuntu (SIEM, Splunk Enterprise) |

## Repository Structure

```text
Iron4Software-SOC-Project/
├── Extras/              # Screenshots, organized by phase (sub-divided for phases 1 and 2)
├── Phase_1/ … Phase_8/  # Markdown writeups and official PDF deliverables, per phase
└── README.md
```

## Academic Context

Completed as part of my SOC Analyst training (RNCP Level 7 program, with a Université Paris Panthéon-Sorbonne Formation Continue certificate), followed by a final dissertation and an oral defense before a jury. Fully isolated home lab, for educational and defensive purposes only.