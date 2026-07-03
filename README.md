# SOC Analyst & Cybersecurity Portfolio

![Focus](https://img.shields.io/badge/Focus-Blue_Team_%26_Detection-0052cc?style=flat-square)
![TryHackMe](https://img.shields.io/badge/TryHackMe-Top_2%25-212121?style=flat-square&logo=tryhackme&logoColor=white)
![Availability](https://img.shields.io/badge/Available-Sept_2026-2ea44f?style=flat-square)

This repository documents my hands-on progression toward a SOC Analyst role. It centralizes my investigation writeups, home lab builds, and a full purple team project, all approached from a blue team, defensive standpoint. The focus throughout is on the actual mechanics of detection and investigation: how to read the logs, how to spot the anomaly, how to follow the evidence chain, not just the theory behind it.

I am currently completing a SOC Analyst master's program while practicing continuously on TryHackMe, where I rank in the top 2% globally.

**What this repository sets out to prove:**

- That I can carry an investigation from an initial alert to a full attack timeline, with IOC extraction and MITRE ATT&CK mapping.
- That I can build and harden a realistic lab environment from scratch, not just consume prebuilt ones.
- That I document my reasoning the way a SOC analyst documents a case, so the decisions are reproducible and defensible.

> **Disclaimer:** All scripts, techniques, and information here are for **educational and defensive purposes only**, within controlled environments.

## Skills & Tools

| Domain | Tools & Technologies |
| :--- | :--- |
| **SIEM & Detection** | ![Splunk](https://img.shields.io/badge/Splunk-000000?style=flat-square&logo=splunk&logoColor=white) ![Elastic](https://img.shields.io/badge/Elastic_Stack-005571?style=flat-square&logo=elastic&logoColor=white) Wazuh, Sigma, ElastAlert |
| **Endpoint Telemetry** | Sysmon, Windows Event Logs, Linux auth logs |
| **Network Analysis** | ![Wireshark](https://img.shields.io/badge/Wireshark-1679A7?style=flat-square&logo=wireshark&logoColor=white) tcpdump, Nmap, PCAP analysis |
| **Analysis & Forensics** | CyberChef, Windows hardening, OWASP Top 10, web attack analysis |
| **Scripting** | ![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white) ![Bash](https://img.shields.io/badge/Bash-4EAA25?style=flat-square&logo=gnu-bash&logoColor=white) PowerShell |
| **Infrastructure** | pfSense, virtualization, home lab design |

## Repository Structure

```text
/
├── Infrastructure-Labs/       # Home lab build docs: pfSense, Windows 11, Windows Server
├── Iron4Software-SOC-Project/ # End-to-end purple team lab (documented separately)
├── Knowledge-WriteUps/        # Technical knowledge base and TryHackMe writeups, by domain
│   ├── Linux-Basics/          # Linux investigation and home lab writeups
│   ├── Networking-Basics/
│   ├── OWASP-Top-10/
│   ├── SOC-Training/
│   ├── Tools/
│   ├── Web-Hacking/
│   └── Windows-Hardening/     # Windows investigation and hardening writeups
├── Networking/                # Traffic and protocol analysis
│   ├── PCAP-Analysis/         # PCAP investigation writeups
│   └── Wireshark-Labs/        # Wireshark capture analysis
│   # plus Nmap and tcpdump lab writeups
└── Projects-Simulations/      # SOC simulator exercises
    └── SOC-Simulations/       # Alert triage, classification and reporting
```

## Highlighted Work

- **Iron4Software Purple Team Project:** a full attack-and-detect lab built end to end, from infrastructure to SIEM investigation. The most complete demonstration of the workflow I would bring to a SOC.
- **SOC Simulator: Alert Triage, Classification and Reporting:** a structured triage exercise mirroring the day-to-day of an N1 analyst on the alert queue.
- **Investigation writeups (Knowledge-WriteUps):** individual cases covering log analysis, network forensics, Windows and Linux telemetry, and web attack patterns, each written up with the reasoning made explicit.

## Contact

Open to SOC Analyst / Blue Team opportunities.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/gerard-diaz-gibert)
[![Email](https://img.shields.io/badge/Email-D14836?style=for-the-badge&logo=gmail&logoColor=white)](mailto:gerarddiazgibert@gmail.com)