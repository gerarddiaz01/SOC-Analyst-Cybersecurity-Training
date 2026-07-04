# Knowledge Base & Writeups

![Category](https://img.shields.io/badge/Category-Knowledge_Base-blue?style=flat-square)
![Source](https://img.shields.io/badge/Source-TryHackMe_%26_SOC_Master's-red?style=flat-square)
![Policy](https://img.shields.io/badge/Policy-No_Spoilers-success?style=flat-square)

## About this folder

This is the core of my portfolio: the technical knowledge base and investigation writeups I have built through my SOC Analyst master's program and my practical training on TryHackMe.

The goal is not to publish ready-made solutions. It is to document how I investigate: the reasoning behind each step, the commands that actually move an investigation forward, and the detection logic a SOC analyst applies day to day. Every writeup is approached from a blue team standpoint, with the emphasis on how to read the evidence, spot the anomaly, and follow the chain, rather than on the answer itself.

## Featured investigations

The writeups I would point a recruiter to first. Each documents a full investigation, from initial alert to conclusions, with the reasoning made explicit at every step.

- **[Slingshot: Web Server Compromise](SOC-Training/slingshot-web-compromise.md)** : investigation of a web server compromise in Elastic, tracing the attack from initial web exploitation through to post-compromise activity.
- **[Boogeyman 1](SOC-Training/boogeyman1-investigation.md)** : end-to-end investigation of a phishing-led intrusion, following the chain from malicious delivery through execution and command and control.
- **[Incident Response Timeline](SOC-Training/SOC-Analyst-Lab-Incident-Response-Timeline.md)** : reconstruction of a full attack timeline from log evidence, the core deliverable of an incident responder.
- **[Splunk Backdoor Investigation](SOC-Training/splunk_backdoor_investigation.md)** : detection and analysis of a backdoored system in Splunk, pairing process telemetry with system events to confirm the finding.

## Structure by domain

The knowledge base is organized around the core competencies of the SOC analyst role:

- **`/SOC-Training`** : SOC investigation writeups. Alert triage, SIEM analysis, detection logic, and full investigation walkthroughs from initial alert to attack timeline. The most job-relevant material in this repository.
- **`/Windows-Hardening`** : Windows security and forensics. Event log analysis, Sysmon telemetry, Active Directory and GPO, endpoint hardening and audit strategy.
- **`/Linux-Basics`** : System administration from an investigative angle. Permissions, authentication logs, and Bash for log parsing and triage.
- **`/Networking-Basics`** : Protocol analysis (TCP/IP) and network intrusion detection fundamentals.
- **`/Web-Hacking`** : Web attack techniques analyzed defensively, understanding the offense in order to detect it.
- **`/OWASP-Top-10`** : The OWASP Top 10 vulnerability classes, each looked at through a detection and mitigation lens.
- **`/Tools`** : Technical cheat sheets for the tools I use daily (Nmap, Wireshark, Splunk, and others), built as quick operational references.

---
*Updated continuously as my training progresses.*