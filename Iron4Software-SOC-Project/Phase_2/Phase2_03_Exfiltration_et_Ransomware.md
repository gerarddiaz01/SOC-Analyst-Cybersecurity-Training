# Phase 2 - Action sur les Objectifs (Exfiltration et Ransomware)

**Environnement :** Home Lab virtuel sur Proxmox pour le projet Iron4Software — Formation Analyste SOC - CyberUniversity (Liora x Sorbonne).

## Objectif du Lab
La phase de mouvement latéral ayant permis d'obtenir les identifiants de l'Administrateur du domaine, la dernière étape de l'audit offensif consiste à accomplir l'objectif final (Action on Objectives). Je vais utiliser l'accès légitime volé pour me connecter au serveur cible, localiser des données critiques (ici, des données de santé soumises au RGPD), et simuler l'action d'un Ransomware (chiffrement et dépôt d'une demande de rançon). Cette action laissera des traces indélébiles dans les journaux Windows (connexions interactives, manipulation de fichiers) qui seront exploitées en Phase 4.

## Outils et Technologies
- **Système d'attaque :** Kali Linux.
- **Client RDP :** xfreerdp (FreeRDP).
- **Cible :** Windows Server 2019 (Contrôleur de Domaine).
- **Framework MITRE ATT&CK :** T1078 (Valid Accounts), T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery).

## 1. Accès Graphique via Bureau Distance (MITRE T1078)

L'attaque par force brute SMB ayant révélé le mot de passe `Admin123`, j'utilise ces informations pour initier une session graphique interactive sur le serveur cible.

**Exécution de la commande :**
Depuis Kali Linux, j'ai lancé le client RDP :
```bash
xfreerdp /v:192.168.3.10 /u:Administrateur /p:Admin123 /cert:ignore /dynamic-resolution
```

**Analyse "Sous le capot" :**
Cette commande établit un tunnel RDP direct vers le port 3389 du serveur Windows. Le paramètre `/cert:ignore` permet de contourner les avertissements liés aux certificats auto-signés du serveur interne. Puisque la règle de pare-feu pfSense (WAN Allow All) le permet, la connexion traverse l'infrastructure sans encombre et m'octroie le contrôle total (clavier/souris) du Contrôleur de Domaine, avec les plus hauts privilèges.

**Contexte SOC & Blue Team :**
Cette connexion est un événement critique. Dans le SIEM, cela se traduira par un événement Windows **Event ID 4624 (Logon Success)** avec un **Logon Type 10** (RemoteInteractive / RDP). La corrélation de cet événement de succès juste après l'avalanche d'échecs (Event ID 4625) vus à l'étape précédente est la signature absolue d'une attaque par force brute réussie ayant mené à une compromission interactive.

## 2. Simulation d'Impact : Le Ransomware (MITRE T1486)

Une fois sur le bureau du serveur, j'explore l'environnement et découvre un dossier nommé `PRIVATE - NE PAS RENTRER !`. Ce dossier illustre une mauvaise pratique de stockage des données.

**Exécution et Résultats :**
À l'intérieur de ce répertoire, j'identifie un fichier critique : un dump de base de données de production d'un client de la santé. Je procède à la simulation de l'attaque :
1. **Chiffrement :** Le fichier est prétendument chiffré et renommé avec une extension caractéristique de ransomware : `LOCKED-Dump_SQL_IronSuite_Clinique_StJean_PROD.bak`.
2. **Note de rançon :** Un fichier texte nommé `PAY-BITCOIN!` est créé à côté des données compromises. Il contient un message explicite de double extorsion ("YOU HAVE BEEN HACKED. PAY BITCOIN TO RETRIEVE THE LOCKED FILES. IF NOTHING IS DONE IN 3 DAYS, THE FILES WILL BE MADE PUBLIC.").

**Contexte SOC & Blue Team :**
L'altération de fichiers sensibles peut être détectée par le SOC si l'audit du système de fichiers (File System Auditing) est activé. La création d'extensions inattendues (`.locked`) ou la création massive de fichiers texte (notes de rançon) dans des répertoires partagés sont des indicateurs de compromission (IoC) majeurs que nous chercherons à modéliser dans nos futures règles Splunk. 

## Conclusion de la Phase 2 (Audit Offensif)
L'audit offensif est terminé. En exploitant une chaîne de vulnérabilités allant d'une faille applicative (Upload PHP) à des défauts d'architecture (Routage permissif) et de durcissement (Politique de verrouillage désactivée, mots de passe faibles), l'infrastructure "Vulnerable-by-Design" a été intégralement compromise. L'entreprise fictive fait face à un incident majeur impliquant des données de santé (RGPD). La matière première (les logs d'attaque) est désormais générée. La prochaine étape consistera à analyser ces traces et à durcir les défenses de l'infrastructure.

---
*Fin du rapport de Lab.*