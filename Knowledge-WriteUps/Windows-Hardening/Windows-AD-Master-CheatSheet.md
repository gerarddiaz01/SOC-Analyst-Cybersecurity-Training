# Windows & Active Directory Master Cheat Sheet (SOC Edition)

![Category](https://img.shields.io/badge/Category-Windows_Forensics-blue?style=flat-square)
![Focus](https://img.shields.io/badge/Focus-Active_Directory_%26_Logs-red?style=flat-square)

## 📖 À propos
Ce document synthétise les concepts clés de l'administration Windows et Active Directory pour un Analyste SOC. Il couvre l'analyse de processus, le système de fichiers NTFS, la gestion des identités AD et les stratégies de groupe (GPO).
*Basé sur les modules "Windows Fundamentals" & "Active Directory Basics" (TryHackMe).*

---

## 🖥️ 1. Windows Core & Forensics

### Gestion des Processus (Task Manager)
Pour repérer des malwares ou activités suspectes.
* **Details Tab :** Vue détaillée indispensable pour l'analyste.
* **Colonnes clés à surveiller :**
    * **PID (Process ID) :** Identifiant unique. Utile pour corréler avec des logs ou des connexions réseau (Netstat).
    * **Image Name :** Nom de l'exécutable. *Suspicion :* `svchost.exe` mal orthographié ou lancé depuis `%TEMP%`.
    * **User Name :** Qui a lancé le processus ? (SYSTEM vs Utilisateur).

### Système de Fichiers & Registre
* **NTFS Permissions :**
    * **Full Control, Modify, Read & Execute, Read, Write.**
    * *Concept SOC :* Les attaquants tentent souvent de modifier les ACLs (Access Control Lists) pour accéder à des fichiers sensibles.
* **Registre (Registry) :** Base de données de configuration (commande `regedit`).
    * *Clés de persistance (Run Keys) :* Endroits où les malwares se cachent pour démarrer automatiquement (ex: `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`).

### Event Viewer
Les journaux (Logs) sont la source principale de détection.
* **Security.evtx :** Connexions, accès fichiers, élévation de privilèges.
* **System.evtx :** Démarrage services, erreurs hardware.
* **Application.evtx :** Crashs d'applications, erreurs logicielles.

---

## 🌲 2. Architecture Active Directory (AD)

Active Directory est l'annuaire centralisé utilisé pour gérer les identités et les accès dans un réseau d'entreprise.

### Structure Logique
* **Domain Controller (DC) :** Le serveur qui détient la base de données AD et gère l'authentification (Kerberos).
* **Domain :** Un groupe d'objets (utilisateurs, ordinateurs) partageant la même base de données.
* **Tree (Arbre) :** Collection de domaines partageant le même espace de noms (ex: `corp.com` et `uk.corp.com`).
* **Forest (Forêt) :** Collection d'arbres. C'est la frontière de sécurité ultime.
* **Trust (Approbation) :** Permet à des utilisateurs d'un domaine d'accéder aux ressources d'un autre domaine (One-way ou Two-way).

### Objets & Organisation
* **Users & Computers :** Les identités du réseau.
* **Groups :** Utilisés pour assigner des permissions (ex: "Domain Admins", "HR-Staff").
* **OU (Organizational Unit) :** Conteneurs pour organiser les objets (par département, localisation) et **appliquer des GPO**.

---

## 🛡️ 3. Sécurité & Hardening (GPO)

Les **Group Policy Objects (GPO)** permettent d'appliquer des configurations de sécurité à tout le parc informatique d'un coup.

| Action Hardening | Description SOC |
| :--- | :--- |
| **Password Policy** | Forcer la complexité, la longueur et la rotation des mots de passe. |
| **Account Lockout** | Verrouiller un compte après 5 échecs (Anti-Bruteforce). |
| **Audit Policy** | Activer la génération de logs (Succès/Échecs) pour les connexions. Indispensable pour voir les attaques dans le SIEM. |
| **Restreindre CMD/PowerShell** | Empêcher les utilisateurs standards de lancer des terminaux. |

---

## 🔍 Cheat Sheet : Event IDs Critiques (Windows Security)

Codes à connaître par cœur pour l'analyse de logs.

| Event ID | Signification | Contexte SOC |
| :--- | :--- | :--- |
| **4624** | Logon Successful | Connexion réussie. Vérifier le `Logon Type` (3=Réseau, 2=Local, 10=RDP). |
| **4625** | Logon Failed | Échec de connexion. **Alerte :** Brute-force ou Password Spraying. |
| **4720** | User Created | Un utilisateur a été créé. Suspect si hors procédure RH. |
| **4726** | User Deleted | Un utilisateur a été supprimé. |
| **4672** | Special Privileges | Un admin s'est connecté (Admin Login). |
| **1102** | Log Clear | **ALERTE ROUGE.** Quelqu'un a effacé les logs de sécurité. |

---
*Dernière mise à jour : Janvier 2026*