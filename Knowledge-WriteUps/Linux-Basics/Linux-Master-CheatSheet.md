# 🐧 Linux Master Cheat Sheet (SOC Edition)

![Category](https://img.shields.io/badge/Category-System_Administration-orange?style=flat-square)
![Focus](https://img.shields.io/badge/Focus-Bash_Scripting_%26_Forensics-green?style=flat-square)

## 📖 À propos
Ce document synthétise les commandes Linux essentielles pour un Analyste SOC. Il couvre la navigation, la gestion des permissions, l'analyse de processus et la manipulation de logs.
*Basé sur les modules "Linux Fundamentals" (TryHackMe) et mes notes personnelles.*

---

## 📂 1. Navigation & Gestion de Fichiers (Survival Kit)

| Commande | Description & Usage SOC | Exemple |
| :--- | :--- | :--- |
| `ls -la` | Liste **tous** les fichiers (y compris cachés `.`) avec détails (permissions, owner). Utile pour repérer des fichiers suspects cachés. | `ls -la /tmp` |
| `cd` / `pwd` | Changer de dossier / Afficher le chemin actuel. | `cd /var/log` |
| `file [fichier]` | Détermine le vrai type d'un fichier (ne se fie pas à l'extension). | `file malware.jpg` (peut révéler un exécutable) |
| `cat [fichier]` | Affiche tout le contenu. | `cat /etc/passwd` |
| `touch` / `mkdir` | Créer un fichier vide / Créer un dossier. | `mkdir evidence_files` |
| `rm -rf [cible]` | Supprime un fichier ou dossier (récursif, forcé). ⚠️ Dangereux. | `rm malware.exe` |
| `cp` / `mv` | Copier ou Déplacer (aussi utilisé pour renommer). | `cp log.txt log.bak` |
| `wget [url]` | Télécharge un fichier depuis le web. | `wget http://site.com/tool.sh` |

---

## 🔍 2. Recherche & Manipulation de Texte (Grep Ninja)

L'arme principale pour l'analyse de logs.

| Commande | Description | Exemple |
| :--- | :--- | :--- |
| `grep "mot" [file]` | Recherche un motif spécifique. | `grep "Failed password" /var/log/auth.log` |
| `grep -r "mot" .` | Recherche récursive dans tous les fichiers du dossier actuel. | `grep -r "TODO" /home/dev` |
| `find / -name [nom]` | Trouve un fichier par son nom dans tout le système. | `find / -name "id_rsa"` |
| `|` (Pipe) | Envoie le résultat de la commande gauche vers la commande droite. | `cat access.log | grep "404"` |
| `>` / `>>` | Redirection : `>` écrase, `>>` ajoute à la fin du fichier. | `echo "Note" >> rapport.txt` |

---

## 🛡️ 3. Permissions & Utilisateurs

Comprendre qui a le droit de faire quoi (Concept clé : `r=4`, `w=2`, `x=1`).

| Commande | Explication | Usage Sécurité |
| :--- | :--- | :--- |
| `chmod 777` | Tout le monde peut lire/écrire/exécuter. | 🚨 **Danger critique**. Souvent utilisé par les malwares pour s'exécuter partout. |
| `chmod 700` | Seul le propriétaire a tous les droits. | ✅ Standard pour les clés SSH (`id_rsa`). |
| `chmod +x` | Rend un fichier exécutable. | Nécessaire pour lancer un script `.sh`. |
| `chown user:group` | Change le propriétaire d'un fichier. | `chown root:root system_file` |
| `su [user]` | Switch User (change d'utilisateur). | `su root` |
| `sudo [cmd]` | Exécute une commande en tant que root (sans changer de session). | `sudo apt update` |

---

## ⚙️ 4. Processus & Système

Pour repérer ce qui tourne sur la machine (et détecter les activités anormales).

* **`ps aux`** : Liste tous les processus en cours (User, PID, CPU, Commande).
    * *Réflexe SOC :* Chercher des noms bizarres ou des processus lancés depuis `/tmp`.
* **`top`** : Affiche les processus en temps réel (comme le Gestionnaire des tâches).
* **`kill [PID]`** : Arrête un processus par son ID.
    * `kill -9 [PID]` : Force l'arrêt immédiat (SigKill).
* **`systemctl status [service]`** : Vérifie si un service (ex: ssh, apache2) est actif.

---

## 📡 5. Réseau & Transfert (SSH/SCP)

| Commande | Description |
| :--- | :--- |
| `ssh user@IP` | Se connecter à une machine distante. |
| `scp file user@IP:/chemin` | Copie sécurisée de fichiers via SSH (Upload). |
| `python3 -m http.server` | Lance un serveur web instantané dans le dossier actuel (Port 8000). Très utile pour exfiltrer des données ou transférer des outils en CTF. |

---

## 🧪 Missions Pratiques (Home Lab - Niveau Avancé)

Exercices réalisés sur mon environnement virtuel (Ubuntu/Kali) pour valider les compétences SOC.

### 🎯 Mission 1 : Navigation, Flags & Opérateurs Logiques
* **Concepts :** `ls -la`, `&&`, Création de dossiers.
* **Objectif :** Maîtriser les options de commande et l'automatisation simple.
* **Actions :**
    1.  Utiliser la commande `ls -la` pour repérer les fichiers cachés (commençant par `.`) dans le dossier home.
    2.  Créer un dossier `Enquete` **ET** entrer dedans en une seule ligne de commande grâce à l'opérateur `&&` (ex: `mkdir Enquete && cd Enquete`).
    3.  Vérifier la position actuelle avec `pwd`.

### 🎯 Mission 2 : Manipulation de Texte & Redirections
* **Concepts :** `echo`, `nano`, `>`, `>>`, `cat`.
* **Objectif :** Créer et modifier des rapports d'incident sans interface graphique.
* **Actions :**
    1.  Utiliser `echo` pour écrire "Début de l'incident" dans un fichier `rapport.txt` (Opérateur `>` pour écraser/créer).
    2.  Utiliser `echo` pour **ajouter** "Preuve 1 collectée" à la suite du fichier sans l'écraser (Opérateur `>>`).
    3.  Ouvrir ce fichier avec `nano`, ajouter une ligne manuellement "Analyse terminée", et sauvegarder (`Ctrl+X`, `Y` pour Nano).
    4.  Afficher le résultat final avec `cat` pour vérifier l'intégrité.

### 🎯 Mission 3 : Utilisateurs, Dossiers Système & Permissions
* **Concepts :** `su`, `/tmp` vs `/etc`, `chmod`, `chown`.
* **Objectif :** Comprendre les privilèges et les zones inscriptibles.
* **Actions :**
    1.  Tenter de créer un fichier dans `/etc` (ex: `touch /etc/test_hack`).  L'action doit échouer (**Permission Denied**) car c'est un dossier système protégé.
    2.  Aller dans `/tmp` (dossier temporaire inscriptible par tous) et créer un fichier `malware_sample.txt`.
    3.  Changer d'utilisateur avec `su` (ou `sudo su` pour passer root).
    4.  Changer le propriétaire du fichier avec `chown` (ex: `chown root:root malware_sample.txt`) et vérifier avec `ls -l` que l'utilisateur standard ne peut plus le modifier.

### 🎯 Mission 4 : Processus & Background
* **Concepts :** `&` (Background), `ps`, `kill`.
* **Objectif :** Gérer des tâches de fond (ex: un dump réseau long) sans bloquer le terminal.
* **Actions :**
    1.  Lancer une commande longue en arrière-plan avec l'opérateur `&` (ex: `sleep 500 &`).
    2.  Vérifier qu'elle tourne avec `ps aux` et noter son **PID** (Process ID).
    3.  Arrêter le processus avec `kill [PID]`.

### 🎯 Mission 5 : Réseau & Transfert (Data Exfiltration Simulation)
* **Concepts :** `python3 http.server`, `wget`, `ssh`, `scp`.
* **Objectif :** Simuler l'exfiltration de données ou le téléchargement d'outils entre deux machines.
* **Actions :**
    1.  **Serveur (Machine A) :** Lancer un serveur web Python instantané sur le port 8000 (`python3 -m http.server 8000`).
    2.  **Client (Machine B) :** Télécharger un fichier depuis la Machine A avec `wget http://[IP_A]:8000/fichier`.
    3.  **Transfert Sécurisé :** Copier un fichier sensible de A vers B via SSH avec `scp` (ex: `scp secret.txt user@IP_B:/tmp/`).

---
*Dernière mise à jour : Janvier 2026*