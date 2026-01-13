# Linux Master Cheat Sheet (SOC Edition)

![Category](https://img.shields.io/badge/Category-System_Administration-orange?style=flat-square)
![Focus](https://img.shields.io/badge/Focus-Bash_Scripting_%26_Forensics-green?style=flat-square)

## 📖 À propos
Ce document synthétise les commandes Linux essentielles pour un Analyste SOC. Il couvre la navigation, la gestion des permissions, l'analyse de processus et la manipulation de logs.
*Basé sur les modules "Linux Fundamentals" (TryHackMe) et mes notes personnelles.*

---

## 1. Navigation & Gestion de Fichiers (Survival Kit)

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

## 2. Recherche & Manipulation de Texte (Grep Ninja)

L'arme principale pour l'analyse de logs.

| Commande | Description | Exemple |
| :--- | :--- | :--- |
| `grep "mot" [file]` | Recherche un motif spécifique. | `grep "Failed password" /var/log/auth.log` |
| `grep -r "mot" .` | Recherche récursive dans tous les fichiers du dossier actuel. | `grep -r "TODO" /home/dev` |
| `find / -name [nom]` | Trouve un fichier par son nom dans tout le système. | `find / -name "id_rsa"` |
| `|` (Pipe) | Envoie le résultat de la commande gauche vers la commande droite. | `cat access.log | grep "404"` |
| `>` / `>>` | Redirection : `>` écrase, `>>` ajoute à la fin du fichier. | `echo "Note" >> rapport.txt` |

---

## 3. Permissions & Utilisateurs

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

## 4. Processus & Système

Pour repérer ce qui tourne sur la machine (et détecter les activités anormales).

* **`ps aux`** : Liste tous les processus en cours (User, PID, CPU, Commande).
    * *Réflexe SOC :* Chercher des noms bizarres ou des processus lancés depuis `/tmp`.
* **`top`** : Affiche les processus en temps réel (comme le Gestionnaire des tâches).
* **`kill [PID]`** : Arrête un processus par son ID.
    * `kill -9 [PID]` : Force l'arrêt immédiat (SigKill).
* **`systemctl status [service]`** : Vérifie si un service (ex: ssh, apache2) est actif.

---

## 5. Réseau & Transfert (SSH/SCP)

| Commande | Description |
| :--- | :--- |
| `ssh user@IP` | Se connecter à une machine distante. |
| `scp file user@IP:/chemin` | Copie sécurisée de fichiers via SSH (Upload). |
| `python3 -m http.server` | Lance un serveur web instantané dans le dossier actuel (Port 8000). Très utile pour exfiltrer des données ou transférer des outils en CTF. |

---
*Dernière mise à jour : Janvier 2026*