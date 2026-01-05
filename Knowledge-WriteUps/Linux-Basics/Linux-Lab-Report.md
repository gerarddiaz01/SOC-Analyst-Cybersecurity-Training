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