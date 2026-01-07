## ⌨️ 1. CMD : Reconnaissance Système & Bases

Avant d'utiliser des outils complexes, il faut savoir interroger le système avec les commandes natives (Living off the Land).

| Commande | Description & Usage SOC | Exemple |
| :--- | :--- | :--- |
| `systeminfo` | **La mine d'or.** Affiche l'OS, la version, le **Hostname**, la RAM, et surtout les **Hotfix (KB)** installés (utile pour voir si une faille est patchée). | `systeminfo` |
| `ver` | Affiche la version exacte du noyau Windows. Rapide pour savoir si on est sur un vieux serveur. | `ver` |
| `hostname` | Affiche le nom de la machine. Crucial pour se repérer dans l'AD. | `hostname` |
| `set` | Affiche toutes les variables d'environnement (PATH, USERNAME, LOGONSERVER). | `set` (ou `echo %PATH%`) |
| `driverquery` | Liste tous les pilotes installés. Utile pour repérer un driver vulnérable ou malveillant (Rootkit). | `driverquery` |
| `cls` | Nettoie l'écran (Clear Screen). | `cls` |
| `help` | Affiche l'aide pour une commande. | `help [commande]` |

### ⚡ Le concept du Pipe (`|`)
Le symbole `|` permet d'envoyer le résultat d'une commande vers une autre.
* **Usage courant :** Quand une commande crache trop de texte (comme `driverquery`), on utilise `more` pour lire page par page.
* **Syntaxe :** `commande_bavarde | more`
* **Navigation :** `Espace` pour avancer, `Ctrl+C` pour quitter.

## 🌐 2. Network Troubleshooting & Discovery

Commandes pour analyser les connexions actives et la configuration réseau.

| Commande | Description | Usage SOC / Analyse |
| :--- | :--- | :--- |
| `ipconfig /all` | Affiche l'IP, le Masque, la Gateway, les DNS et l'**Adresse MAC** (Physique). | Première commande à lancer. Vérifier les DNS (est-ce un DNS malveillant ?) et le suffixe DNS. |
| `getmac` | Affiche uniquement l'adresse MAC. | Utile pour identifier une machine sur un switch ou dans des logs DHCP. |
| `ping [target]` | Teste la connectivité (ICMP Echo Request). | Vérifier si une machine est "vivante". *Attention :* Les pare-feu (comme Windows Defender) bloquent souvent le Ping par défaut. |
| `tracert [target]` | Affiche la route (les routeurs) jusqu'à la cible. | Analyse de chemin : Par où passent mes paquets ? Y a-t-il un détour suspect (Hijacking) ? |
| `nslookup [domain]` | Résolution de nom (DNS). Transforme `www.google.com` en IP. | **Crucial.** Permet de repérer si un domaine pointe vers une IP connue comme malveillante (C2). |
| `netstat` | Affiche les connexions réseaux actives. | **L'outil roi.** Permet de voir qui est connecté à la machine. |

### 🕵️ Focus sur Netstat (La chasse aux connexions)
L'analyste utilise rarement `netstat` seul. On utilise des "flags" pour avoir des détails :
* **Commande SOC :** `netstat -ano` (ou `-abon` si admin)
    * `-a` : Affiche tout (Listening ports + Established connections).
    * `-n` : Affiche les IP/Ports en numérique (pas de résolution DNS lente).
    * `-o` : Affiche le **PID** (Process ID). Permet de lier la connexion au processus (via Task Manager).
    * `-b` : Affiche directement le nom de l'exécutable (nécessite Admin).

## 📂 3. File System Operations (Navigation & Gestion)

Commandes pour se déplacer et manipuler les fichiers.

| Commande | Description | Usage SOC / Analyse |
| :--- | :--- | :--- |
| `cd` | Affiche le dossier actuel (équivalent `pwd`). | Toujours vérifier où on est avant de lancer un script. |
| `cd [dossier]` | Entre dans un dossier. `cd ..` pour remonter. | |
| `dir` | Liste le contenu (équivalent `ls`). | |
| `dir /a` | **Afficher tout** (y compris cachés). | **Critique.** Les malwares se cachent souvent avec l'attribut "+h" (Hidden). Toujours utiliser `/a` en investigation. |
| `dir /s` | **Récursif**. Liste le contenu du dossier et de tous les sous-dossiers. | Utile pour chercher un fichier spécifique sur tout le disque : `dir /s malware.exe`. |
| `tree` | Affiche l'arborescence visuellement. | Permet de comprendre rapidement la structure d'un dossier web ou utilisateur. |
| `mkdir [nom]` | Créer un dossier (Make Directory). | Créer un dossier de collecte de preuves (`mkdir Evidence`). |
| `rmdir [nom]` | Supprimer un dossier (Remove Directory). | |
| `type [fichier]` | Affiche le contenu d'un fichier texte (équivalent `cat`). | Lire des logs, des fichiers *hosts* ou des notes laissées par l'attaquant (`type ransom_note.txt`). |
| `more [fichier]` | Affiche le contenu page par page. | Pour lire des gros fichiers de logs sans inonder le terminal. |
| `copy [source] [dest]` | Copier un fichier. | Faire une sauvegarde d'un fichier critique avant d'y toucher (`copy hosts hosts.bak`). |
| `move [source] [dest]` | Déplacer ou renommer un fichier. | |
| `del [fichier]` | Supprimer un fichier (ou `erase`). | |
| `*` (Wildcard) | Joker pour "n'importe quoi". | `del *.log` (Supprime tous les logs). `dir *.exe` (Liste tous les exécutables). |

## ⚙️ 4. Process Management (Gestion des Tâches)

Identifier et arrêter les processus (programmes en cours d'exécution).

| Commande | Description | Usage SOC / Analyse |
| :--- | :--- | :--- |
| `tasklist` | Affiche tous les processus en cours (Nom, PID, RAM). | Chercher des anomalies : processus inconnus, doublons suspects (deux `lsass.exe` ?), ou consommation RAM excessive. |
| `tasklist /FI "..."` | **Filtre** la liste. | `tasklist /FI "imagename eq nginx.exe"` : Pour vérifier si un service web spécifique tourne. |
| `taskkill /PID [ID]` | Arrête un processus via son identifiant unique. | Neutralisation précise. On préfère le PID au nom pour éviter de tuer le mauvais programme. |
| `taskkill /IM [Nom]` | Arrête un processus via son nom d'image. | `taskkill /IM notepad.exe` : Tue toutes les fenêtres Notepad d'un coup. |
| `/F` (Flag) | **Force** l'arrêt. | Indispensable pour les malwares récalcitrants : `taskkill /PID 1234 /F`. |

## Conclusion et Commandes Complémentaires

Dans cette section, nous nous sommes concentrés sur les commandes les plus pratiques pour accéder à un système en réseau via la ligne de commande. Cependant, il existe d'autres commandes administratives utiles à connaître pour la maintenance :

* **`chkdsk`** : Vérifie le système de fichiers et les volumes de disque à la recherche d'erreurs et de secteurs défectueux.
* **`driverquery`** : Affiche la liste des pilotes de périphériques (drivers) installés.
* **`sfc /scannow`** : Analyse les fichiers système pour détecter la corruption et tente de les réparer.

### Rappels importants
* **L'aide** : Ne pas oublier que l'ajout de `/?` à la fin de la plupart des commandes permet d'afficher la page d'aide.
* **La commande `more`** : Nous l'avons utilisée de deux manières :
    1.  Pour lire des fichiers texte : `more fichier.txt`
    2.  Pour paginer une sortie longue (via un pipe) : `commande | more`

### Gestion de l'alimentation (Shutdown)
La commande de base pour éteindre est `shutdown /s`. Voici les variantes essentielles :
* **Redémarrer** : `shutdown /r`
* **Annuler un arrêt** : `shutdown /a` (utile si un arrêt est programmé ou lancé par erreur).