# Windows PowerShell - Cheat Sheet

## 1. Bases de PowerShell & Découverte
PowerShell utilise des **cmdlets**, des outils puissants pour l'administration système et l'automatisation. Contrairement à CMD, PowerShell manipule des **objets**, et non simplement du texte.

### Syntaxe : La convention Verbe-Nom
Les cmdlets suivent une norme de nommage stricte `Verbe-Nom` pour garantir la prévisibilité.
* **Verbe** : L'action à effectuer (ex: `Get`, `Set`, `New`, `Remove`).
* **Nom** : L'entité sur laquelle on agit (ex: `Content`, `Service`, `Location`).
    * `Get-Content` : Lit un fichier (équivalent à `cat` ou `type`).
    * `Set-Location` : Change de répertoire (équivalent à `cd`).

### Commandes Essentielles de Découverte
Être autonome en PowerShell signifie savoir trouver ses outils et la documentation.

| Cmdlet | Description | Usage Professionnel |
| :--- | :--- | :--- |
| **`Get-Command`** | Liste tous les cmdlets, fonctions et alias disponibles. | `Get-Command -Verb Get` (Trouve tous les outils "Get") |
| **`Get-Help`** | L'outil le plus critique. Affiche la syntaxe et l'usage. | `Get-Help <Cmdlet> -Examples` (Affiche des cas concrets) |
| **`Get-Alias`** | Mappe les anciennes commandes CMD/Linux vers PS. | `Get-Alias dir` (Révèle que c'est un raccourci pour `Get-ChildItem`) |

### Création d'Alias
Pour créer nos propres raccourcis (ex: créer `grep` pour `Select-String`) :
* **Temporaire :** `Set-Alias grep Select-String`
* **Persistant :** Ajouter la commande dans le fichier `$PROFILE`.

### Étendre les Fonctionnalités (Modules)
PowerShell se connecte à des dépôts en ligne (comme PowerShell Gallery) pour récupérer de nouveaux outils.
* **`Find-Module`** : Chercher des paquets en ligne.
    * *Exemple :* `Find-Module -Name "*Security*"` (Les astérisques aident à la recherche partielle).
* **`Install-Module`** : Installe le paquet sélectionné.

## 2. Navigation et Gestion des Fichiers
PowerShell simplifie la gestion des fichiers en utilisant des cmdlets génériques qui fonctionnent aussi bien pour les dossiers que pour les fichiers.

### Navigation et Listing
| Cmdlet | Alias (CMD/Bash) | Description | Exemple |
| :--- | :--- | :--- | :--- |
| **`Get-ChildItem`** | `dir`, `ls` | Liste le contenu d'un répertoire. | `Get-ChildItem -Path "C:\Users"` |
| **`Set-Location`** | `cd` | Change le répertoire courant. | `Set-Location -Path "..\Documents"` |

### Création et Manipulation (L'approche Unifiée)
Contrairement au CMD (qui utilise `md`, `echo`, `del`, `rd`), PowerShell utilise des verbes génériques associés au paramètre `-ItemType`.

* **Création (`New-Item`)** :
    * **Dossier :** `New-Item -Path ".\Logs" -ItemType Directory`
    * **Fichier :** `New-Item -Path ".\Logs\note.txt" -ItemType File`
    * *Note :* L'alias `mkdir` existe mais est une fonction wrapper, il vaut mieux s'habituer à `New-Item` dans les scripts.

* **Suppression (`Remove-Item`)** :
    * Supprime fichiers ou dossiers : `Remove-Item -Path ".\Logs"` (Alias: `rm`, `del`).

* **Copie et Déplacement** :
    * **`Copy-Item`** (`cp`, `copy`) : `Copy-Item ".\file.txt" -Destination ".\Backup\"`
    * **`Move-Item`** (`mv`, `move`) : Sert aussi à **renommer** : `Move-Item "ancien.txt" "nouveau.txt"`

### Lecture de contenu
* **`Get-Content`** (`type`, `cat`) : Affiche le contenu d'un fichier dans la console.
    * *Exemple :* `Get-Content ".\passwords.txt"`

## 3. Pipeline, Filtrage et Tri
La puissance de PowerShell réside dans le **Pipeline (`|`)**. Il permet de passer la sortie d'une commande (output) comme entrée (input) vers une autre.
**Important :** PowerShell transmet des **Objets** (avec propriétés et méthodes), pas juste du texte brut.

### Commandes de Manipulation de Données

| Cmdlet | Alias | Description | Exemple |
| :--- | :--- | :--- | :--- |
| **`Where-Object`** | `where`, `?` | Filtre les résultats selon une condition. | `Get-Service | Where-Object Status -eq 'Running'` |
| **`Sort-Object`** | `sort` | Trie les résultats par propriété. | `Get-ChildItem | Sort-Object Length -Descending` |
| **`Select-Object`** | `select` | Choisit des propriétés spécifiques ou limite le nombre de résultats. | `Get-ChildItem | Select-Object Name, Length -First 5` |
| **`Select-String`** | (Aucun par défaut) | Recherche du texte dans des fichiers (équivalent `grep`). | `Select-String -Path "*.log" -Pattern "Error"` |

### Opérateurs de Comparaison
Contrairement à Bash (`=`, `!=`, `>`), PowerShell utilise des tirets :

* **`-eq`** : Égal à (*Equal*)
* **`-ne`** : Pas égal à (*Not Equal*)
* **`-gt`** / **`-ge`** : Plus grand que (*Greater Than*) / ou égal (*Greater or Equal*)
* **`-lt`** / **`-le`** : Plus petit que (*Less Than*) / ou égal (*Less or Equal*)
* **`-like`** : Correspondance avec joker (wildcard `*`). Ex: `-like "test*"`

## 4. Énumération Système et Réseau
Pour l'audit et l'administration, PowerShell permet de récupérer des informations granulaires (objets) là où CMD ne renvoyait que du texte.

### Informations Système et Utilisateurs
| Cmdlet | Équivalent CMD | Description |
| :--- | :--- | :--- |
| **`Get-ComputerInfo`** | `systeminfo` | Affiche un rapport complet (OS, BIOS, Hardware). C'est beaucoup plus détaillé que son homologue CMD. |
| **`Get-LocalUser`** | `net user` | Liste les utilisateurs locaux. Indispensable pour vérifier la sécurité (comptes activés, descriptions suspectes). |

### Configuration Réseau
| Cmdlet | Équivalent CMD | Description |
| :--- | :--- | :--- |
| **`Get-NetIPConfiguration`** | `ipconfig /all` | Vue d'ensemble des interfaces, IP, DNS et Gateway. |
| **`Get-NetIPAddress`** | (Pas d'équivalent direct) | Liste détaillée de toutes les IP configurées (actives ou non) sur le système. |

### Astuce d'Audit
Pour trouver rapidement les administrateurs ou les comptes actifs :
`Get-LocalUser | Where-Object Enabled -eq $True`

## Analyse Système Temps Réel & Forensique

Cette section couvre les commandes essentielles pour surveiller l'activité dynamique du système (processus, réseau) et effectuer des analyses d'intégrité de base.

### Surveillance Dynamique (Processus & Réseau)

| Cmdlet | Description | Cas d'usage (Use Case) |
| :--- | :--- | :--- |
| **`Get-Process`** | Affiche les processus en cours d'exécution (CPU, RAM, ID). | Troubleshooting, repérage de processus suspects consommant des ressources anormales. |
| **`Get-Service`** | Liste l'état des services (Running, Stopped, Paused). | Identifier des services malveillants installés pour la persistance ou des services critiques arrêtés. |
| **`Get-NetTCPConnection`** | Affiche les connexions TCP actives (ports locaux/distants). | **Incident Response** : Détecter des backdoors, des reverse shells ou des connexions vers des C2 (Command & Control). |

## 5. Analyse Système Temps Réel & Forensique

Cette section couvre les commandes essentielles pour surveiller l'activité dynamique du système (processus, réseau) et effectuer des analyses d'intégrité de base.

### Surveillance Dynamique (Processus & Réseau)

| Cmdlet | Description | Cas d'usage (Use Case) |
| :--- | :--- | :--- |
| **`Get-Process`** | Affiche les processus en cours d'exécution (CPU, RAM, ID). | Troubleshooting, repérage de processus suspects consommant des ressources anormales. |
| **`Get-Service`** | Liste l'état des services (Running, Stopped, Paused). | Identifier des services malveillants installés pour la persistance ou des services critiques arrêtés. |
| **`Get-NetTCPConnection`** | Affiche les connexions TCP actives (ports locaux/distants). | **Incident Response** : Détecter des backdoors, des reverse shells ou des connexions vers des C2 (Command & Control). |

### Intégrité des Fichiers & Données Cachées

#### Hachage de Fichier
Permet de vérifier l'intégrité d'un fichier et de détecter toute altération (tampering).
```powershell
Get-FileHash -Path .\fichier_suspect.txt
# Par défaut : SHA256. Utiliser -Algorithm pour changer (MD5, SHA1, etc.)
```

### Alternate Data Streams (ADS)
Les ADS permettent de cacher des données derrière un fichier NTFS standard. Ils sont invisibles pour l'explorateur Windows classique.

**Commande pour lister les flux :**
```powershell
Get-Item -Path "C:\Chemin\Vers\Fichier.txt" -Stream *
```

## 6. Scripting & Automatisation

Le scripting consiste à écrire une série de commandes dans un fichier texte (un script) pour automatiser des tâches manuelles. C'est comme donner une "to-do list" à l'ordinateur.

**Importance en Cybersécurité :**
* **Blue Team :** Analyse de logs, extraction d'IOCs, détection d'anomalies.
* **Red Team :** Énumération système, exécution de commandes à distance, obfuscation.
* **SysAdmin :** Gestion de configuration, vérification d'intégrité, application de politiques de sécurité.

### Exécution à Distance : `Invoke-Command`

Cette commande est fondamentale pour gérer des machines à distance ou exécuter des payloads sur une cible. Elle permet de lancer des commandes sur un ou plusieurs ordinateurs (locaux ou distants).

| Paramètre Clé | Description |
| :--- | :--- |
| **`-ComputerName`** | Spécifie la machine cible. |
| **`-FilePath`** | Exécute un script local (sur ta machine) *vers* la machine distante. |
| **`-ScriptBlock { ... }`** | Exécute directement une commande ou un bloc de code sans avoir besoin d'un fichier script. |
| **`-Credential`** | Permet de spécifier un utilisateur/domaine spécifique pour l'exécution. |

#### Exemples d'utilisation

**1. Lancer un script local sur un serveur distant :**
Le script est sur ma machine, mais il s'exécute sur le serveur.
```powershell
Invoke-Command -FilePath c:\scripts\audit.ps1 -ComputerName Serveur01
```

**2. Lancer une commande directe (sans fichier) :**
Ici, on demande au serveur distant de nous donner sa culture (langue/région) en utilisant des identifiants spécifiques.
```powershell
Invoke-Command -ComputerName Serveur01 -Credential Domaine\User -ScriptBlock { Get-Culture }
```