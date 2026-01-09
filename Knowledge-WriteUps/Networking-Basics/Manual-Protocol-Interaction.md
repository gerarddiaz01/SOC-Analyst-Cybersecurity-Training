# 🌐 Interaction Manuelle avec les Protocoles Réseau (CLI)

Ce laboratoire documente l'exploration et l'interaction manuelle avec les protocoles de la couche Application (Modèle OSI Layer 7) en utilisant des outils en ligne de commande (CLI) comme `telnet`, `ftp` et `whois`.

**Objectif :** Comprendre le fonctionnement interne des protocoles standards (HTTP, FTP, POP3) en forgeant manuellement les requêtes, simulant ainsi des processus de débogage ou d'énumération de services sans interface graphique.

---

## 1. HTTP via Telnet (Service Discovery & Banner Grabbing)
**Contexte :** Interagir avec un serveur Web sans navigateur pour identifier la version du serveur et récupérer des pages cachées.

### 🛠️ Méthodologie
L'outil `telnet` permet d'ouvrir une connexion TCP brute sur le port 80. Une fois connecté, je dois manuellement construire l'en-tête de la requête HTTP.

**Commande d'énumération :**
```bash
telnet [MACHINE_IP] 80
```

**Payload injecté (Requête HTTP Standard) :**
```http
GET / HTTP/1.1
Host: telnet.thm
[Entrée]
[Entrée]
```
> *Note : La double entrée est nécessaire pour signaler au serveur la fin de l'en-tête HTTP.*

### 🚩 Résultats & Analyse
* **Version du Serveur :** L'en-tête de réponse `Server:` permet d'identifier le logiciel (ex: Apache/2.4.xx ou nginx).
* **Challenge (Flag caché) :** Pour récupérer le fichier spécifique `flag.html`, la requête suivante a été utilisée :
    ```http
    GET /flag.html HTTP/1.1
    Host: telnet.thm
    ```
* **Flag obtenu :** `THM{...}` (Visible dans le code source HTML retourné).

---

## 2. OSINT & WHOIS
**Contexte :** Recueillir des informations publiques sur l'enregistrement d'un domaine (Open Source Intelligence).

### 🛠️ Méthodologie
Utilisation de la base de données WHOIS pour interroger les détails d'enregistrement du domaine cible.

**Commande :**
```bash
whois twitter.com
```

### 🚩 Résultats
* **Analyse :** Recherche de la ligne `Creation Date` dans les métadonnées du Registrar.
* **Date de création validée :** `2000-01-21` (Format YYYY-MM-DD).

---

## 3. FTP (File Transfer Protocol) - Authentification & Extraction
**Contexte :** Accéder à un serveur de fichiers, naviguer dans l'arborescence et exfiltrer des données sensibles.

### 🛠️ Méthodologie
Le protocole FTP (Port 21) permet souvent des connexions anonymes s'il est mal configuré.

**Séquence de commandes :**
1.  **Connexion :**
    ```bash
    ftp [MACHINE_IP]
    ```
2.  **Login :** Utilisateur `anonymous` (Mot de passe laissé vide/Entrée).
3.  **Énumération :**
    ```ftp
    ls
    ```
4.  **Exfiltration :**
    ```ftp
    get flag.txt
    ```
5.  **Lecture (Localement) :**
    ```bash
    cat flag.txt
    ```

### 🚩 Résultats
* L'accès anonyme a été confirmé.
* Le fichier `flag.txt` a été récupéré avec succès à la racine du serveur.

---

## 4. POP3 (Post Office Protocol) - Forensics d'Emails
**Contexte :** Connexion directe à un serveur de messagerie pour lire les emails stockés sans utiliser de client lourd (Outlook/Thunderbird).

### 🛠️ Méthodologie
POP3 (Port 110) utilise une série de commandes textuelles strictes pour l'authentification et la récupération des messages.

**Connexion Initiale :**
```bash
telnet [MACHINE_IP] 110
```

**Séquence d'interaction POP3 :**

| Étape | Commande | Description |
| :--- | :--- | :--- |
| **Login** | `USER [username]` | Déclare l'identité de l'utilisateur. |
| **Password** | `PASS [password]` | Authentifie l'utilisateur. |
| **Lister** | `LIST` | Affiche la liste des messages avec leur ID et taille. |
| **Lire** | `RETR 4` | Récupère le contenu complet du **4ème message**. |
| **Quitter** | `QUIT` | Ferme proprement la session. |

### 🚩 Résultats
* La commande `RETR 4` a permis d'afficher le corps du 4ème email.
* **Flag identifié :** `THM{...}` contenu dans le message.

---

## 💡 Compétences Validées (Key Takeaways)
* **Compréhension TCP/IP :** Capacité à établir des connexions brutes sur des ports applicatifs spécifiques (80, 21, 110).
* **Protocole HTTP :** Maîtrise de la structure des requêtes manuelles (Verbe GET, Header Host obligatoire).
* **Débogage de Service :** Capacité à tester la viabilité d'un service (Web, Mail, FTP) et à interagir avec lui en langage natif, compétence essentielle pour l'administration système et le Pentesting.