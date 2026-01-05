# 🌐 Analyse du Protocole HTTP (HyperText Transfer Protocol)

![Category](https://img.shields.io/badge/Category-Network_%26_Web-blue?style=flat-square)
![Focus](https://img.shields.io/badge/Focus-Log_Analysis-orange?style=flat-square)

## 🎯 Objectif
Comprendre la structure brute des requêtes et réponses HTTP pour être capable d'analyser le trafic web et les logs de serveurs (Apache/Nginx/IIS) dans un contexte de SOC.

## 🧠 Concepts Techniques Clés

### 1. Structure d'une Requête
Le protocole est "Stateless" (sans état). Chaque requête est indépendante.
* **Verb (Méthode) :** Indique l'action voulue (`GET`, `POST`, `PUT`, `DELETE`).
* **URL (Path) :** La ressource demandée.
* **Headers :** Les métadonnées critiques pour l'analyste.

### 2. Les Codes de Statut (Status Codes) & Interprétation Sécurité
Voici comment j'interprète les codes lors d'une investigation :

| Plage | Signification | Intérêt pour le SOC (Exemples) |
| :--- | :--- | :--- |
| **2xx** | Succès | `200 OK` : Trafic normal (ou exfiltration réussie). |
| **3xx** | Redirection | `301/302` : Peut être utilisé dans des campagnes de Phishing. |
| **4xx** | Erreur Client | `401/403` : Brute-force ou accès non autorisé.<br>`404` (en masse) : Scan de vulnérabilités (Fuzzing). |
| **5xx** | Erreur Serveur | `500` : Peut indiquer une injection SQL (SQLi) réussie qui a crashé le backend. |

### 3. Headers Critiques pour l'Analyse
* **User-Agent :** Permet d'identifier le client.
    * *Suspicion :* User-Agents vides, ou outils connus comme `sqlmap`, `nikto`, `curl` (si inattendu).
* **Referer :** D'où vient l'utilisateur.
* **Cookie :** Utilisé pour le suivi de session (risque de vol de session / Hijacking).
* **Host :** Indispensable dans les environnements virtualisés (Vhosts).

## 🛠️ Exercice Pratique : Manipulation de Requêtes Brutes

Dans le cadre du module "HTTP in Detail", j'ai utilisé un émulateur de client HTTP pour forger manuellement des paquets et interagir avec une API REST. Voici les scénarios techniques réalisés :

### 1. Récupération de Ressources et Paramètres (GET)
* **Action :** Requête simple vers `/room`.
* **Action avec Paramètre :** Requête vers `/blog` en ciblant un ID spécifique (`id=1`).
    * **Commande :** `GET /blog?id=1 HTTP/1.1`
    * **🛡️ Note d'Analyste :** Les paramètres passés via `GET` sont visibles dans l'URL. Si une application y passe des tokens ou mots de passe, ils apparaîtront en clair dans les logs du serveur et du proxy (Incident de fuite de données).

### 2. Actions Destructives (DELETE)
* **Action :** Suppression de l'utilisateur ID 1.
    * **Commande :** `DELETE /user/1 HTTP/1.1`
    * **🛡️ Note d'Analyste :** La méthode `DELETE` est rarement autorisée pour les utilisateurs standards. Voir cette méthode dans des logs provenant d'une IP externe est souvent un indicateur de compromission ou de tentative d'exploitation d'API.

### 3. Modification de Données (PUT)
* **Action :** Mise à jour des privilèges de l'utilisateur 2 (`username=admin`).
    * **Commande :** `PUT /user/2` avec le corps `username=admin`.
    * **🛡️ Note d'Analyste :** Contrairement à `POST` (création), `PUT` remplace ou met à jour une ressource existante. C'est un vecteur classique pour l'escalade de privilèges (IDOR) si l'API ne vérifie pas correctement qui fait la demande.

### 4. Authentification (POST)
* **Action :** Tentative de connexion avec credentials (`thm` / `letmein`).
    * **Commande :** `POST /login` avec le corps `username=thm&password=letmein`.
    * **🛡️ Note d'Analyste :** Les données sensibles sont envoyées dans le *Body* de la requête, et non dans l'URL. Cependant, sans HTTPS (TLS), ces identifiants passent en clair sur le réseau et sont capturables via Wireshark.

> **Note :** Cet exercice démontre pourquoi la validation des entrées côté serveur est cruciale, car le client (navigateur) peut être entièrement manipulé par un attaquant.

## 🛡️ Takeaway pour l'Analyste SOC
Comprendre HTTP est la base pour lire les logs de proxy ou de WAF (Web Application Firewall). Une attaque ne se voit souvent que par une anomalie subtile dans un Header ou une séquence de codes 4xx suivie d'un 200 (Brute-force réussi).