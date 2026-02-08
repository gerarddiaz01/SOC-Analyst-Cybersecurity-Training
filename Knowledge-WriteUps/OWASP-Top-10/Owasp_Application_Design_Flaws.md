# Rapport de Lab : OWASP Top 10 2025 — Application Design Flaws

**Environnement :** Lab virtuel — Tryhackme Room OWASP Top 10 2025: Application Design Flaws

## Contexte et Architecture
Ce laboratoire est réalisé sur la plateforme TryHackMe dans un environnement virtuel contrôlé (Sandbox). L'infrastructure repose sur l'interaction entre deux machines distinctes :
* **Machine Attaquante :** Une station de travail disposant des outils d'analyse de sécurité (Navigateur, cURL, CyberChef, Terminal).
* **Machine Victime :** Un serveur cible hébergeant plusieurs applications web vulnérables. Chaque application est exposée sur un port spécifique préconfiguré (ex: 5002, 5003, etc.) pour isoler et simuler des failles de conception distinctes.

## Objectif du Lab
Ce rapport documente l'analyse et l'exploitation de quatre vulnérabilités majeures du nouvel OWASP Top 10 2025. L'approche pédagogique repose sur des exercices pratiques de type **Capture The Flag (CTF)** : chaque catégorie théorique est immédiatement suivie d'une mise en situation réelle où la vulnérabilité doit être exploitée pour récupérer un "flag".

Cette méthode permet de valider la compréhension théorique par l'action et, dans une posture d'Analyste SOC, d'identifier les indicateurs de compromission (IOCs) pour définir les mesures de mitigation adéquates.

## Outils et Technologies utilisés
* **Navigateur Web & DevTools :** Inspection du code source client et manipulation d'URL.
* **cURL :** Interaction avec les API RESTful.
* **CyberChef :** Décodage et opérations cryptographiques.
* **Python (Stack Trace) :** Analyse des retours d'erreurs applicatives.

---

## Task 1 : AS02 - Security Misconfigurations

### Contexte Théorique
Les mauvaises configurations de sécurité surviennent lorsque les systèmes, serveurs ou applications sont déployés avec des paramètres par défaut non sécurisés, des réglages incomplets ou des services exposés. Contrairement aux bugs de code, il s'agit d'erreurs dans la mise en place de l'environnement ou du réseau.

Ces erreurs créent des points d'entrée faciles pour les attaquants. Une configuration verbeuse, comme laisser le mode débogage activé en production, peut exposer des traces de la pile d'exécution (stack traces) ou des détails système critiques.

### Consigne du lab
"Accédez à l'API de gestion des utilisateurs sur le port 5002 et tentez de provoquer une erreur technique pour vérifier si l'application révèle des informations sensibles via des messages de débogage verbeux."

### Analyse et Exploitation (CTF)
J'ai commencé l'analyse en naviguant vers l'API de gestion des utilisateurs sur le port 5002. La documentation de l'API indique explicitement une règle de validation : "User ID must be numeric".

![Documentation de l'API User Management](../images/OWASP/Captura%20de%20pantalla%202026-02-08%20152616.png)

Dans un premier temps, j'ai vérifié le comportement normal de l'application en soumettant un ID valide (`123`). L'application a répondu correctement avec les données JSON de l'utilisateur, confirmant que le service est fonctionnel.

![Réponse JSON normale pour l'ID 123](../images/OWASP/Captura%20de%20pantalla%202026-02-08%20152644.png)

Pour tester la robustesse de la configuration, j'ai adopté une approche offensive visant à provoquer une erreur non gérée. Si les développeurs ont laissé le "Debug Mode" actif, provoquer un crash de l'application pourrait révéler des secrets internes au lieu d'afficher une page d'erreur générique.

J'ai intentionnellement désobéi aux instructions en remplaçant l'ID numérique par une chaîne de caractères textuelle (`abcd`) dans l'URL : `http://10.65.184.179:5002/api/user/abcd`.

L'application n'a pas su gérer cette entrée inattendue de manière sécurisée. Au lieu d'une erreur 404 ou 400 standard, le serveur a renvoyé une réponse contenant un objet JSON `debug_info`. Cette réponse verbeuse a exposé une trace d'erreur Python (Traceback) et, plus critique encore, a révélé le flag directement dans le message d'exception.

![Erreur verbeuse révélant le flag et le traceback](../images/OWASP/Captura%20de%20pantalla%202026-02-08%20152702.png)

Le flag récupéré dans les logs d'erreur est : `THM{V3RB0S3_3RR0R_L34K}`.

### Implications pour un Analyste SOC

En tant qu'analyste SOC, cet exercice met en lumière plusieurs points de vigilance :

1.  **Désactivation du Mode Debug :** Il est impératif de s'assurer que les environnements de production ont les modes de débogage désactivés (ex: `FLASK_DEBUG=0` ou `DEBUG=False` dans Django/Flask). Les messages d'erreur présentés à l'utilisateur final doivent être génériques et ne jamais révéler la structure interne du code.
2.  **Surveillance des Logs (Code 500) :** Une augmentation soudaine des erreurs `500 Internal Server Error` provenant d'une même adresse IP peut indiquer une tentative de fuzzing ou de scanning de vulnérabilités. Ces événements doivent générer des alertes.
3.  **Sanitisation des Sorties :** Les mécanismes de gestion des erreurs doivent intercepter les exceptions et les logger en interne pour les développeurs, sans les renvoyer dans la réponse HTTP vers le client.

---

## Task 2 : AS03 - Software Supply Chain Failures

### Contexte Théorique
Les défaillances de la chaîne logistique logicielle (Supply Chain Failures) surviennent lorsque des applications dépendent de composants, librairies ou services tiers qui sont compromis, obsolètes ou non vérifiés. Contrairement à une vulnérabilité dans le code source propriétaire, la faille réside ici dans les dépendances importées.

Les attaquants exploitent ces maillons faibles pour injecter du code malveillant ou contourner les sécurités, comme l'a démontré l'attaque SolarWinds en 2021. Dans le cadre de ce lab, le scénario simule l'utilisation d'une librairie obsolète nommée `lib/vulnerable_utils.py` contenant une fonctionnalité de test ("backdoor") oubliée.

### Consigne du lab
"Connectez-vous au service de traitement de données sur le port 5003 et exploitez une bibliothèque tierce obsolète pour déclencher son mode de débogage caché et extraire les secrets de configuration."

### Analyse et Exploitation (CTF)
J'ai accédé au service de traitement de données sur le port **5003**. La page d'accueil présente une documentation API succincte pour un endpoint RESTful.

**Reconnaissance :**
En analysant la documentation, j'ai identifié les contraintes techniques pour interagir avec le service :
* **Endpoint :** `/api/process`
* **Méthode :** `POST`
* **Format :** JSON
* **Paramètre requis :** Un champ `data`.

![Documentation API du Data Processing Service](../images/OWASP/Captura%20de%20pantalla%202026-02-08%20153724.png)

Le challenge indique que la librairie vulnérable écoute un mot-clé spécifique pour déclencher son mode de débogage interne. L'indice fourni sur les explications du Capture The Flag ("Can you `debug` it?") suggère fortement que la chaîne de caractères `debug` est le déclencheur.

**Exploitation :**
Contrairement à la tâche précédente, je ne pouvais pas utiliser la barre d'adresse du navigateur car il s'agit d'une requête `POST`. J'ai donc utilisé l'outil en ligne de commande `curl` depuis la machine attaquante pour forger une requête HTTP spécifique.

J'ai construit la commande suivante pour envoyer le payload JSON `{"data": "debug"}` en précisant le header `Content-Type` approprié :

```bash
curl -X POST [http://10.65.184.179:5003/api/process](http://10.65.184.179:5003/api/process) -H "Content-Type: application/json" -d '{"data": "debug"}'
```

Dès l'envoi de la commande, le serveur a traité le mot-clé "debug" via la librairie obsolète. Au lieu de traiter la donnée normalement, la librairie a renvoyé la configuration interne du service, incluant des secrets critiques.

![Exécution de la commande curl et récupération du flag](../images/OWASP/Captura%20de%20pantalla%202026-02-08%20154515.png)

La réponse JSON contient le token administrateur, une clé secrète interne et le flag : `THM{SUPPLY_CH41N_VULN3R4B1L1TY}`.

### Implications pour un Analyste SOC

Pour contrer les risques liés à la chaîne logistique, plusieurs mesures défensives s'imposent :

1.  **Analyse de Composition Logicielle (SCA) :** Il est crucial d'utiliser des outils de SCA (comme OWASP Dependency-Check ou Snyk) dans les pipelines CI/CD pour scanner automatiquement les dépendances et identifier les librairies obsolètes (CVE connues) avant le déploiement. Si le SOC ne gère pas la CI/CD, il doit en revanche être informé des nouvelles vulnérabilités (CVE) critiques publiées pour rechercher rétroactivement des traces d'exploitation dans les logs (Threat Hunting).
2.  **Inventaire et SBOM :** Maintenir un inventaire à jour des composants logiciels (Software Bill of Materials - SBOM) permet de savoir rapidement si une application utilise une librairie compromise lorsqu'une vulnérabilité est rendue publique.
3.  **Surveillance des Comportements Anormaux :** Côté SOC, une réponse HTTP contenant des clés explicites (`admin_token`, `internal_secret`) ou des payloads entrants atypiques (comme un simple mot-clé de debug dans un champ de données) doit déclencher une alerte DLP (Data Loss Prevention) ou WAF.

---

## Task 3 : AS04 - Cryptographic Failures

### Contexte Théorique
Les défaillances cryptographiques surviennent lorsque le chiffrement est absent, mal implémenté ou utilise des algorithmes obsolètes. Cela inclut l'utilisation de clés codées en dur (hard-coded), une gestion défaillante des secrets ou l'usage de modes de chiffrement faibles (comme ECB).

Ces failles permettent aux attaquants de déchiffrer des données sensibles (mots de passe, PII, tokens) qui devraient rester confidentielles. Ce challenge illustre le cas classique où la cryptographie est implémentée, mais où les clés nécessaires au déchiffrement sont laissées "sous le paillasson" (côté client).

### Consigne du lab
"Analysez le code source du "Secure Document Viewer" sur le port 5004 pour identifier les faiblesses cryptographiques côté client et retrouver la clé nécessaire au déchiffrement du fichier confidentiel."

### Analyse et Exploitation (CTF)
J'ai accédé au "Secure Document Viewer" sur le port **5004**. L'application affiche un message chiffré et indique que la fonctionnalité de déchiffrement est temporairement indisponible, nécessitant une clé autorisée.

![Interface du Secure Document Viewer](../images/OWASP/Captura%20de%20pantalla%202026-02-08%20155338.png)

**Reconnaissance (Code Review) :**
Puisque l'application est censée déchiffrer le document dans le navigateur, la logique de déchiffrement doit nécessairement se trouver côté client. J'ai inspecté le code source de la page (Ctrl+U) et identifié l'appel à un script externe suspect : `/static/js/decrypt.js`.

![Inspection du code source HTML](../images/OWASP/Captura%20de%20pantalla%202026-02-08%20160044.png)

**Identification des Secrets :**
En ouvrant ce fichier JavaScript, j'ai immédiatement repéré la section de configuration. Le développeur a commis l'erreur critique de laisser la clé symétrique et le mode de chiffrement en clair dans le code source accessible à tous.

* **Clé (Secret Key) :** `"my-secret-key-16"`
* **Algorithme :** AES (induit par la taille de clé 128 bits -> 16 caractères x 8 bits = 128 bits)
* **Mode :** `ECB` (Electronic Codebook - mode non sécurisé car il ne masque pas les motifs de données).

![Découverte de la clé codée en dur dans le JS](../images/OWASP/Captura%20de%20pantalla%202026-02-08%20160152.png)

**Déchiffrement (CyberChef) :**
Avec ces éléments, j'ai utilisé CyberChef pour reproduire le processus de déchiffrement. J'ai construit la "recette" suivante :
1.  **From Base64 :** Le texte chiffré affiché sur la page web est encodé en Base64 pour le transport. Il faut d'abord le décoder pour obtenir les données brutes (Raw).
2.  **AES Decrypt :**
    * Key : `my-secret-key-16` (Format UTF8).
    * Mode : `ECB`.
    * Input : `Raw`.

![Déchiffrement réussi avec CyberChef](../images/OWASP/Captura%20de%20pantalla%202026-02-08%20161108.png)

Le résultat en clair révèle le mot de passe administrateur et le flag : `THM{CRYPTO_FAILURE_H4RDC0D3D_K3Y}`.

### Implications pour un Analyste SOC

Pour prévenir ces fuites de données, les règles suivantes doivent être appliquées :

1.  **Gestion des Secrets (Secrets Management) :** Aucun secret (clés API, clés de chiffrement, mots de passe) ne doit jamais être codé en dur dans le code source, et encore moins côté client (Frontend). Il faut utiliser des gestionnaires de secrets (Vaults) et charger ces variables d'environnement côté serveur uniquement.
2.  **Architecture Cryptographique :** Le déchiffrement de données sensibles ne doit jamais être confié au client (navigateur), car cela implique de lui fournir la clé. Le traitement cryptographique doit rester côté serveur (Backend).
3.  **Algorithmes Robustes :** Le mode ECB est à proscrire car il révèle des répétitions dans les données. Il faut privilégier des modes authentifiés comme AES-GCM (Galois/Counter Mode).
---

## Task 4 : AS06 - Insecure Design

### Contexte Théorique
La conception non sécurisée (Insecure Design) diffère des vulnérabilités d'implémentation (bugs de code). Elle survient lorsque des failles logiques ou architecturales sont présentes dès la conception du système, souvent dues à l'absence de modélisation des menaces (Threat Modeling).

Un exemple classique est la confiance aveugle accordée au côté client ou l'hypothèse erronée qu'une URL non publiée restera secrète ("Security by Obscurity"). Dans le contexte de l'IA, cela inclut également la confiance implicite dans les modèles sans garde-fous. Contrairement à un bug, une conception non sécurisée ne se "patche" pas facilement ; elle nécessite souvent une refonte de l'architecture.

### Consigne du lab
"Accédez à l'application SecureChat sur le port 5005 et contournez la restriction d'affichage 'mobile uniquement' pour interagir directement avec l'API backend non sécurisée et exfiltrer les messages privés de l'administrateur."

### Analyse et Exploitation (CTF)

**Reconnaissance :**
En naviguant sur l'application web, je suis tombé sur une page d'accueil invitant uniquement à télécharger l'application mobile. Le message "SecureChat is designed exclusively for mobile devices" suggère une hypothèse de conception des développeurs : ils pensent que seuls les utilisateurs de l'application officielle pourront accéder au service.

![Page d'accueil de SecureChat](../images/OWASP/Captura%20de%20pantalla%202026-02-08%20163007.png)

**Découverte de l'API (API Fuzzing) :**
Sachant qu'une application mobile n'est qu'une interface (Frontend) communiquant avec un serveur (Backend) via une API, j'ai tenté de localiser les endpoints de cette API. J'ai testé des chemins standards (Fuzzing manuel) comme `/api/users`.

L'hypothèse des développeurs s'est révélée fausse : l'API est exposée publiquement et ne vérifie pas l'origine de la requête. J'ai pu récupérer la liste complète des utilisateurs (incluant l'administrateur) au format JSON.

![Liste des utilisateurs exposée via l'API](../images/OWASP/Captura%20de%20pantalla%202026-02-08%20163139.png)

**Exploitation (IDOR) :**
Une fois les noms d'utilisateurs connus (`admin`, `alice`, `bob`), j'ai cherché à accéder aux messages privés. La faille de conception ici est l'absence de contrôle d'accès au niveau de l'objet (IDOR - Insecure Direct Object Reference) : le système ne vérifie pas si l'utilisateur qui fait la requête est autorisé à voir les données demandées.

J'ai construit l'URL `http://10.65.184.179:5005/api/messages/admin`. L'API m'a renvoyé le contenu des messages privés de l'administrateur sans aucune authentification.

![Accès aux messages privés de l'admin](../images/OWASP/Captura%20de%20pantalla%202026-02-08%20163237.png)

Le message système contient le flag : `THM{1NS3CUR3_D35IGN_4SSUMPT10N}`.

### Implications pour un Analyste SOC

Pour pallier ces défauts de conception, une approche "Secure by Design" est nécessaire :

1.  **Architecture Zero Trust :** Ne jamais faire confiance au client (Frontend). L'API Backend doit systématiquement authentifier et autoriser chaque requête, quelle que soit son origine supposée (Mobile ou Web).
2.  **Modélisation des Menaces :** Avant même d'écrire le code, il faut identifier les scénarios d'abus (Abuse Cases). Ici, le scénario "Un utilisateur accède à l'API sans passer par l'app mobile" aurait dû être anticipé.
3.  **Surveillance API :** Côté SOC, il faut surveiller les requêtes API directes qui ne présentent pas les en-têtes (User-Agent) typiques de l'application mobile officielle, ainsi que l'énumération séquentielle d'objets (tentatives d'accès à `/api/messages/user1`, `/api/messages/user2`, etc.).

---
*Fin du rapport*










