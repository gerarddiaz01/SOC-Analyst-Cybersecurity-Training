# Phase 3 - Durcissement de l'Infrastructure (Hardening)

**Environnement :** Home Lab virtuel sur Proxmox pour le projet Iron4Software — Formation Analyste SOC - CyberUniversity (Liora x Sorbonne).

## Objectif du Lab
L'audit offensif de la Phase 2 a mis en lumière un constat sans appel : l'infrastructure était compromise de bout en bout, non pas à cause d'une faille zero-day sophistiquée, mais à cause d'une accumulation de négligences de configuration. Le SIEM enregistrait tout, mais le SOC était aveugle, faute de règles de détection. Avant de pouvoir créer des alertes de haute fidélité, je dois refermer les portes que j'ai moi-même ouvertes.

Cette phase est le pivot défensif du projet. Je bascule définitivement de la posture Red Team vers la posture Blue Team pour appliquer un durcissement en profondeur organisé en trois couches successives : le périmètre réseau (pfSense), l'hôte (Windows Server 2019) et le pipeline de supervision (Splunk). Chaque mesure appliquée répond directement à une vulnérabilité documentée en Phase 2, transformant progressivement ce laboratoire "Vulnerable-by-Design" en une forteresse supervisée, prête pour la création des alertes SOC de la Phase 4.

## Outils et Technologies
- **Pare-feu périmétrique :** pfSense (interface Web, gestion des règles WAN/LAN).
- **Hardening OS :** Windows Defender Firewall avec fonctions avancées de sécurité.
- **Politique de domaine :** Gestion des stratégies de groupe (GPMC / `gpmc.msc`), `gpupdate /force`.
- **Sécurité des identifiants :** Credential Guard (VBS - Virtualization Based Security).
- **Transfert de fichiers :** WinSCP (SFTP), OpenSSH Server.
- **Chiffrement des flux SIEM :** Splunk TLS/SSL (`inputs.conf`, `outputs.conf`, certificats `.pem`).
- **Contrôle des accès fichiers :** ACL NTFS (onglet Sécurité, désactivation de l'héritage).
- **Framework MITRE ATT&CK :** T1562.004 (Disable or Modify System Firewall), T1110.001 (Brute Force - contre-mesure), T1003.001 (OS Credential Dumping - contre-mesure).

## 1. Couche Réseau : Verrouillage du Périmètre pfSense

### A. Suppression de la règle "Allow All" (WAN)

La première faille exploitée en Phase 2 était architecturale : une règle WAN autorisant l'intégralité du trafic entrant permettait à ma machine Kali, en ajoutant simplement une route statique, de joindre directement les serveurs internes sans aucune friction. C'est la première porte à condamner.

Depuis une machine du LAN interne (Windows Server 2019 ou Windows 10), j'accède à l'interface d'administration de pfSense via `https://192.168.3.1`. L'interface est intentionnellement accessible uniquement depuis le LAN et non depuis le WAN, ce qui constitue en soi une bonne pratique d'hygiène de gestion.

Dans le menu `Firewall > Rules`, onglet `WAN`, deux règles sont visibles :

- **La règle à supprimer :** La règle `IPv4 *` avec Source `*`, Destination `*`, Port `*`. C'est elle qui jouait le rôle de "tapis rouge" pour l'attaquant.
- **La règle à conserver :** La règle `NAT Exposition Serveur Web Vulnérable`, qui autorise uniquement le trafic TCP entrant vers `192.168.3.11` sur le port 80. Cette règle est spécifique et justifiée ; elle sera durcie dans une étape ultérieure.

Je supprime la règle permissive via l'icône poubelle, puis je clique sur **Apply Changes** pour que le rechargement des règles soit effectif immédiatement.

> **Contexte SOC & Blue Team :**
> Cette suppression illustre le principe fondamental du "Least Privilege" appliqué au réseau : tout ce qui n'est pas explicitement autorisé doit être refusé par défaut (Deny by Default). Un pare-feu périmétrique avec une règle "Allow All" n'est pas un pare-feu, c'est un routeur. La journalisation des tentatives de connexion bloquées sur l'interface WAN constitue une source de renseignement précieuse pour détecter les phases de reconnaissance (MITRE T1595) lors de la Phase 4.

### B. Validation technique du durcissement périmétrique (Côté Kali)

La suppression d'une règle doit toujours être vérifiée par un test négatif côté attaquant. Je rallume la machine Kali, je m'assure que la route statique de la Phase 2 est toujours présente, puis je tente de joindre le Contrôleur de Domaine :

```bash
sudo ip route add 192.168.3.0/24 via 192.168.50.7
ping -c 4 192.168.3.10
```

Le résultat est un `100% packet loss`. Même si la table de routage de Kali pointe toujours vers le pfSense, ce dernier reçoit les paquets sur son interface WAN et, ne trouvant aucune règle d'autorisation correspondante, les rejette immédiatement. Le mouvement latéral direct est officiellement brisé.

### C. Restriction du RDP au niveau LAN (pfSense)

En Phase 2, une fois dans le LAN, l'attaquant pouvait librement utiliser le protocole RDP (port 3389) pour rebondir de machine en machine. La défense périmétrique ne suffit pas si l'intérieur du réseau est plat et sans cloisonnement. Je crée donc deux règles dans `Firewall > Rules > LAN` :

**Règle 1 (Pass) — Autorisation chirurgicale :**
- Action : `Pass`
- Protocol : `TCP`
- Source : `Single host` → `192.168.3.2` (poste client Windows 10 légitime)
- Destination : `Single host` → `192.168.3.10` (Windows Server 2019)
- Port de destination : `MS RDP (3389)`
- Description : `Autorise RDP uniquement depuis le poste Admin`

**Règle 2 (Block) — Blocage du reste :**
- Action : `Block`
- Protocol : `TCP`
- Source : `Any`
- Destination : `Single host` → `192.168.3.10`
- Port de destination : `MS RDP (3389)`
- Description : `Bloque tout autre accès RDP vers le serveur`

L'ordre des règles est critique dans pfSense : les règles sont évaluées de haut en bas et la première correspondance l'emporte. La règle `Pass` spécifique au poste Admin doit impérativement se trouver au-dessus de la règle `Block` générale.

> **Contexte SOC & Blue Team :**
> Cette segmentation LAN est une application directe du concept de "Zero Trust Network" : même un équipement interne ne doit pas avoir accès à tout par défaut. En opérationnel, l'accès RDP aux serveurs d'infrastructure critique se fait exclusivement depuis des bastions d'administration (Jump Hosts) dont les IPs sont connues et listées. Toute tentative de connexion RDP provenant d'une source non autorisée vers le serveur sera automatiquement bloquée et journalisée par pfSense, générant un IoC exploitable dans Splunk.

## 2. Couche Système : Durcissement de l'Hôte (Endpoint Hardening)

### A. Réactivation du Pare-feu Windows Defender (WS2019)

En Phase 1, j'avais désactivé le pare-feu local de Windows Server 2019 pour simuler une négligence administrative. Cette désactivation avait eu pour conséquence directe de permettre le scan de ports et la connexion RDP depuis n'importe quelle source, même après une hypothétique compromission du pfSense. La défense en profondeur exige qu'une deuxième barrière existe au niveau de l'hôte.

Sur le Windows Server 2019, j'ouvre le "Pare-feu Windows Defender avec fonctions avancées de sécurité", puis `Propriétés du pare-feu Windows Defender`. Pour chacun des trois profils (Domaine, Privé, Public), je passe l'état du pare-feu sur **Activé (recommandé)**, avec les connexions entrantes configurées sur **Bloquer (par défaut)**. Je valide par `Appliquer` puis `OK`.

Les trois profils affichent désormais le bouclier vert confirmant leur activation.

> **Contexte SOC & Blue Team :**
> La réactivation du pare-feu hôte illustre le principe de "Défense en Profondeur" (Defense in Depth). Si le périmètre (pfSense) venait à céder de nouveau — via un vecteur non anticipé — le pare-feu local constituerait un dernier rempart contre les tentatives de scan ou d'exploitation. En opérationnel, les règles de pare-feu hôte sont elles-mêmes distribuées et appliquées via GPO pour garantir leur uniformité et empêcher qu'un administrateur local ne les désactive manuellement.

### B. GPO Anti-Brute-Force : Politique de Verrouillage de Compte

L'attaque `crackmapexec` de la Phase 2 avait réussi précisément parce que le seuil de verrouillage du compte était fixé à 0 (désactivé), permettant des dizaines de tentatives successives sans aucun blocage. Je corrige cela directement dans la stratégie de domaine.

Sur le Windows Server 2019, j'ouvre `gpmc.msc` (Gestion des stratégies de groupe), je clique droit sur `Default Domain Policy` et je sélectionne `Modifier`. Je navigue vers :

`Configuration ordinateur > Stratégies > Paramètres Windows > Paramètres de sécurité > Stratégies de comptes > Stratégie de verrouillage de compte`

Je configure le paramètre suivant :
- **Seuil de verrouillage de compte :** `5 tentatives` (Windows propose automatiquement une durée de verrouillage de 10 minutes, que j'accepte).

La GPO affiche maintenant :
- Seuil de verrouillage : `5 tentatives d'ouvertures de session`
- Durée de verrouillage : `10 minutes`
- Réinitialisation du compteur : `10 minutes`

Cette mesure neutralise techniquement `crackmapexec` : à la 6ème tentative erronée, le compte `Administrateur` est automatiquement verrouillé par l'OS, rendant la suite de l'attaque par dictionnaire inopérante.

> **Contexte SOC & Blue Team :**
> La politique de verrouillage de compte est un mécanisme de détection autant que de protection. En Phase 4, je créerai une alerte Splunk qui se déclenche dès la détection de l'Event ID `4740` (Compte verrouillé). En corrélant cet événement avec les Event ID `4625` qui l'ont précédé, je serai en mesure d'identifier non seulement la tentative de brute-force, mais aussi sa source réseau exacte, transformant ainsi une mesure défensive passive en un capteur actif pour le SOC.

### C. GPO d'Audit du Système de Fichiers (Event ID 4663)

En Phase 2, le ransomware a chiffré les données du dossier `PRIVATE` et Splunk n'a rien vu, car l'audit des accès aux objets n'était pas configuré. Pour que le SOC puisse détecter une telle manipulation à l'avenir, je dois d'abord autoriser Windows à générer les logs correspondants, puis lui désigner précisément les dossiers à surveiller.

**Étape 1 — Activation de la politique d'audit dans la GPO :**

Toujours dans l'éditeur de la `Default Domain Policy`, je navigue vers :

`Configuration ordinateur > Stratégies > Paramètres Windows > Paramètres de sécurité > Configuration avancée de la stratégie d'audit > Stratégies d'audit > Accès à l'objet`

Je double-clique sur "Auditer le système de fichiers" et je coche **Configurer les événements d'audit suivants**, puis les cases **Succès** et **Échec**. Je valide.

**Étape 2 — Application immédiate des stratégies :**

Pour ne pas attendre le prochain cycle de rafraîchissement des GPO (qui peut aller jusqu'à 90 minutes sur un domaine), je force l'application immédiate depuis une invite de commande administrateur :

```cmd
gpupdate /force
```

La sortie confirme : `La mise à jour de la stratégie d'ordinateur s'est terminée sans erreur.`

**Étape 3 — Ciblage chirurgical du dossier `PRIVATE` :**

Activer la GPO ne suffit pas : elle autorise Windows à générer des logs de fichiers, mais ne lui indique pas quels répertoires surveiller. Appliquer cet audit à l'ensemble du disque génèrerait un bruit de logs ingérable. Je dois donc cibler précisément le dossier sensible.

Dans l'Explorateur Windows, je fais un clic droit sur `C:\PRIVATE - NE PAS RENTRER !` → `Propriétés` → onglet `Sécurité` → `Avancé` → onglet `Audit`. Je clique sur `Ajouter`, puis `Sélectionner un principal` et j'entre `Tout le monde`. Dans la liste des autorisations avancées, je coche :
- **Écriture** (pour détecter toute modification ou chiffrement de fichier).
- **Suppression** et **Supprimer les sous-dossiers et les fichiers** (pour détecter l'effacement des originaux après chiffrement).

Je valide en cliquant `OK` trois fois.

> **Contexte SOC & Blue Team :**
> Ce ciblage est la configuration prérequise indispensable pour créer l'alerte anti-ransomware en Phase 4. Sans lui, l'Event ID `4663` (Accès à un objet) ne sera jamais généré pour ce dossier. Avec lui, chaque modification dans `PRIVATE` produira un log contenant le nom du fichier concerné, le compte ayant effectué l'action et l'heure précise. La corrélation d'un pic de ces événements sur un intervalle court — signature caractéristique d'un chiffrement en masse par ransomware — sera l'une des alertes les plus critiques de notre SIEM.

### D. Credential Guard : Protection contre le Vol d'Identifiants en Mémoire

La Phase 2 s'est conclue par la compromission du compte `Administrateur`. Dans un scénario réel, un attaquant disposant de ce niveau de privilèges lancerait immédiatement un outil tel que Mimikatz pour extraire les hashs NTLM de tous les comptes connectés depuis la mémoire du processus `LSASS`. Ces hashs permettent ensuite des attaques de type "Pass-the-Hash" pour se propager latéralement vers d'autres systèmes du domaine, sans même connaître les mots de passe en clair.

Pour contrer cela, j'active le **Credential Guard** via GPO. Cette fonctionnalité (disponible sur Windows Server 2016 et ultérieur) repose sur la Virtualization Based Security (VBS) : les secrets d'authentification (hashs, tickets Kerberos) sont déplacés dans un micro-noyau sécurisé, `LSAIso.exe`, isolé du reste de l'OS par l'hyperviseur. Même un processus tournant avec les droits `SYSTEM` ne peut pas lire cette zone mémoire.

Depuis `gpmc.msc`, je modifie la `Default Domain Policy` et navigue vers :

`Configuration ordinateur > Stratégies > Modèles d'administration > Système > Device Guard`

Je double-clique sur "Activer la sécurité basée sur la virtualisation", je bascule sur **Activé**, puis dans le panneau "Options" :
- **Configuration du Credential Guard :** `Activé avec le verrouillage UEFI`

L'option "verrouillage UEFI" est la plus robuste : elle empêche la désactivation de Credential Guard sans accès physique à la machine pour modifier les paramètres UEFI, rendant ainsi la désactivation par un attaquant distant impossible même avec les droits `Administrateur`.

> **Contexte SOC & Blue Team :**
> Le Credential Guard ne génère pas directement d'événements dans Splunk, mais il agit comme un filet de sécurité silencieux. Si un attaquant compromet un compte Admin et tente d'exécuter Mimikatz, l'outil retournera des hashs vides ou des erreurs, rendant toute tentative de mouvement latéral par Pass-the-Hash inopérante. En Phase 5 (re-test), cette mesure sera l'une des preuves concrètes de l'efficacité du durcissement.

### E. Sauvegarde Immuable : Isolation des Données de Récupération

La simulation de ransomware en Phase 2 a mis en évidence l'absence totale de plan de reprise d'activité : si les données avaient été réellement chiffrées, il n'y aurait eu aucune sauvegarde accessible pour restaurer l'environnement. Je crée donc une zone sanctuaire pour les sauvegardes en appliquant le principe du moindre privilège au niveau des ACL NTFS.

Je crée le répertoire `C:\BACKUPS_SECURE`, puis j'ouvre ses propriétés (onglet `Sécurité` → `Avancé`) et j'effectue les opérations suivantes :

1. **Désactivation de l'héritage :** Je clique sur "Désactiver l'héritage" et je choisis de supprimer toutes les permissions héritées. Cette étape est fondamentale : sans elle, les groupes parents (comme `Utilisateurs authentifiés`) conserveraient leurs droits par héritage, rendant le cloisonnement inopérant.

2. **Nettoyage des ACL :** Je supprime tous les groupes d'utilisateurs génériques présents dans la liste des permissions.

3. **Configuration finale :** Seuls les comptes `SYSTEM` et `Administrateurs` conservent un accès complet.

**Analyse du compromis sécurité/praticité :**
Un durcissement maximal consisterait à retirer également l'accès `Administrateurs`, ne laissant que `SYSTEM`. Dans ce cas, même un Administrateur humain recevrait un "Accès refusé" depuis l'Explorateur Windows. Pour ce lab, j'ai conservé cet accès pour faciliter les opérations. En production, la méthode professionnelle consiste à utiliser un compte de service dédié (`svc-backup`), le seul autorisé en écriture sur ce dossier, et à recourir à des outils comme `psexec` pour agir en tant que `SYSTEM` de manière traçable si une restauration manuelle est nécessaire.

> **Contexte SOC & Blue Team :**
> La valeur de cette mesure est double. D'une part, si un ransomware s'exécute dans le contexte d'un utilisateur compromis, il sera bloqué par les ACL avant même d'atteindre ce dossier. D'autre part, si un attaquant disposant de droits Admin tente de modifier les ACL pour accéder aux sauvegardes, cette action génèrera un Event ID `4670` (Modification des permissions d'un objet), un indicateur de compromission que je pourrai surveiller dans Splunk comme signal d'alarme critique d'une attaque en phase finale.

## 3. Couche Surveillance : Sécurisation du Pipeline de Logs (TLS Splunk)

### A. Contexte et Enjeu

Jusqu'à présent, les Universal Forwarders envoyaient les journaux d'événements Windows vers le serveur Splunk en clair sur le port `9997`. Concrètement, n'importe quel attaquant ayant un accès réseau interne pouvait lancer Wireshark et lire en temps réel le contenu des logs en transit : noms d'utilisateurs, noms de machines, EventCodes. Pire encore, un attaquant sophistiqué pourrait injecter de faux événements pour manipuler les alertes du SOC (Spoofing). Je dois donc chiffrer ce pipeline.

### B. Préparation des Certificats sur le Serveur Splunk (Ubuntu)

Je me connecte en terminal sur la VM Splunk (Ubuntu, `192.168.3.20`). Splunk fournit par défaut des certificats auto-signés dans `/opt/splunk/etc/auth/`. Plutôt que d'utiliser directement ces fichiers partagés avec l'interface web, je crée un dossier dédié pour isoler proprement les certificats de transport :

```bash
sudo su
cd /opt/splunk/etc/auth/
sudo mkdir my_certs
sudo cp /opt/splunk/etc/auth/cacert.pem /opt/splunk/etc/auth/my_certs/
sudo cp /opt/splunk/etc/auth/server.pem /opt/splunk/etc/auth/my_certs/
```

Cette séparation respecte le principe de bonne hygiène opérationnelle : on ne mélange pas les certificats de l'interface d'administration web avec les certificats utilisés pour le transport des données de supervision.

### C. Activation du Port TLS sur l'Indexer Splunk

Je configure Splunk pour écouter les connexions chiffrées sur un nouveau port dédié (`9998`), en parallèle du port existant (`9997`) que je ne coupe pas immédiatement pour ne pas interrompre le flux de logs pendant la migration.

Via l'interface Web de Splunk (`Settings > Forwarding and receiving > Configure receiving`), je crée un nouveau port de réception `9998`.

Ensuite, en ligne de commande, je modifie le fichier `inputs.conf` pour activer le SSL sur ce port :

```bash
nano /opt/splunk/etc/system/local/inputs.conf
```

J'ajoute les directives suivantes :

```ini
[splunktcp-ssl:9998]
disabled = 0

[SSL]
rootCA = /opt/splunk/etc/auth/my_certs/cacert.pem
serverCert = /opt/splunk/etc/auth/my_certs/server.pem
password = password
```

Je redémarre Splunk pour prendre en compte la configuration :

```bash
sudo /opt/splunk/bin/splunk restart
```

### D. Transfert des Certificats vers le Forwarder Windows (WinSCP + SSH)

Pour que la poignée de main TLS (handshake) fonctionne, le Universal Forwarder Windows doit disposer du même certificat CA (`cacert.pem`) pour vérifier l'identité du serveur Splunk.

Le serveur SSH n'étant pas installé par défaut sur l'Ubuntu, je l'installe préalablement :

```bash
sudo apt update && sudo apt install openssh-server -y
sudo systemctl status ssh
```

Le service affiche `active (running)`. Je corrige ensuite les permissions pour permettre la navigation SFTP dans le dossier des certificats :

```bash
sudo chmod 755 /opt/splunk/etc/auth
sudo chmod -R 755 /opt/splunk/etc/auth/my_certs
```

Depuis le Windows Server 2019, j'utilise WinSCP (protocole SFTP, port 22) pour me connecter à l'Ubuntu Splunk et transférer les deux fichiers `cacert.pem` et `server.pem` vers :

`C:\Program Files\SplunkUniversalForwarder\etc\auth\my_certs\`

**Troubleshooting — Erreur de connexion WinSCP :**
Lors de la première tentative de connexion, WinSCP retournait une erreur `Network error: Connection to "192.168.3.20" refused`. Le message précisait que le serveur écoutait sur FTP et non SFTP. La cause était simple : le daemon `openssh-server` n'était pas installé sur l'Ubuntu, qui n'offrait donc aucun service SSH actif. L'installation du paquet et le démarrage du service ont immédiatement résolu le problème. Cette erreur illustre un point SOC important : la présence d'un service n'est jamais garantie, même sur une machine qu'on administre — la vérification de l'état des services critiques doit être intégrée aux routines de supervision.

### E. Configuration du Forwarder Windows pour le Flux Chiffré

Sur le Windows Server 2019, j'ouvre le Bloc-notes en tant qu'Administrateur et je modifie le fichier :

`C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf`

Je remplace la configuration existante (pointant vers le port `9997` non chiffré) par la configuration SSL :

```ini
[tcpout]
defaultGroup = splunk_ssl

[tcpout:splunk_ssl]
server = 192.168.3.20:9998
clientCert = $SPLUNK_HOME\etc\auth\my_certs\server.pem
sslRootCAPath = $SPLUNK_HOME\etc\auth\my_certs\cacert.pem
sslPassword = password
sslVerifyServerCert = false
```

Je redémarre le service Forwarder depuis PowerShell (en Admin) :

```powershell
Restart-Service SplunkForwarder
```

### F. Validation du Tunnel Chiffré

Pour confirmer que les logs arrivent bien via le nouveau canal sécurisé, j'interroge Splunk en filtrant sur le hostname du Windows Server :

```spl
index=main host=WIN-HKVM4FR00PS
```

Les 11 336 événements s'affichent normalement. Pour l'analyste qui regarde le tableau de bord Splunk, le résultat est visuellement identique. C'est précisément le point clé : le chiffrement est transparent pour l'utilisateur final, mais radical sur le plan de la sécurité du transport.

> **Contexte SOC & Blue Team (L'enveloppe transparente vs le coffre blindé) :**
> Avant cette configuration, les logs voyageaient comme une lettre dans une enveloppe transparente : lisibles par quiconque sur le réseau. Un attaquant avec Wireshark pouvait intercepter en temps réel les noms d'utilisateurs, les EventCodes et même les traces de ses propres actions pour anticiper les détections. Après activation du TLS sur le port `9998`, les paquets capturés ne contiennent plus que du texte chiffré illisible. Le chiffrement résout également le problème d'usurpation (Spoofing) : grâce aux certificats, le Forwarder est certain de parler au vrai serveur Splunk, et non à un faux indexeur qu'un attaquant aurait pu mettre en place pour absorber et modifier les logs avant leur transmission.

## Implications pour un Analyste SOC

À l'issue de cette phase de durcissement, l'infrastructure Iron4Software n'est plus la même qu'au début de ce projet. Chaque vulnérabilité identifiée et documentée lors de l'audit offensif a reçu une réponse technique précise et vérifiable.

Le bilan des quatre couches de sécurité désormais en place est le suivant :

- **Périmètre réseau :** La règle "Allow All" est supprimée. Le pivot direct depuis le WAN est impossible. Le RDP vers le Contrôleur de Domaine est restreint au seul poste d'administration légitime via une règle LAN ciblée.
- **Hôte (Endpoint) :** Le pare-feu Windows est réactivé sur tous les profils. La politique de verrouillage de compte (5 tentatives) neutralise toute attaque par brute-force. Le Credential Guard isole les secrets d'authentification dans une enclave mémoire inatteignable, même par un administrateur compromis.
- **Données sensibles :** L'audit NTFS sur le dossier `PRIVATE` est actif — la moindre tentative de modification ou de suppression générera un Event ID `4663`. Le dossier `BACKUPS_SECURE` est protégé par des ACL restrictives qui rendront une attaque ransomware inopérante sur les données de récupération.
- **Pipeline SIEM :** Le flux de logs entre les Forwarders et l'Indexer Splunk transite désormais via un tunnel TLS sur le port `9998`, éliminant les risques d'interception et d'injection de faux logs.

Ce durcissement constitue le socle indispensable sur lequel la Phase 4 va s'appuyer. Il est maintenant possible de créer des règles de détection et des alertes de haute fidélité dans la certitude que la télémétrie collectée est intègre, que son transport est sécurisé, et que les comportements anormaux qu'elle va capturer sont réels.

---
*Fin du rapport de Lab.*