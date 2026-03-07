# Phase 2 - Mouvement Latéral et Compromission d'Identifiants (Brute-Force)

**Environnement :** Home Lab virtuel sur Proxmox pour le projet Iron4Software — Formation Analyste SOC - CyberUniversity (Liora x Sorbonne).

## Objectif du Lab
Après avoir obtenu un accès initial sur la zone exposée (Serveur Web), l'objectif de l'attaquant est de s'étendre vers le cœur du réseau (Mouvement Latéral) pour compromettre la cible de haute valeur : le Contrôleur de Domaine Windows Server 2019. Cette étape vise à exploiter la permissivité du pare-feu interne et à forcer l'authentification du compte Administrateur (Credential Access). Sur le plan défensif, cette attaque frontale générera une volumétrie massive de journaux d'échecs d'authentification, matière première idéale pour la création de nos futures alertes SOC.

## Outils et Technologies
- **Système d'attaque :** Kali Linux.
- **Routage :** Manipulation de la table de routage Linux (`ip route`).
- **Outil de Brute-Force :** CrackMapExec / NetExec (Interaction SMB).
- **Framework MITRE ATT&CK :** T1090 (Proxy / Pivot), T1110.001 (Brute Force: Password Guessing).

## 1. Mouvement Latéral : Le Routage vers le LAN (MITRE T1090)

Bien que je dispose d'un Reverse Shell sur le serveur Ubuntu, l'analyse de l'architecture (Phase 1) m'a révélé une faille critique : le pare-feu pfSense possède une règle WAN "Allow All". Par conséquent, la machine d'attaque Kali n'a même pas besoin d'utiliser l'Ubuntu comme proxy complexe pour atteindre le réseau interne (LAN). Il suffit de lui indiquer la route.

**Exécution de la commande :**
Depuis un terminal local sur Kali Linux, j'ai forcé le trafic à destination du réseau interne à transiter par l'IP publique du pare-feu :
```bash
sudo ip route add 192.168.3.0/24 via 192.168.50.7
```

**Analyse "Sous le capot" :**
Cette commande modifie la table de routage du noyau Linux de la machine d'attaque. Elle stipule que tout paquet destiné au sous-réseau `192.168.3.0/24` (le LAN de l'entreprise) doit être envoyé à la passerelle `192.168.50.7` (l'interface WAN du pfSense). Puisque pfSense est mal configuré et ne filtre pas le trafic entrant, il route docilement ces paquets vers les serveurs internes. C'est une illustration parfaite d'un contournement périmétrique par simple erreur de configuration.

## 2. L'Attaque par Force Brute (MITRE T1110.001)

Sachant que le Contrôleur de Domaine (cible `192.168.3.10`) gère l'authentification de l'entreprise, j'ai lancé une attaque par force brute ciblée sur le compte "Administrateur" natif en utilisant un dictionnaire de mots de passe.

**Exécution de la commande :**
Afin de contourner l'instabilité du protocole RDP face aux connexions automatisées, j'ai privilégié le protocole SMB (port 445), beaucoup plus robuste pour ce type d'attaque, via l'outil `crackmapexec` :
```bash
crackmapexec smb 192.168.3.10 -u Administrateur -p passwords.txt
```

**Analyse "Sous le capot" :**
L'outil initie des requêtes d'authentification SMB (`NTLMSSP`) à une vitesse fulgurante. À chaque tentative erronée, le serveur Windows répond par un code d'erreur `STATUS_LOGON_FAILURE`. L'outil itère sur le fichier texte jusqu'à recevoir un jeton d'accès valide de la part du service de partage de fichiers de Windows.

**Troubleshooting et Résultats (La faille humaine) :**
Dans un environnement Windows Server 2019 standard, cette attaque aurait dû échouer lamentablement à cause de la "Stratégie de verrouillage du compte", qui bloque l'utilisateur après 10 tentatives ratées (déclenchant un `STATUS_ACCOUNT_LOCKED_OUT`). 
Cependant, l'attaque a ici réussi après 34 tentatives infructueuses, l'outil affichant un succès explicite (`Pwn3d!`) à la 35ème ligne pour le mot de passe `Admin123`. 
Cette réussite met en lumière une faille de configuration humaine critique : pour des raisons de prétendue "facilité d'utilisation", les administrateurs de l'entreprise avaient désactivé la politique de verrouillage (Seuil fixé à 0). La forteresse numérique est tombée à cause d'une négligence de processus.

**Contexte SOC & Blue Team :**
Le succès de l'attaquant est une aubaine pour l'analyste SOC. Les 34 tentatives erronées ont généré exactement 34 événements de sécurité Windows distincts (Event ID 4625 - Échec d'ouverture de session), suivis d'un événement de succès (Event ID 4624). Cette signature temporelle (un volume massif d'ID 4625 en quelques secondes provenant de la même source) est l'empreinte digitale exacte d'une attaque par force brute. Je m'appuierai sur cette volumétrie lors de la Phase 4 pour paramétrer mon alerte SIEM avec une condition de déclenchement pertinente (ex: > 10 échecs en 1 minute).

## Implications pour un Analyste SOC
Les identifiants du compte à plus haut privilège du domaine sont désormais compromis. La négligence combinée d'un mot de passe prédictible (`Admin123`) et d'une politique de sécurité affaiblie a rendu caduque toute la robustesse native de l'OS. En tant que défenseur, le défi n'est plus d'empêcher l'intrusion, puisqu'elle a eu lieu, mais de détecter les actions post-compromission (Post-Exploitation). L'attaquant dispose désormais des clés pour se connecter graphiquement via RDP et initier l'objectif final de sa campagne : l'exfiltration et la destruction des données.

---
*Fin du rapport de Lab.*