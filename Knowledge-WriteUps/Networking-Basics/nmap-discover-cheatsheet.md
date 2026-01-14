# Nmap : Network Mapper - Cheatsheet

**Catégorie :** Networking / Enumeration

**Outil :** Nmap (Network Mapper)

**Usage :** Découverte de réseau, scan de ports, détection de services et d'OS.

---

## 1. Introduction & Ciblage
Nmap est l'outil standard pour l'audit réseau. Il permet de cartographier les périphériques connectés et d'identifier les services actifs.

**Syntaxe de ciblage :**
* **IP Unique :** `nmap 192.168.0.1`
* **Plage d'IP :** `nmap 192.168.0.1-10`
* **Sous-réseau (CIDR) :** `nmap 192.168.0.1/24`
* **Liste uniquement (Pas de scan) :** `nmap -sL 192.168.0.1/24` (Liste les cibles potentielles sans les scanner).

---

## 2. Découverte d'Hôtes (Host Discovery)
Avant de scanner les ports, il faut identifier les machines actives ("up").

| Option | Description | Contexte |
| :--- | :--- | :--- |
| **`-sn`** | **Ping Scan**. Vérifie si l'hôte est en ligne sans scanner les ports. | Idéal pour la cartographie rapide. |
| **`-Pn`** | **No Ping**. Considère tous les hôtes comme étant "Online". | Utile si la cible bloque l'ICMP (Firewall). |

**Note sur le comportement réseau :**
* **Réseau Local (LAN) :** Nmap utilise des requêtes **ARP**. Si une machine répond, elle est marquée "Host is up".
* **Réseau Distant :** Nmap utilise ICMP et TCP (SYN/ACK) car ARP ne traverse pas les routeurs.

---

## 3. Techniques de Scan de Ports
Une fois la cible identifiée, on cherche les portes ouvertes.

### TCP Connect Scan (`-sT`)
* **Fonctionnement :** Effectue le "Three-way handshake" complet (SYN -> SYN/ACK -> ACK).
* **Avantage :** Fonctionne sans privilèges root (sudo).
* **Inconvénient :** Très bruyant dans les logs, connexion établie puis fermée (RST).

### SYN Scan (`-sS`) - "Stealth Scan"
* **Fonctionnement :** Envoie un SYN, reçoit un SYN/ACK, mais renvoie immédiatement un RST (ne finit jamais la connexion).
* **Avantage :** Plus discret, plus rapide. C'est le scan par défaut en root.
* **Prérequis :** Nécessite les privilèges root (`sudo`).

### UDP Scan (`-sU`)
* **Fonctionnement :** Scanne les services sans connexion (DNS, SNMP, DHCP).
* **Particularité :** Souvent plus lent car UDP ne garantit pas la réponse.

---

## 4. Spécification des Ports
Par défaut, Nmap scanne les 1000 ports les plus courants.

| Option | Description | Exemple |
| :--- | :--- | :--- |
| **`-F`** | **Fast Mode**. Scanne les 100 ports les plus communs. | `nmap -F target` |
| **`-p`** | **Port spécifique**. Liste ou plage. | `nmap -p 22,80 target` |
| **`-p-`** | **Tout**. Scanne les 65 535 ports (équivalent à `-p 1-65535`). | `nmap -p- target` |

---

## 5. Énumération de Service et d'OS
Savoir qu'un port est ouvert ne suffit pas, il faut savoir *qui* écoute.

* **Détection de Version (`-sV`) :** Interroge le port ouvert pour récupérer la bannière et la version du logiciel (ex: Apache 2.4.41).
* **Détection d'OS (`-O`) :** Analyse les réponses TCP/IP pour deviner le système d'exploitation (Linux, Windows, etc.).
* **Scan Agressif (`-A`) :** Combine la détection d'OS (`-O`), de Version (`-sV`), de scripts et le Traceroute.

---

## 6. Performance et Timing (`-T`)
Pour éviter les IDS ou accélérer le scan, Nmap propose des modèles de timing (Templates).

* **`-T0` (Paranoid) :** Très lent, pour éviter la détection (attend 5 min entre les paquets).
* **`-T1` (Sneaky)**
* **`-T2` (Polite)**
* **`-T3` (Normal) :** Valeur par défaut.
* **`-T4` (Aggressive) :** Recommandé pour les réseaux modernes et fiables (rapide).
* **`-T5` (Insane) :** Risque de perte de précision.

---

## 7. Gestion de l'Output (Formats)
Il est crucial de sauvegarder les résultats pour l'analyse ultérieure.

| Option | Format | Description |
| :--- | :--- | :--- |
| **`-oN`** | Normal | Fichier texte lisible par un humain. |
| **`-oX`** | XML | Pour importation dans d'autres outils (ex: Metasploit). |
| **`-oG`** | Grepable | Format linéaire facile à filtrer avec `grep`. |
| **`-oA`** | All | Génère les 3 formats simultanément (`.nmap`, `.xml`, `.gnmap`). |

**Verbosity :**
* **`-v`** : Affiche plus de détails pendant le scan.
* **`-vv`** : Encore plus de détails.

---

### Exemple de commande complète
Scanner une cible en mode agressif, sur tous les ports, sans ping, avec sauvegarde :
```bash
sudo nmap -p- -A -Pn -T4 -oA rapport_scan 192.168.1.50
```

### 8. Cas d'Usage et Exemples Pratiques

Voici une sélection de commandes adaptées à différents scénarios réels.

**1. Le "Scan Initial" (Rapide & Discret)**
L'objectif est de voir rapidement les services principaux sans scanner les 65k ports, en utilisant le mode "Stealth" (SYN).
* `-sS` : Scan SYN (Discret).
* `-F` : Fast mode (100 ports les plus courants).
* `--top-ports 1000` est le défaut, mais `-F` est plus rapide.

```bash
sudo nmap -sS -F 192.168.1.50
```

**2. L'Audit de Services UDP (Souvent oublié)**
Les services comme DNS (53), SNMP (161) ou DHCP (67) utilisent UDP. Ce scan est lent par nature, on limite donc souvent les ports ou on active le verbeux pour voir l'avancement.
* `-sU` : Active le scan UDP.
* `-v` : Mode verbeux pour voir l'activité en temps réel.

```bash
sudo nmap -sU -F -v 192.168.1.50
```

**3. Le "Noisy Scan" (Tout savoir)**
Utilisé dans les CTF ou quand la discrétion n'est pas requise. On veut tout : versions, OS, et traceroute.
* `-A` : OS + Version + Scripts + Traceroute.
* `-p-` : Scanne TOUS les ports (1 à 65535).
* `-T4` : Timing agressif (rapide).

```bash
sudo nmap -A -p- -T4 192.168.1.50
```

**4. Le "Stealthy / IDS Evasion" (Lent)**
Si un pare-feu ou un IDS bloque les scans rapides, on ralentit la cadence.
* `-sS` : SYN Scan (ne complète pas la connexion).
* `-T1` : "Sneaky". Envoie des paquets très lentement (peut prendre des heures).
* `-Pn` : Ne pas pinger l'hôte avant (suppose qu'il est en ligne).

```bash
sudo nmap -sS -T1 -Pn 192.168.1.50
```

**5. La Cartographie Réseau (Sans Port Scan)**
Juste pour savoir quelles IPs sont utilisées dans un sous-réseau, sans scanner les ports (Ping Sweep).
* `-sn` : Ping Scan (désactive le port scan).
* `-oN` : Sauvegarde la liste dans un fichier texte.

```bash
nmap -sn -oN live_hosts.txt 192.168.1.0/24
```