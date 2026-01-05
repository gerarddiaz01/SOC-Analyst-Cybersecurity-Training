# 🖥️ Configuration Windows Server 2019 (AD Lab)

Ce document détaille les étapes spécifiques de post-installation effectuées pour intégrer le serveur Windows 2019 au réseau sécurisé du laboratoire.

## 1. Installation & Résolution de Problèmes Hyperviseur
Lors du déploiement sous VirtualBox, des configurations spécifiques ont été nécessaires pour assurer la stabilité :
* **Installation Manuelle :** Désactivation de l'option "Unattended Installation" de VirtualBox pour éviter l'erreur de licence EULA.
* **Guest Additions :** Installation des outils invités pour la gestion de l'affichage et de la souris.

## 2. Configuration Réseau (Adressage Statique)
Contrairement aux clients (Windows 11 / Ubuntu), le futur Contrôleur de Domaine nécessite une IP fixe pour être joignable en permanence.

* **Interface :** Ethernet0
* **Mode IP :** Statique (Manuel)

| Paramètre | Valeur | Description |
| :--- | :--- | :--- |
| **Adresse IP** | `192.168.50.10` | IP réservée pour le Serveur AD |
| **Masque** | `255.255.255.0` | CIDR /24 |
| **Passerelle** | `192.168.50.1` | Vers pfSense LAN |
| **DNS Préféré** | `192.168.50.1` | (Sera remplacé par 127.0.0.1 après promotion AD) |

## 3. Configuration du Pare-feu (Firewall Rules)
Par défaut, Windows Server bloque les requêtes ICMP (Ping), ce qui empêche la vérification de la connectivité réseau.

**Action réalisée :**
1.  Ouverture du console "Pare-feu Windows Defender avec fonctions avancées".
2.  Activation de la règle de trafic entrant :
    * *Nom :* **Partage de fichiers et d'imprimantes (Demande d'écho - Trafic entrant ICMPv4)**
    * *Profil :* Domaine / Privé / Public

> **Résultat :** Le serveur répond désormais aux pings provenant de Kali Linux et Ubuntu, validant la visibilité réseau.