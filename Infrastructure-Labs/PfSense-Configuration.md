# 🔥 Configuration pfSense (Gateway & Firewall)

Ce document détaille la configuration initiale du pare-feu pfSense, qui agit comme la passerelle centrale et le routeur pour l'ensemble du laboratoire SOC.

## 1. Configuration Hyperviseur (VirtualBox)
Contrairement aux autres machines, pfSense nécessite **deux** cartes réseau distinctes pour assurer son rôle de routeur (entrée et sortie).

| Adaptateur | Mode VirtualBox | Nom du Réseau | Rôle |
| :--- | :--- | :--- | :--- |
| **Adaptateur 1** | Accès par Pont (Bridged) | *Carte Wifi/Eth Physique* | **WAN** : Connecte le lab à Internet via la box domestique. |
| **Adaptateur 2** | Réseau Interne | `pfsense_lan` | **LAN** : Réseau privé isolé pour les VMs du Lab. |

> **Note importante :** L'ordre des adaptateurs est crucial. Par défaut, pfSense détecte l'Adaptateur 1 comme `em0` (WAN) et l'Adaptateur 2 comme `em1` (LAN).

## 2. Configuration des Interfaces (Console & GUI)
L'adressage IP a été configuré pour définir le segment réseau du laboratoire (`192.168.50.0/24`).

* **Interface WAN (`em0`) :**
    * **Mode :** DHCP (Reçoit une IP du routeur domestique FAI).
    * **Rôle :** Accès Internet sortant (NAT).

* **Interface LAN (`em1`) :**
    * **Mode :** Statique (Static IPv4).
    * **Adresse IP :** `192.168.50.1`
    * **Masque (CIDR) :** `/24` (255.255.255.0)
    * **Rôle :** Passerelle par défaut (Gateway) pour toutes les VMs.

## 3. Services Réseau (DHCP & DNS)
Pour faciliter la gestion des clients (Windows 11, Ubuntu, Kali), le service DHCP a été activé sur l'interface LAN.

### 🔹 Serveur DHCP (LAN)
* **Plage d'activation :** `192.168.50.100` à `192.168.50.199`
* **Exclusions :**
    * `.1` à `.99` : Réservé pour les infrastructures (Gateway, Serveurs, AD).
    * `.200+` : Réservé pour futures extensions ou VPN.

### 🔹 Service DNS (Resolver)
pfSense agit comme un relais DNS (DNS Resolver/Unbound) pour le réseau interne.
* **Configuration :** Les clients utilisent `192.168.50.1` comme serveur DNS. pfSense résout les requêtes en les transmettant aux serveurs root ou au FAI.

## 4. Règles de Pare-feu (Firewall Rules)
Configuration initiale pour permettre le fonctionnement du laboratoire (mode "Permissif" pour la mise en place).

### Interface WAN
* **Block Private Networks (RFC1918) :** *Désactivé* (Décoché).
    * *Justification :* Comme le lab est derrière une box domestique (qui donne déjà une IP privée type 192.168.1.x), il faut autoriser le trafic privé entrant sur le WAN pour l'administration.

### Interface LAN
* **Default Allow LAN to Any Rule :** *Active* (Par défaut).
    * **Action :** Autoriser IPv4 * Source `LAN net` * Vers `any`.
    * **Justification :** Permet aux VMs (Kali, Ubuntu, Windows) d'accéder à Internet pour les mises à jour et les installations de paquets.