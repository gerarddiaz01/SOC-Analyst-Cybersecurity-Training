# 🛡️ Lab Report: Stormshield Network Security (CSNA)

Ce document retrace mes laboratoires pratiques réalisés dans le cadre de la préparation à la certification **CSNA (Certified Stormshield Network Administrator)**. L'environnement utilisé est une machine virtuelle Stormshield (EVA) déployée dans un hyperviseur.

**Objectif Global :** Déployer, configurer et sécuriser un réseau d'entreprise simulé avec une appliance SNS.

---

## 🏗️ Lab 1 : Initialisation & Segmentation Réseau
**Contexte :** Démarrage d'un firewall vierge, configuration des interfaces réseaux pour séparer les zones (LAN, WAN, DMZ).

### 🛠️ Configuration Appliquée
1.  **Interfaces :**
    * `Ethernet0` (OUT) : Configuré en **WAN** (DHCP ou IP statique publique).
    * `Ethernet1` (IN) : Configuré en **LAN** (`192.168.10.254/24`). Définition comme passerelle par défaut pour les clients internes.
2.  **Objets Réseaux :**
    * Création de l'objet `Network_LAN` (`192.168.10.0/24`) pour faciliter l'appel dans les règles.

### 🚩 Validation
* Ping réussi depuis une machine du LAN vers l'interface interne du Stormshield.
* Accès à l'interface d'administration Web (`https://192.168.10.254/admin`).

---

## 🚦 Lab 2 : Politique de Filtrage (Firewalling)
**Contexte :** Appliquer le principe de "moindre privilège". Tout est bloqué par défaut, on ouvre uniquement les flux nécessaires.

### 🛠️ Règles de Sécurité Créées
J'ai configuré un "Slot" de filtrage avec les règles suivantes (Ordre séquentiel) :

| ID | Action | Source | Destination | Port/Service | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | **Bloquer** | Any | Any | SMB (445) | Protection contre propagation virale |
| 2 | **Passer** | Network_LAN | Internet | HTTP/HTTPS | Navigation Web pour les employés |
| 3 | **Passer** | Admin_PC | Firewall_Mgt | SSH/HTTPS | Administration sécurisée |
| 4 | **Bloquer** | Any | Any | Any | Règle implicite finale (Cleanup) |

> *Note : J'ai activé la trace (Logs) sur la règle n°2 pour auditer le trafic Web.*

### 📸 Preuve (Screenshot suggéré)
![Filtrage](../images/stormshield-rules-filtering.png)
*(Capture d'écran de ta politique de filtrage montrant les règles actives)*

---

## 🌍 Lab 3 : NAT (Translation d'adresse)
**Contexte :** Permettre aux machines du LAN (adresses privées) d'accéder à Internet via l'adresse publique du Firewall.

### 🛠️ Configuration du NAT
Le filtrage ne suffit pas, il faut translater les adresses sources.
1.  **Menu :** Politique de Filtrage > NAT.
2.  **Règle de Masquerading (Source NAT) :**
    * **Source Originale :** `Network_LAN`
    * **Destination Originale :** `Internet`
    * **Source Translatée :** `Firewall_OUT` (L'adresse publique de l'interface de sortie).

### 🚩 Résultat & Logs
* Depuis un PC du LAN : `ping 8.8.8.8` -> **Succès**.
* Analyse des logs "Trafic" : On voit bien que l'IP source `192.168.10.x` est remplacée par l'IP publique du firewall.

---

## 🛡️ Lab 4 : IPS (Intrusion Prevention System) & Sécurité Applicative
**Contexte :** Transformer le Firewall en IPS pour détecter et bloquer des attaques applicatives, pas juste filtrer des ports.

### 🛠️ Configuration
1.  **Activation de l'analyse :** Sur la règle de flux HTTP (Lab 2), j'ai changé le niveau d'inspection de "Firewall" à "IPS".
2.  **Test d'attaque :** Simulation d'une tentative d'accès à un site malveillant ou téléchargement du fichier de test EICAR.

### 🚩 Logs d'Alarmes
* Le moteur IPS a détecté le flux suspect.
* **Alarme générée :** `Détection Malware (EICAR Test File)`.
* **Action :** Connexion réinitialisée (Reset) par le Stormshield.

![Alarme IPS](../images/stormshield-ips-log.png)
*(Capture des logs d'alarmes montrant la détection)*

---

## 💡 Compétences Clés CSNA Validées
* **Gestion des Objets :** Compréhension de l'abstraction (IP -> Objet) pour des règles maintenables.
* **Stateful Inspection :** Configuration des règles de filtrage avec suivi de connexion.
* **NAT/PAT :** Maîtrise de la translation pour l'accès Internet sortant.
* **Monitoring :** Capacité à lire les logs "Trafic" et "Alarmes" pour diagnostiquer un blocage.