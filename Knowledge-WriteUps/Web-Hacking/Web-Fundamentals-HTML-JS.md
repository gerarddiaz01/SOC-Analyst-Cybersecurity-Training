# Architecture Web & Client-Side Mechanics (HTML/JS)

![Category](https://img.shields.io/badge/Category-Web_Security-blueviolet?style=flat-square)
![Focus](https://img.shields.io/badge/Focus-Code_Analysis-orange?style=flat-square)
![Skill](https://img.shields.io/badge/Skill-DOM_Manipulation-yellow?style=flat-square)

## Objectif
Comprendre comment les navigateurs interprètent le code côté client (Client-Side) pour identifier les vulnérabilités liées à la structure des pages (HTML) et à l'interactivité (JavaScript). L'objectif est de passer de "consommateur" de page web à "manipulateur" du code source.

## Concepts Techniques Clés

### 1. HTML (HyperText Markup Language)
C'est le squelette de la page.
* **Sécurité :** Si un attaquant peut injecter du HTML arbitraire dans une page, il peut modifier l'apparence du site (Defacement) ou créer de faux formulaires de connexion (Phishing).

### 2. JavaScript (JS)
C'est le muscle qui rend la page interactive.
* **DOM (Document Object Model) :** La structure en arbre de la page que JS peut modifier en temps réel.
* **Sécurité :** Si un attaquant parvient à faire exécuter son propre JS par le navigateur de la victime, c'est une faille **XSS (Cross-Site Scripting)**. Cela permet le vol de cookies de session.

### 3. View Source vs Inspect Element
* **View Source (Ctrl+U) :** Affiche le code tel qu'il a été envoyé par le serveur. Utile pour trouver des commentaires cachés ou des identifiants oubliés.
* **Inspect Element (F12) :** Affiche le code tel qu'il est *actuellement* rendu après l'exécution du JavaScript.

---

## Exercices Pratiques : Manipulation & Injection

Dans un environnement de simulation ("Sandboxed"), j'ai effectué plusieurs manipulations directes du code source pour altérer le comportement du site.

### 1. Manipulation HTML & Réparation de Liens
* **Scénario :** Une image ne s'affichait pas ("Broken Image").
* **Action :** Analyse de la balise `<img>`. Identification d'une erreur dans l'attribut `src` (chemin de fichier incorrect).
* **Injection de Média :** Ajout manuel d'une balise `<img>` pointant vers une ressource interne (`img/dog-1.png`) pour modifier le contenu visuel de la page.
* **Note d'Analyste :** Comprendre les chemins relatifs/absolus est crucial pour détecter les failles LFI (Local File Inclusion) où un attaquant essaie d'accéder à des fichiers système.

### 2. Exécution JavaScript (DOM Manipulation)
* **Scénario :** Modifier le texte affiché sur la page sans recharger celle-ci.
* **Action :** Injection de code JavaScript pour cibler un élément par son ID et modifier son contenu.
    * **Commande :** `document.getElementById("demo").innerHTML = "Hack the Planet";`
* **Interactivité Malveillante :** Création d'un bouton piégé qui exécute du code au clic.
    * **Code injecté :** `<button onclick='...'>Click Me!</button>`
* **Note d'Analyste :** C'est le principe de base des attaques XSS. Si je peux forcer le navigateur à afficher "Hack the Planet", je peux aussi lui demander d'envoyer les cookies de l'utilisateur vers mon serveur (Cookie Stealing).

### 3. Injection HTML (HTML Injection)
* **Scénario :** Le site permettait à l'utilisateur d'entrer du texte qui était affiché tel quel.
* **Action :** Injection d'une balise de lien hypertexte `<a>` pointant vers un site tiers (`http://hacker.com`).
* **Note d'Analyste :** C'est une vulnérabilité classique. Un attaquant peut utiliser cela pour rediriger des utilisateurs légitimes vers un site de phishing transparent (Open Redirect / Phishing Vector).

### 4. Information Disclosure (Fuite de données)
* **Scénario :** Recherche d'informations sensibles sur un site vulnérable.
* **Action :** Inspection du Code Source (`Ctrl+U`). Découverte d'un commentaire HTML `` contenant un mot de passe en clair.
* **Note d'Analyste :** Les développeurs laissent souvent des commentaires de débogage ou des identifiants "temporaires" en production. L'analyse statique du code source est la première étape d'un audit de sécurité.

---

## Takeaway pour le SOC
Le navigateur fait confiance à tout ce que le serveur lui envoie. En tant qu'analyste, je dois surveiller les logs pour détecter des motifs d'injection HTML (`<script>`, `onload=`, `javascript:`) dans les paramètres d'URL ou les champs de formulaire, car ils indiquent une tentative de compromission côté client.