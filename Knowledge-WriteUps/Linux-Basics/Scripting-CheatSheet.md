# Introduction au Shell Scripting (Bash)

Le **Shell Scripting** consiste à stocker une série de commandes dans un fichier pour automatiser des tâches répétitives. Bien que le scripting soit possible dans plusieurs langages, le **Bash** est le standard sous Linux.

## 1. Configuration & Shebang

Pour qu'un script fonctionne, il doit être exécutable et définir son interpréteur via le **Shebang** (`#!`).

* **Extension :** `.sh`
* **Commande d'exécution :** `./script.sh` (Le `./` spécifie le dossier courant).
* **Permission requise :** `chmod +x script.sh`

### Structure de base
```bash
#!/bin/bash
# La ligne ci-dessus est le Shebang. Elle indique d'utiliser /bin/bash.
echo "Hello World"
```

## 2. Variables & Inputs

En Bash, on ne type pas les variables. L'assignation est stricte sur les espaces.

| Action | Syntaxe | Note Importante |
| :--- | :--- | :--- |
| **Assigner** | `var="valeur"` | **Jamais d'espaces** autour du `=` |
| **Lire** | `echo $var` | Toujours utiliser `$` pour appeler la variable |
| **Saisie User** | `read var` | Attend une entrée clavier de l'utilisateur |

### Exemple
```bash
#!/bin/bash
echo "Quel est ton nom ?"
read username
echo "Bienvenue, $username !"
```

## 3. Les Boucles (Loops)

Les boucles permettent de répéter des actions. La boucle `for` est idéale pour itérer sur une liste ou une plage de nombres.

### Syntaxe For Loop
```bash
#!/bin/bash
# Itération de 1 à 10
for i in {1..10}; do
    echo "Itération numéro $i"
done
```

* **do** : Marque le début du bloc.
* **done** : Marque la fin du bloc.

## 4. Les Conditions (If/Else)

Permet d'exécuter du code selon des critères.

**Attention** : Les espaces sont obligatoires à l'intérieur des crochets `[ ]`.

### Syntaxe If/Else
```bash
#!/bin/bash
echo "Entrez votre nom :"
read name

# Notez les espaces : [ "valeur" = "valeur" ]
if [ "$name" = "Stewart" ]; then
    echo "Accès autorisé. Secret : THM_Script"
else
    echo "Accès refusé."
fi
```

* **fi** : Indique la fin de la condition (If inversé).

## 5. Commentaires

Essentiels pour la documentation, ils sont ignorés par le shell.
``` bash
# Ceci est un commentaire
echo "Test" # Commentaire en fin de ligne
```

## Exemples de Scripts : Logique & Fichiers

Cette section explore un cas d'usage courant : un système d'authentification utilisant des opérateurs logiques.

### Script d'Authentification (Logique AND)

Ce script simule un accès sécurisé. Il utilise une boucle pour poser des questions séquentielles et une condition finale stricte utilisant l'opérateur `&&` (ET logique).

### Concepts Clés
* **`elif`** : "Sinon si". Permet de gérer plusieurs conditions à la suite.
* **`&&`** : Opérateur logique "ET". La condition est vraie uniquement si **toutes** les sous-conditions sont vraies.
* **`-eq`** : Comparaison numérique (Equal).

### Le Code (Locker Script)
```bash
#!/bin/bash

# Initialisation des variables
username=""
companyname=""
pin=""

# Boucle de 1 à 3 pour poser les 3 questions
for i in {1..3}; do
    if [ "$i" -eq 1 ]; then
        echo "Entrez votre nom d'utilisateur :"
        read username
    elif [ "$i" -eq 2 ]; then
        echo "Entrez le nom de l'entreprise :"
        read companyname
    else
        echo "Entrez votre code PIN :"
        read pin
    fi
done

# Vérification finale : TOUTES les conditions doivent correspondre
if [ "$username" = "John" ] && [ "$companyname" = "Tryhackme" ] && [ "$pin" = "7385" ]; then
    echo "Authentification réussie. Casier ouvert."
else
    echo "Authentification refusée !!"
fi
```