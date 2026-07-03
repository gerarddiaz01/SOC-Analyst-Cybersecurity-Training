## 1. Script de Recherche Automatisée (Grep & Loops)

Ce script parcourt un dossier pour trouver un fichier contenant une chaîne de caractères spécifique (un "flag"). C'est très utile pour l'analyse de logs ou le CTF (Capture The Flag).

### Concepts Clés
* **Wildcards (`*.log`)** : Cible tous les fichiers finissant par .log.
* **`grep -q`** : Mode "quiet" (silencieux). Ne n'affiche rien à l'écran, sert juste à vérifier si le texte existe (retourne vrai/faux).
* **`$(basename "$file")`** : Une sous-commande qui prend un chemin complet (`/var/log/syslog`) et ne garde que le nom du fichier (`syslog`).

### Le Code (Flag Search)
``` bash
#!/bin/bash

directory="/var/log"
flag="thm-flag01-script"

echo "Recherche en cours dans : $directory"

# Boucle sur chaque fichier .log du dossier
for file in "$directory"/*.log; do
    # Si le fichier contient le flag
    if grep -q "$flag" "$file"; then
        echo "Flag trouvé dans le fichier : $(basename "$file")"
    fi
done
```

---

