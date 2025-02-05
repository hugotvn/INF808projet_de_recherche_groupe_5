### Projet de recherche du groupe 5 dans le cadre du cours INF808 réaction aux attaques et analyse

#### Sujet : Réaction et protection contre une attaque à l'aide de l'outil Kestrel 



##
#### Utilisation de Kestrel
L'usage de kestrel se fait dans l'environnemnet virtuel huntingspace que l'on va créer à la racine du projet. Dans un premier temps créer l'environnement virtuel : 
``` 
python3 -m venv huntingspace .
huntingspace/bin/activate
```
  
Ensuite installer les dépendances nécessaires :
```
pip install --upgrade pip setuptools wheel
pip install kestrel-jupyter
```

Et mettre en place l'environnement 
```
kestrel_jupyter_setup
```

Quand l'utilisation est finie utiliser le commande : 

```deactivate```


##
### Utilisation de Kestrel 
Il y a deux options pour utiliser Kestrel :

- Soit en ligne de commande en faisant :
```kestrel nom_du_fichier```

- Soit en utilisant Jupyter en utilisant la commande :
``` jupyter nbclassic```
Et en cliquant sur ```nouveau``` puis ``` kestrel```.