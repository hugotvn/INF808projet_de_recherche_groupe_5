### Projet de recherche du groupe 5 dans le cadre du cours INF808 réaction aux attaques et analyse

#### Sujet : Réaction et protection contre une attaque à l'aide de l'outil Kestrel 



##
#### Mise en place de Kestrel
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

Quand l'utilisation est finie utiliser la commande : 

```deactivate```


##
### Utilisation de Kestrel 
Il y a deux options pour utiliser Kestrel :

- Soit en ligne de commande en faisant :
```kestrel nom_du_fichier```

- Soit en utilisant Jupyter en utilisant la commande :
``` jupyter nbclassic```
Et en cliquant sur ```nouveau``` puis ``` kestrel```.


### Installation ELK (Elasticsearch - Logstash - Kibana)
```
pip install -r requirements.txt
```

Pour lancer les containers :  
```
cd elastic
docker-compose -d up
cd ..
```

Créer le dossier qui recevra les patterns des logs Catalinac  
```
docker exec -it elastic-logstash-1 mkdir /usr/share/logstash/patterns
```

Mettre les patterns de logstash dans les pattern  
```
docker cp custom.txt /usr/share/logstash/patterns/custom.txt
```

Aller sur [localhost:5601](http://localhost:5601/) qui est le port de Kibana
S'identifier avec les codes suivant :
- Identifiant : elastic
- Mot de passe : Dans ```elastic/.env```

Aller dans Stack Management > Index Management > Console
Copier coller le script ```elastic/mapping_elastic.txt```

Lancer la commande

Voilà, installation terminée !

### Envoyer des données dans Elsticsearch

On envoit d'abord des données dans Logstash qui se chargera ensuite de les envoyer à Elasticsearch.
Logstash écoute sur le port 5044 avec le protocole TCP. On envoie donc nos logs avec la commande suivante :  
```cat logs/catalina.2025-03-30.log | nc localhost 5044```

### Installation et utilisation Stix-shifter
Nous utilisons le module elastic_ecs de Stix-shifter (déjà installé grâce à requirements.txt) 

Récupérer le certificat d'elasticsearch  
```docker cp elastic-es01-1:/usr/share/elasticsearch/config/certs/ca/ca.crt stix/ca_elastic.crt```

L'ajouter dans les certificats reconnus par python  
```
export SSL_CERT_FILE=stix/ca_elastic.crt 
export REQUESTS_CA_BUNDLE=stix/ca_elastic.crt
```

Vérifier que c'est ajouté  
```python3 -c "import ssl; print(ssl.get_default_verify_paths())"```

Vérifier que la connexion peut s'établir.  
```stix-shifter transmit elastic_ecs "\$(cat stix/connect.json)" "\$(cat stix/config.json)" ping```

Récupérer les données traités par logstash, puis elastic search puis transformées en format stix grâce à la commande suivante : (pour récupérer 10 résultats)  
```
stix-shifter --debug transmit elastic_ecs "\$(cat stix/connect.json)" "\$(cat stix/config.json)" results '((event.loglevel : "FINE") OR (event.loglevel : "WARNING") OR (event.loglevel : "INFO")) AND (@timestamp:\["2025-03-30T00:00:00.000Z" TO "2025-03-31T00:05:00.000Z"])' 0 10 > results.json
```
