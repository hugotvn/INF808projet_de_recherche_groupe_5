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


### Installation Stix-shifter
(ne pas oublier de pip install -r requirements.txt)

Dans le dossier elastic:
docker-compose -d up

Créer le dossier qui recevra les patterns des logs Catalina
docker exec -it elastic-logstash-1 mkdir /usr/share/logstash/patterns

Mettre les patterns de logstash dans les pattern
docker cp custom.txt /usr/share/logstash/patterns/custom.txt

Récupérer le certificat d'elasticsearch
docker cp elastic-es01-1:/usr/share/elasticsearch/config/certs/ca/ca.crt stix/ca_elastic.crt

Mettre le chemin dans connect.json dans l'option "selfSignedCert"

L'ajouter dans les certificats reconnus par python
export SSL_CERT_FILE=stix/ca_elastic.crt 
export REQUESTS_CA_BUNDLE=stix/ca_elastic.crt

Vérifier que c'est ajouté
python3 -c "import ssl; print(ssl.get_default_verify_paths())"

Vérifier que la connexion peut s'établir.
stix-shifter transmit elastic_ecs "\$(cat connect.json)" "\$(cat config.json)" ping

Créer un index qui s'appelle logstash_logs dans elasticsearch avec la query qui est dans le fichier mapping_elastic.txt

Transférer les logs à logstash grâce au protocole TCP.
cat logs/catalina.2025-03-30.log | nc localhost 5044

Récupérer les données traités par logstash, puis elastic search puis transformées en format stix grâce à la commande suivante : (pour récupérer 10 résultats)
stix-shifter --debug transmit elastic_ecs "\$(cat connect.json)" "\$(cat config.json)" results '((event.loglevel : "FINE") OR (event.loglevel : "WARNING") OR (event.loglevel : "INFO")) AND (@timestamp:\["2025-03-30T00:00:00.000Z" TO "2025-03-31T00:05:00.000Z"])' 0 10 > results.json
