# Jajalicious

## Paramètrages

Plusieurs paramètres sont à configurer avant de lancer le script :

* ADDRESS_LISTEN => Adresse sur laquelle le serveur va écouter
* PORT_LISTEN => Port sur lequel le serveur va écouter
* ADDRESS_GOPHISH => URL du serveur Gophish (habituellement https://localhost:3333)
* API_KEY_GOPHISH => API KEY du serveur Gophish (trouvable dans les paramètres de Gophish)
* campagn_name => Nom des campagnes qui seront créé dans Gophish
* ADDRESS_SERVER => URL du serveur où joindre Jajalicious (exemple : https://fakedomain.com)
* NAME_MALICIOUS_BASIC_FILE => Chemin du fichier malicieux en version française
* NAME_MALICIOUS_BASIC_FILE_EN => Chemin du fichier malicieux en version anglaise
* CERTFILE_PATH => Chemin du certificat PEM dans le cas d'un scénario avec authentification

## Génération des pages de redirection pour Gophish

Les pages qui seront générées seront à mettre dans la Landing Page de la campagne (page où l'utilisateur arrive lors du clique) :

```
python jajalicious.py --generateredirect fakedomain.com
```

Deux fichiers seront disponibles :

* redirectFR.html : Redirection pour les utilisateurs francophone
* redirectEN.html : Redirection pour les utilisateurs anglophone

## Premier lancement

La commande suivante permet de tester les paramètres renseigné.

```
python jajalicious.py --testparam
```

## Lancement normal

```
python jajalicious.py&
```

Les résultats seront disponibles dans le fichier "result.csv"

## Lancement avec fenêtre d'authentification dans WORD

Il sera nécessaire de renseigner un certficat SSL dans le paramètre "CERTFILE_PATH"

```
python jajalicious --auth&
```
