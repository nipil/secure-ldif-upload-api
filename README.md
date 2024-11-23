# Secure LDIF upload API

Qu'est-ce que c'est ?

- une **API** Web
- qui permet de téléverser un fichier **LDIF**
- de le chiffrer et de le signer va **GPG**
- de l'envoyer en **SFTP** vers l'un ou l'autre serveur prédéfini

## Dépendances

Uses Debian 12 system packages only, with versions :

- Python - [doc 3.11](https://docs.python.org/fr/3.11/index.html)
    - Flask = micro web framework - [doc 2.2](https://devdocs.io/flask~2.2/)
        - Flask HTTPAuth = bearer token - [doc stable](https://flask-httpauth.readthedocs.io/en/stable/)
    - magic = identification type mime - [doc 0.4.26](https://github.com/ahupp/python-magic/tree/0.4.26)
    - LDAP = manipulation LDIF - [doc 3.4.3](https://www.python-ldap.org/en/python-ldap-3.4.3/)
    - GnuPG = chiffrement et signature - [doc 0.4.9](https://gnupg.readthedocs.io/en/0.4.9/)
    - Paramiko = ssh/sftp library - [doc 2.12](https://docs.paramiko.org/en/2.12/)
    - pydantic = data validation - [doc 1.10](https://docs.pydantic.dev/1.10/)

## Configuration

Pour le chiffrement GPG :

- générer vos clés de signature
- importer les clés de chiffrement de vos partenaires
- positionnez le niveau de confiance pour les clés

Pour la connexion SFTP :

- générez vos clés SSH pour l'authenification
- transmettez vos clés SSH publiques à vos partenaires
- préparez votre configuration SSH pour chaque partenaire (`Host`, `User`, `Port`, `IdentityFile`)
- vérifiez que les configurations

Voir le dossier `examples`, avec les données utilisées en développement :

- `id_rsa*` et `config` : des clés SSH pour se connecter à un hôte distant
- `gpg-setup.sh` : un script pour créer une clé GPG pour chiffrer et signer
- `example.ldif` : un fichier LDIF de test
- `app_config.json` : une configuration valide pour la configuration devcontainer

Le fichier LDIF `example.ldif` a été récupéré de [Evolveum/midpoint](https://github.com/Evolveum/midpoint/blob/v4.9/infra/test-util/src/main/resources/test-data/ldif/example.ldif) (licence Apache)

Les paramètres implicites sont visibles dans les `BaseModel` du code.

## Exécution côté serveur

En développement

    cp examples/app_config.json  .
    flask --debug run

En production

    # Configurer Apache et Gunicorn !

# Exécution côté client

Simplement avec CURL :

    curl --fail-with-body --request POST \
        -H "Authorization: Bearer letmein" \
        --form "ldif=@examples/example.ldif" \
        localhost:5000/foo/upload-ldif?force

Les paramètres ont la signification suivante :

- `foo` le "tenant" auquel est associé une configuration GPG et SFTP
- `letmein` un token d'accès pour le tenant
- `localhost:5000` le point d'entrée du serveur API
- `/<tenant>/upload-ldif` le chemin de la requête POST
- `force` un paramètre optionnel pour écraser les fichiers déjà présents (déconseillé)
- `--form "ldif=@"` où `ldif` est l'id de l'élément du formulaire `multipart/form-data`
- `examples/example.ldif` est le chemin relatif du fichier ldif à envoyer

Le code de sortie de CURL :

- `0` si tout s'est bien passé (code réponse HTTP < 400)
- `22` si une erreur a eu lieu (code réponse HTTP >= 400)
