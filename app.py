#!/usr/bin/env python3

import json
import logging
import socket
import sys
from getpass import getuser
from hashlib import sha256
from io import BytesIO
from pathlib import Path

from flask import Flask, request, Response
from flask_httpauth import HTTPTokenAuth
from gnupg import GPG
from ldap import LDAPError
from ldif import LDIFParser
from magic import Magic
from paramiko import SSHConfig, SSHException, Transport, SFTPClient, RSAKey, Ed25519Key, ECDSAKey
from paramiko.config import SSH_PORT
from pydantic import BaseModel, Field, Extra, ValidationError
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge, InternalServerError, Locked, Forbidden, NotFound

DEFAULT_SSH_SECRET_ID_PATH = '~/.ssh/id_rsa'
DEFAULT_SSH_CONFIG_PATH = '~/.ssh/config'
DEFAULT_APP_CONFIG_FILE_NAME = 'app_config.json'


class InvalidConfiguration(Exception):
    pass


class TenantConfig(BaseModel, extra=Extra.forbid):
    bearer_tokens: list[str]
    gpg_encryption_fingerprint: str
    gpg_signature_fingerprint: str
    ssh_config_host: str
    sftp_target_directory: str
    sftp_target_temporary_filename: str
    sftp_target_gpg_filename: str
    sftp_target_detached_signature_filename: str
    sftp_write_buffer_size: int = 1024


class AppConfig(BaseModel, extra=Extra.forbid):
    log_level: str
    max_upload_size: int
    form_input_file_id: str = 'ldif'
    query_args_force_name: str = 'force'
    accepted_file_detected_mime_types: list[str] = Field(default_factory=lambda: ['text/plain'])
    tenants: dict[str, TenantConfig] = Field(default_factory=dict)

    @staticmethod
    def load(path=DEFAULT_APP_CONFIG_FILE_NAME):
        try:
            with open(Path(path).expanduser(), 'rt') as file:
                return AppConfig(**json.load(file))
        except OSError as e:
            logging.warning(f'Impossible de charger la configuration : {e}')
            raise InternalServerError('Configuration applicative non disponible')


def create_app():
    try:
        return create_flask_app()
    except Exception as e:
        logging.error(f"Erreur durant la création de l'application: {e}")
        sys.exit(1)


def create_flask_app():
    """
    Créé l'application Flask, définit les routes
    """
    app = Flask(__name__, instance_relative_config=True)
    config = AppConfig.load()
    logging.basicConfig(format='%(levelname)-8s %(message)s', level=getattr(logging, config.log_level.upper()))
    auth = HTTPTokenAuth(scheme='Bearer')

    @auth.verify_token
    def verify_token(token: str):
        """Recherche un tenant pour lequel ce token serait autorisé"""
        for tenant_name, tenant_config in config.tenants.items():
            if token in tenant_config.bearer_tokens:
                return tenant_name
        return None

    @app.route('/<tenant>/upload-ldif', methods=['POST'])
    @auth.login_required
    def upload_ldif(tenant: str):
        if tenant not in config.tenants:
            raise NotFound('Tenant inconnu')
        if auth.current_user() != tenant:
            raise Forbidden("Vous n'avez pas accès à ce tenant")
        if request.content_length is None:
            raise BadRequest('Aucun fichier envoyé')
        if request.content_length > config.max_upload_size:
            raise RequestEntityTooLarge('Envoi trop volumineux')
        if len(request.files) != 1:
            raise BadRequest('Un unique fichier est nécessaire')
        try:
            file = request.files[config.form_input_file_id]
        except KeyError:
            raise BadRequest(f'Un champs "{config.form_input_file_id}" pour '
                             'le fichier est nécessaire dans le formulaire')
        content = file.read()
        force = config.query_args_force_name in request.values
        logging.info(f'Remplacement de fichiers sur la destination : {"" if force else "dés"}activé')
        logging.info(f'Nouvelle requête de {request.remote_addr} pour envoyer un ldif vers le tenant {tenant}')
        try:
            result = upload_ldif_to_target(config, tenant, content, force)
        except Exception as e:
            logging.error(e)
            raise e
        return Response(result)

    return app


def analyze_ldif(content: bytes, allowed_mime_types: list[str]):
    """
    Analyse le LDIF pour en extraire quelques informations
    """

    class LdifDnCounter(LDIFParser):

        def __init__(self, data: bytes):
            self.count = 0
            file = BytesIO(data)
            super().__init__(file)

        def handle(self, dn, entry):
            self.count += 1

        @staticmethod
        def get_count(data: bytes):
            ctr = LdifDnCounter(data)
            ctr.parse()
            return ctr.count

    logging.info(f'Taille du fichier fourni : {len(content)} octets')
    digest = sha256(content).hexdigest().lower()
    logging.info(f'SHA256 du fichier fourni : {digest}')
    mime = Magic(mime=True).from_buffer(content)
    logging.info(f'Type mime détecté pour le fichier fourni : {mime}')
    if mime not in allowed_mime_types:
        raise BadRequest(f'Type mime "{mime}" non-autorisé. '
                         f'Types autorisés : {" ".join(allowed_mime_types)}')
    try:
        dn_count = LdifDnCounter.get_count(content)
    except (ValueError, LDAPError) as e:
        logging.warning(f"Erreur lors de l'analyse du fichier LDIF : {e}")
        raise BadRequest(f"Impossible d'analyser le contenu du fichier LDIF")
    logging.info(f'Le fichier LDIF contient {dn_count} enregistrements')


def crypt_and_sign(content: bytes, encryption_fingerprint: str, signature_fingerprint: str):
    """
    Chiffre le contenu et créé une signature détachée
    """
    gpg = GPG()
    logging.info(f'Chiffrement du LDIF par GPG avec la clé : {encryption_fingerprint}')
    encrypted = gpg.encrypt(content, encryption_fingerprint, always_trust=True, armor=False)
    if encrypted.returncode != 0:
        raise InternalServerError('Impossible de chiffrer les données')
    logging.info(f'Longueur par GPG des données chiffrées : {len(encrypted.data)} octets')
    digest = sha256(encrypted.data).hexdigest().lower()
    logging.info(f'SHA256 du fichier chiffré : {digest}')
    logging.info(f'Signature par GPG du fichier chiffré avec la clé : {signature_fingerprint}')
    signature = gpg.sign(encrypted.data, detach=True, binary=True, extra_args=['--local-user', signature_fingerprint])
    if signature.returncode != 0:
        raise InternalServerError('Impossible de signer les données chiffrées')
    logging.info(f'Longueur de la signature des données chiffrées : {len(signature.data)} octets')
    digest = sha256(signature.data).hexdigest().lower()
    logging.info(f'SHA256 de la signature détachée : {digest}')
    return encrypted.data, signature.data


def send_sftp(encrypted: bytes, signature: bytes, force: bool, *, host: str, folder: str, tmp_file: str, sig_file: str,
              gpg_file: str, buf_size: int):
    """
    Envoie les fichiers sur le SFTP
    """

    class SshConnectParams(BaseModel):
        hostname: str
        username: str = Field(alias='user', default_factory=getuser)
        port: int = SSH_PORT
        identity_file: list[str] = Field(alias='identityfile', default_factory=lambda: [DEFAULT_SSH_SECRET_ID_PATH])

    def load_ssh_secret_key(path):
        path = str(Path(path).expanduser())
        for cls in [ECDSAKey, Ed25519Key, RSAKey]:  # Ne tente pas DSSKey (déprécié)
            try:
                return cls.from_private_key_file(path)
            except SSHException:
                continue
            except OSError as exc:
                raise InvalidConfiguration(f'Clé SSH {path} inaccessible : {exc}')
        raise InvalidConfiguration(f'Impossible de charger la clé SSH : {path}')

    def sftp_cd(sftp_obj, path):
        try:
            sftp_obj.chdir(path)
        except OSError as exc:
            raise SSHException(f'''Impossible d'atteindre le dossier "{path}" sur le serveur SFTP : {exc}''')

    def sftp_dir(sftp_obj):
        try:
            return set(sftp_obj.listdir())
        except OSError as exc:
            raise SSHException(f'Lecture impossible du dossier SFTP courant : {exc}')

    def sftp_write_file(sftp_obj, content: bytes, name: str):
        logging.info(f'Écriture de du fichier {name}')
        try:
            with sftp_obj.open(name, 'w', bufsize=buf_size) as fic:
                fic.write(content)
        except OSError as exc:
            raise SSHException(f'''Impossible d'écrire le fichier "{name}" : {exc}''')

    def sftp_rename_temp(sftp_obj, src: str, dst: str):
        logging.info(f'Renommage de {src} en {dst}')
        try:
            sftp_obj.rename(src, dst)
        except OSError as exc:
            raise SSHException(f'Impossible de renommer "{src}" en "{dst}: {exc}')

    def sftp_unlink(sftp_obj, name: str):
        logging.info(f'Suppression de {name}')
        try:
            sftp_obj.unlink(name)
        except OSError as exc:
            raise SSHException(f'Impossible supprimer le fichier "{name}" : {exc}')

    logging.info(f"Préparation de l'envoi en SFTP...")
    config_path = str(Path(DEFAULT_SSH_CONFIG_PATH).expanduser())
    try:
        config = SSHConfig.from_path(config_path)
    except OSError as e:
        raise InvalidConfiguration(f'Impossible de charger la configuration SSH "{config_path}" : {e}')
    try:
        config = SshConnectParams(**config.lookup(host))
    except ValidationError as e:
        e = str(e).replace('\n', ' ')
        raise InvalidConfiguration(f'Configuration SSH {config_path} invalide : {e}')

    # Si seul le SFTP est autorisé, utiliser SSHClient entrainerait un rejet, donc
    # obligation de se passer du confort du SSHClient, et des fonctions automatiques
    # qui vont avec : gestion des fingerprint serveur, détection du format de clés...
    logging.info(f'Connexion à {config.hostname} port {config.port}')
    with Transport((config.hostname, config.port)) as transport:
        ssh_private_key = load_ssh_secret_key(config.identity_file[0])
        # ATTENTION : `hostkey=None` ne vérifiera PAS le fingerprint du server distant
        logging.info(f"Utilisateur {config.username} et clé {config.identity_file[0]}")
        transport.connect(None, config.username, pkey=ssh_private_key)
        with SFTPClient.from_transport(transport) as sftp:
            sftp_cd(sftp, folder)
            targets = {sig_file, gpg_file}
            existing = sftp_dir(sftp)
            logging.info(f'{len(existing)} fichiers présents sur la cible : {", ".join(existing)}')
            conflict = targets.intersection(existing)
            if len(conflict) > 0 and not force:
                raise Locked(f'Fichiers en conflit sur la cible : {", ".join(conflict)}')
            for present in conflict:
                sftp_unlink(sftp, present)
            sftp_write_file(sftp, signature, tmp_file)
            sftp_rename_temp(sftp, tmp_file, sig_file)
            sftp_write_file(sftp, encrypted, tmp_file)
            sftp_rename_temp(sftp, tmp_file, gpg_file)
            existing = sftp_dir(sftp)
            logging.info(f'Opération terminée, fichiers présents: {", ".join(existing)}')


def upload_ldif_to_target(app_config: AppConfig, tenant: str, content: bytes, force: bool):
    analyze_ldif(content, app_config.accepted_file_detected_mime_types)
    tenant_config = app_config.tenants[tenant]
    encrypted, signature = crypt_and_sign(content, tenant_config.gpg_encryption_fingerprint,
                                          tenant_config.gpg_signature_fingerprint)
    try:
        send_sftp(encrypted, signature, force, host=tenant_config.ssh_config_host,
                  folder=tenant_config.sftp_target_directory, tmp_file=tenant_config.sftp_target_temporary_filename,
                  sig_file=tenant_config.sftp_target_detached_signature_filename,
                  gpg_file=tenant_config.sftp_target_gpg_filename, buf_size=tenant_config.sftp_write_buffer_size)
    except InvalidConfiguration as e:
        logging.warning(f'Échec de configuration SSH avec la configuration "{tenant_config.ssh_config_host}" : {e}')
        raise InternalServerError(f'Configuration SFTP invalide pour le tenant {tenant}')  # déjà escapé par Flask
    except (socket.gaierror, SSHException) as e:
        logging.warning(f'Opération SSH en erreur avec la configuration "{tenant_config.ssh_config_host}" : {e}')
        raise InternalServerError(f"Échec de l'opération SFTP pour le tenant {tenant}")  # déjà escapé par Flask
