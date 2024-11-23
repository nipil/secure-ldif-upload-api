#!/usr/bin/env python3

import json
import logging
import socket
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
from pydantic import BaseModel, Field, Extra
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge, InternalServerError, Locked, Forbidden, NotFound

DEFAULT_SSH_SECRET_ID_PATH = '~/.ssh/id_rsa'
DEFAULT_SSH_CONFIG_PATH = '~/.ssh/config'
DEFAULT_APP_CONFIG_FILE_NAME = 'app_config.json'


class TenantConfig(BaseModel, extra=Extra.forbid):
    bearer_tokens: list[str]
    gpg_encryption_recipient_id: str
    gpg_signature_id: str
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
        with open(Path(path).expanduser(), 'rt') as file:
            return AppConfig(**json.load(file))


def create_app():
    try:
        return create_flask_app()
    except Exception as e:
        logging.exception(f"Erreur durant la création de l'application: {e}")
        raise e


def create_flask_app():
    """
    Créé l'application Flask, définit les routes
    """
    app = Flask(__name__, instance_relative_config=True)
    config = AppConfig.load()
    logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d %H:%M:%S',
                        level=getattr(logging, config.log_level.upper()))
    auth = HTTPTokenAuth(scheme='Bearer')

    @auth.verify_token
    def verify_token(token: str):
        """Recherche le tenant pour lequel ce token est autorisé"""
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
    except LDAPError as e:
        raise BadRequest(f'''Impossible d'analyser le contenu du fichier LDIF: {e}''')
    logging.info(f'Le fichier LDIF contient {dn_count} enregistrements')


def crypt_and_sign(content: bytes, encryption_id: str, signature_id: str):
    """
    Chiffre le contenu et créé une signature détachée
    """
    gpg = GPG()
    encrypted = gpg.encrypt(content, encryption_id, always_trust=True, armor=False)
    if encrypted.returncode != 0:
        raise InternalServerError('''Impossible de chiffrer les données''')
    logging.info(f'Longueur des données chiffrées : {len(encrypted.data)} octets')
    digest = sha256(encrypted.data).hexdigest().lower()
    logging.info(f'SHA256 du fichier chiffré : {digest}')
    signature = gpg.sign(encrypted.data, keyid=signature_id, detach=True, binary=True)
    if signature.returncode != 0:
        raise InternalServerError('''Impossible de signer les données chiffrées''')
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
        for cls in [ECDSAKey, Ed25519Key, RSAKey]:  # Ne tente pas DSSKey (déprécié)
            try:
                return cls.from_private_key_file(Path(path).expanduser())
            except SSHException:
                continue
        raise TypeError(f'Impossible de charger la clé SSH privée: {path}')

    logging.info(f'''Préparation de l'envoi en SFTP...''')
    config = SSHConfig.from_path(Path(DEFAULT_SSH_CONFIG_PATH).expanduser())
    config = SshConnectParams(**config.lookup(host))

    # Si seul le SFTP est autorisé, utiliser SSHClient entrainerait un rejet
    # en conséquence, obligation de se passer du confort du SSHClient
    # (gestion des fingerprint serveur, détection du format de clés...)
    logging.info(f'Connexion à {config.hostname} port {config.port}')
    with Transport((config.hostname, config.port)) as transport:

        # ATTENTION : `hostkey=None` ne vérifiera PAS le fingerprint du server distant
        logging.info(f'''Utilisateur {config.username} et clé {config.identity_file[0]}''')
        transport.connect(None, config.username, pkey=load_ssh_secret_key(config.identity_file[0]))
        with SFTPClient.from_transport(transport) as sftp:

            sftp.chdir(folder)
            targets = {sig_file, gpg_file}
            existing = set(sftp.listdir())
            logging.info(f'{len(existing)} fichiers présents sur la cible : {", ".join(existing)}')
            conflict = targets.intersection(existing)
            if len(conflict) > 0 and not force:
                raise Locked(f'Fichiers en conflit sur la cible : {", ".join(conflict)}')
            for file in existing:
                logging.info(f'Suppression de {file} avant écriture')
                sftp.unlink(file)

            logging.info(f'Écriture de la signature dans {tmp_file}')
            with sftp.open(tmp_file, 'w', bufsize=buf_size) as file:
                file.write(signature)
            logging.info(f'Renommage de {tmp_file} en {sig_file}')
            sftp.rename(tmp_file, sig_file)

            logging.info(f'Écriture du document dans {tmp_file}')
            with sftp.open(tmp_file, 'w', bufsize=buf_size) as file:
                file.write(encrypted)
            logging.info(f'Renommage de {tmp_file} en {gpg_file}')
            sftp.rename(tmp_file, gpg_file)

            existing = set(sftp.listdir())
            logging.info(f'Opération terminée, fichiers présents: {", ".join(existing)}')


def upload_ldif_to_target(app_config: AppConfig, tenant: str, content: bytes, force: bool):
    analyze_ldif(content, app_config.accepted_file_detected_mime_types)
    tenant_config = app_config.tenants[tenant]
    encrypted, signature = crypt_and_sign(content, tenant_config.gpg_encryption_recipient_id,
                                          tenant_config.gpg_signature_id)
    try:
        send_sftp(encrypted, signature, force, host=tenant_config.ssh_config_host,
                  folder=tenant_config.sftp_target_directory, tmp_file=tenant_config.sftp_target_temporary_filename,
                  sig_file=tenant_config.sftp_target_detached_signature_filename,
                  gpg_file=tenant_config.sftp_target_gpg_filename, buf_size=tenant_config.sftp_write_buffer_size)
    except (SSHException, socket.error, IOError) as e:
        logging.error(e)
        raise InternalServerError(f"Échec de l'opération SFTP pour le tenant: {tenant}")  # déjà escapé par Flask
