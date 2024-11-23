#!/bin/bash

# génère automatiquement une clé GPG avec l'id 'myself'

export GPG_TTY=$(tty)  # needed in containers
gpg --batch --passphrase '' --quick-gen-key myself default default
