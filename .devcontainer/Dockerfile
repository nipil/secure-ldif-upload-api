FROM debian:bookworm-slim

RUN apt-get update && \
apt-get upgrade -y && \
apt-get install -y --no-install-recommends \
    curl \
    git \
    gnupg \
    iputils-ping \
    openssh-client \
    python3-flask \
    python3-flask-httpauth \
    python3-gnupg \
    python3-ldap \
    python3-magic \
    python3-paramiko \
    python3-pydantic \
    && \
rm -rf /var/lib/apt/lists/*

ENTRYPOINT [ "/bin/bash" ]
