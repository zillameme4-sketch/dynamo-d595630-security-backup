# Single image for BOTH the agent run and the verifier (canonical TB2).
# It builds a deliberately mis-hardened multi-service host: sshd, redis, nginx +
# a small internal web app, a root cron backup job, a setuid helper and sudo
# grants. The agent hardens it in place; the verifier boots the services from
# their on-disk configuration and attacks them, then checks functionality.
FROM public.ecr.aws/docker/library/ubuntu:24.04@sha256:0d39fcc8335d6d74d5502f6df2d30119ff4790ebbb60b364818d5112d9e3e932

ENV DEBIAN_FRONTEND=noninteractive

# System packages + verifier deps (pytest), all baked at build time and pinned.
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server redis-server nginx sudo cron openssl gcc libc6-dev \
        iproute2 procps curl ca-certificates python3 python3-pip \
    && pip install --no-cache-dir --break-system-packages pytest==8.4.1 pytest-json-ctrf==0.3.5 \
    && rm -rf /var/lib/apt/lists/*

# --- Accounts -------------------------------------------------------------
# appuser: owns the web app and is the legitimate key-based SSH login.
# lowuser: a low-privilege foothold used to test privilege-escalation vectors.
RUN useradd -m -s /bin/bash appuser \
    && useradd -m -s /bin/bash lowuser \
    && install -d -m 0700 -o appuser -g appuser /home/appuser/.ssh
COPY data/appuser_authorized_keys /home/appuser/.ssh/authorized_keys
RUN chown appuser:appuser /home/appuser/.ssh/authorized_keys \
    && chmod 0600 /home/appuser/.ssh/authorized_keys

# --- SSH ------------------------------------------------------------------
RUN mkdir -p /run/sshd /etc/ssh/sshd_config.d && ssh-keygen -A >/dev/null
COPY data/etc/sshd_config /etc/ssh/sshd_config
COPY data/etc/sshd_legacy.conf /etc/ssh/sshd_config.d/00-legacy.conf

# --- Redis ----------------------------------------------------------------
COPY data/etc/redis.conf /etc/redis/redis.conf
RUN mkdir -p /var/lib/redis && chown redis:redis /var/lib/redis

# --- Web app --------------------------------------------------------------
RUN mkdir -p /opt/webapp
COPY data/webapp/app.py /opt/webapp/app.py
COPY data/webapp/webapp.conf /opt/webapp/webapp.conf
RUN chown -R appuser:appuser /opt/webapp && chmod 0644 /opt/webapp/webapp.conf

# --- nginx (TLS reverse proxy) -------------------------------------------
COPY data/etc/nginx.conf /etc/nginx/nginx.conf
RUN mkdir -p /etc/nginx/certs \
    && openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout /etc/nginx/certs/server.key -out /etc/nginx/certs/server.crt \
        -subj "/CN=localhost" >/dev/null 2>&1 \
    && chmod 0644 /etc/nginx/certs/server.crt && chmod 0640 /etc/nginx/certs/server.key

# --- Cron backup job ------------------------------------------------------
RUN mkdir -p /opt/backup
COPY data/etc/backup.sh /opt/backup/backup.sh
COPY data/etc/app-backup.cron /etc/cron.d/app-backup
# Deliberately weak: the backup script is world-writable and the crontab file
# is writable by everyone (a root-executed job anyone can rewrite).
RUN chmod 0777 /opt/backup/backup.sh && chmod 0666 /etc/cron.d/app-backup

# --- setuid diagnostics helper -------------------------------------------
COPY data/etc/netdiag.c /usr/local/src/netdiag.c
RUN gcc -O2 -o /usr/local/bin/netdiag /usr/local/src/netdiag.c \
    && chown root:root /usr/local/bin/netdiag \
    && chmod 4755 /usr/local/bin/netdiag

# --- sudo grants ----------------------------------------------------------
COPY data/etc/sudoers_appops /etc/sudoers.d/appops
RUN chmod 0440 /etc/sudoers.d/appops

WORKDIR /app
