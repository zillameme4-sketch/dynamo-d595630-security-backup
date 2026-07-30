# Single image for BOTH the agent run and the verifier (canonical TB2).
# It builds a deliberately mis-hardened multi-service host: sshd, redis, nginx +
# a small internal web app, plus a root "maintenance" cron job that re-applies an
# insecure baseline on every run. The agent hardens it in place; the verifier
# runs the maintenance job (as the scheduler would), boots the services from
# their on-disk configuration, attacks them, then checks functionality.
FROM public.ecr.aws/docker/library/ubuntu:24.04@sha256:0d39fcc8335d6d74d5502f6df2d30119ff4790ebbb60b364818d5112d9e3e932

ENV DEBIAN_FRONTEND=noninteractive

# System packages + verifier deps (pytest), all baked at build time and pinned.
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server redis-server nginx sudo cron openssl gcc libc6-dev \
        iproute2 procps curl ca-certificates libcap2-bin perl python3 python3-pip \
    && pip install --no-cache-dir --break-system-packages pytest==8.4.1 pytest-json-ctrf==0.3.5 \
    && rm -rf /var/lib/apt/lists/*

# --- Accounts -------------------------------------------------------------
# appuser: owns the web app and is the legitimate key-based SSH login.
# lowuser: an unprivileged foothold; it is a member of the "maintenance" group.
# toolsvc: a leftover service account that was created with uid 0.
RUN groupadd maintenance \
    && useradd -m -s /bin/bash appuser \
    && useradd -m -s /bin/bash -G maintenance lowuser \
    && useradd -o -u 0 -g 0 -M -s /bin/bash toolsvc \
    && install -d -m 0700 -o appuser -g appuser /home/appuser/.ssh
COPY data/appuser_authorized_keys /home/appuser/.ssh/authorized_keys
RUN chown appuser:appuser /home/appuser/.ssh/authorized_keys \
    && chmod 0600 /home/appuser/.ssh/authorized_keys

# COPY carries the mode of the file in the build context, which depends on the
# filesystem the repo was checked out on (git only records the execute bit), so
# every copied path below is given its mode explicitly. Without that, the image
# differs between checkouts and picks up world-writable configs that are not
# part of the intended weakness set.

# --- SSH ------------------------------------------------------------------
RUN mkdir -p /run/sshd /etc/ssh/sshd_config.d && ssh-keygen -A >/dev/null
COPY data/etc/sshd_config /etc/ssh/sshd_config
RUN chown root:root /etc/ssh/sshd_config && chmod 0644 /etc/ssh/sshd_config

# --- Redis ----------------------------------------------------------------
COPY data/etc/redis.conf /etc/redis/redis.conf
RUN mkdir -p /var/lib/redis && chown redis:redis /var/lib/redis \
    && chown root:root /etc/redis/redis.conf && chmod 0644 /etc/redis/redis.conf

# --- Web app --------------------------------------------------------------
RUN mkdir -p /opt/webapp
COPY data/webapp/app.py /opt/webapp/app.py
COPY data/webapp/webapp.conf /opt/webapp/webapp.conf
RUN chown -R appuser:appuser /opt/webapp \
    && chmod 0644 /opt/webapp/app.py /opt/webapp/webapp.conf

# --- nginx (TLS reverse proxy) -------------------------------------------
COPY data/etc/nginx.conf /etc/nginx/nginx.conf
COPY data/etc/nginx-app.conf /etc/nginx/conf.d/app.conf
COPY data/etc/nginx-legacy.conf /etc/nginx/conf.d/legacy-http.conf
RUN chown root:root /etc/nginx/nginx.conf /etc/nginx/conf.d/app.conf /etc/nginx/conf.d/legacy-http.conf \
    && chmod 0644 /etc/nginx/nginx.conf /etc/nginx/conf.d/app.conf /etc/nginx/conf.d/legacy-http.conf \
    && mkdir -p /etc/nginx/certs \
    && openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout /etc/nginx/certs/server.key -out /etc/nginx/certs/server.crt \
        -subj "/CN=localhost" >/dev/null 2>&1 \
    && chmod 0644 /etc/nginx/certs/server.crt && chmod 0640 /etc/nginx/certs/server.key

# --- setuid diagnostics helper (setuid bit is applied by the baseline) ----
COPY data/etc/netdiag.c /usr/local/src/netdiag.c
RUN chown root:root /usr/local/src/netdiag.c && chmod 0644 /usr/local/src/netdiag.c \
    && gcc -O2 -o /usr/local/bin/netdiag /usr/local/src/netdiag.c \
    && chown root:root /usr/local/bin/netdiag && chmod 0755 /usr/local/bin/netdiag

# --- ops perl helper (a diagnostics copy of perl; its capability is applied
#     by the baseline, the same way the setuid bit is applied to netdiag) -----
RUN install -o root -g root -m 0755 /usr/bin/perl /usr/local/bin/opsperl

# --- Maintenance job + host profile ---------------------------------------
# The vendored host-profile.dist is the copy the job rolls back to when the
# active profile no longer matches the settings approved inside the job itself.
RUN mkdir -p /opt/ops /etc/ops /usr/share/ops /usr/local/ops/bin
COPY data/ops/maintenance.sh /opt/ops/maintenance.sh
COPY data/ops/collect-logs.sh /opt/ops/collect-logs.sh
COPY data/ops/opsreport /usr/local/ops/bin/opsreport
COPY data/ops/host-profile.conf /etc/ops/host-profile.conf
COPY data/ops/host-profile.conf /usr/share/ops/host-profile.dist
COPY data/etc/ops-maintenance.cron /etc/cron.d/ops-maintenance
# The helper *file* is root-owned and not writable by the group; the directory
# it lives in was left writable by the ops "maintenance" group long ago, which
# is what actually decides who can replace the helper the root job executes.
RUN chown root:root /etc/cron.d/ops-maintenance /etc/ops/host-profile.conf \
        /usr/share/ops/host-profile.dist /opt/ops/maintenance.sh \
    && chmod 0644 /etc/cron.d/ops-maintenance \
    && chmod 0644 /etc/ops/host-profile.conf /usr/share/ops/host-profile.dist \
    && chmod 0777 /opt/ops/maintenance.sh \
    && chown root:maintenance /opt/ops/collect-logs.sh && chmod 0775 /opt/ops/collect-logs.sh \
    && chown root:root /usr/local/ops/bin/opsreport && chmod 0755 /usr/local/ops/bin/opsreport \
    && chown root:maintenance /usr/local/ops/bin && chmod 0775 /usr/local/ops/bin \
    && /opt/ops/maintenance.sh

WORKDIR /app
