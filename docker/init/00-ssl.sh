#!/bin/bash
# Enable TLS on the upstream server.
#
# Runs during database initialisation, i.e. after initdb and before the real
# postmaster is started, so the settings below take effect on that start.
set -eu

: "${PGDATA:?PGDATA must be set}"

openssl req -new -x509 -days 3650 -nodes -text \
    -out "$PGDATA/server.crt" \
    -keyout "$PGDATA/server.key" \
    -subj "/CN=pregresql-upstream" >/dev/null 2>&1

chmod 600 "$PGDATA/server.key"

cat >>"$PGDATA/postgresql.conf" <<'EOF'

# --- enabled by docker/init/00-ssl.sh -----------------------------------------
ssl = on
ssl_cert_file = 'server.crt'
ssl_key_file = 'server.key'
EOF

echo "pregresql: enabled TLS on the upstream server"
