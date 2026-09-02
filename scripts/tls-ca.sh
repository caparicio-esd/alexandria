#!/usr/bin/env bash
#
# Creates the certificate authority this project's TLS runs on, inside the
# project, so nothing depends on where the machine happens to keep its own.
#
# What it produces is the CA itself — a root certificate and the private key
# that signs with it. Caddy takes those two files and mints the per-name
# certificates on the fly; they are never generated here.
#
# The key is a real signing key: anything that trusts this root trusts every
# certificate it ever issues. That is why .certs/ is gitignored, why the key is
# written 600, and why a CA must never be committed — a repository with a CA key
# in it is a man-in-the-middle kit for every machine that trusted it.

set -euo pipefail

DIR="${TLS_CA_DIR:-.certs}"
DAYS="${TLS_CA_DAYS:-3650}"
NAME="${TLS_CA_NAME:-Alexandria Local Authority}"

if [[ -f "$DIR/root.crt" && -f "$DIR/root.key" ]]; then
  echo "ca         $DIR/root.crt already there"
  openssl x509 -in "$DIR/root.crt" -noout -subject -enddate | sed 's/^/           /'
  exit 0
fi

mkdir -p "$DIR"

# P-256 rather than RSA: every client in this project's path supports it, and it
# keeps the handshake small. 10 years, because a development CA that expires is
# a morning lost to a confusing error.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout "$DIR/root.key" -out "$DIR/root.crt" \
  -days "$DAYS" -nodes -subj "/CN=$NAME" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

chmod 600 "$DIR/root.key"
chmod 644 "$DIR/root.crt"

echo "ca         $DIR/root.crt created"
openssl x509 -in "$DIR/root.crt" -noout -subject -enddate | sed 's/^/           /'
echo
echo "It is not trusted by anything yet. Install it once with:"
echo
echo "  task tls:trust"
