#!/usr/bin/env bash
#
# Registers this deployment's node as an application in its Zitadel, and merges
# the credentials it gets back into .env next to this file.
#
# The work is scripts/zitadel-bootstrap.sh at the repository root — the same
# script development uses, and the same idempotent behaviour: run it again after
# a domain change or after somebody deletes the application by hand, and it
# converges. What this wrapper adds is two things that file cannot assume.
#
# One, the deployment's own addresses: left to itself the script reads them out
# of config/config.yaml, where they are development names.
#
# Two, the merge. That script *writes* its env file — truncates it — because in
# development the file is entirely its own output. Here .env is hand-written and
# holds every other secret the stack has, so the script is pointed at a scratch
# file and only the three values it generates are folded back in.
#
# Run it after the first `docker compose up -d`, then `docker compose up -d`
# again so the node picks up the credentials.

set -euo pipefail

cd "$(dirname "$0")"

if [[ ! -f .env ]]; then
  echo "no .env here. Copy .env.example and fill it in first." >&2
  exit 1
fi

set -a
# shellcheck disable=SC1091
source .env
set +a

: "${ALEXANDRIA_DOMAIN:?set ALEXANDRIA_DOMAIN in .env}"
: "${AUTH_DOMAIN:?set AUTH_DOMAIN in .env}"

# Where compose finds the stack, for the `docker compose cp` the script uses to
# read Zitadel's bootstrap token out of its volume.
export COMPOSE_FILE="docker-compose.yaml"

# The addresses, as the browser will see them. The script sends the issuer's
# host as a Host header — Zitadel resolves which instance a request belongs to
# from it — while calling the management API on the loopback port compose
# publishes, so provisioning does not wait on a certificate having been issued.
export ZITADEL_ISSUER="https://${AUTH_DOMAIN}"
export ZITADEL_API="http://127.0.0.1:${ZITADEL_HOST_PORT:-1600}"
export REDIRECT_URI="https://${ALEXANDRIA_DOMAIN}/api/v1/auth/callback"
export APP_URL="https://${ALEXANDRIA_DOMAIN}/"

scratch="$PWD/.env.zitadel"
export ENV_FILE="$scratch"

# Seeded from .env so a re-run keeps the key that is already sealing live
# sessions: the script reuses whatever it finds in its env file and only
# generates one when there is none.
if [[ -n "${ALEXANDRIA_AUTH_CONFIG_SESSION_KEY:-}" ]]; then
  printf 'ALEXANDRIA_AUTH_CONFIG_SESSION_KEY=%s\n' \
    "$ALEXANDRIA_AUTH_CONFIG_SESSION_KEY" > "$scratch"
fi

bash ../../scripts/zitadel-bootstrap.sh

# ===== Fold the generated values back into .env ==============================

set_var() {
  local key="$1" value="$2"

  if grep -q "^${key}=" .env; then
    # A temporary file and a move, rather than sed -i: the in-place flag takes
    # an argument on BSD sed and none on GNU, and this runs on both.
    sed "s|^${key}=.*|${key}=${value}|" .env > .env.tmp && mv .env.tmp .env
  else
    printf '%s=%s\n' "$key" "$value" >> .env
  fi
}

read_var() {
  sed -n "s/^$1=//p" "$scratch" | head -n 1
}

for key in ALEXANDRIA_AUTH_CONFIG_CLIENT_ID \
  ALEXANDRIA_AUTH_CONFIG_CLIENT_SECRET \
  ALEXANDRIA_AUTH_CONFIG_SESSION_KEY \
  ZITADEL_M2M_CLIENT_ID \
  ZITADEL_M2M_CLIENT_SECRET; do
  value="$(read_var "$key")"

  # An `if`, not a `&&`: under `set -e` a false `&&` as the last command of the
  # loop body ends the script, and a value the script did not generate is not
  # an error.
  if [[ -n "$value" ]]; then
    set_var "$key" "$value"
  fi
done

rm -f "$scratch"

echo "merged     $PWD/.env"
echo
echo "  Now restart the node so it reads them:"
echo
echo "      docker compose up -d alexandria"
echo
