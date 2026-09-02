#!/usr/bin/env bash
#
# Gives the wallet an identity: a signing key and a default DID.
#
# It exists because a wallet that has just been created has neither, and the
# node's first call to it is GET /dids/default — which answers 404, and the node
# reports itself not ready with an error that names a missing model rather than
# a missing setup step. This turns that into `task wallet:bootstrap`.
#
# It is idempotent: it looks for a default DID first and does nothing when there
# already is one. Run it again after `task wallet:reset` and it converges on the
# same state, though not on the same identity — a DID is derived from its key,
# so a new key is a new node as far as the dataspace is concerned.

set -euo pipefail

CONFIG="${ALEXANDRIA_CONFIG:-config/config.yaml}"
KEY_ID="${FAFNIR_KEY_ID:-alexandria-signing-key}"
ALIAS="${FAFNIR_ALIAS:-alexandria}"
# Ed25519 by default: small, fast, and what did:jwk is most often seen with.
# The wallet also takes P-256 and secp256k1 — the curve this project builds jwx
# with — so a deployment that needs one of those sets this.
ALGORITHM="${FAFNIR_KEY_ALGORITHM:-ED25519}"

# Read out of the node's own configuration rather than restated here: the wallet
# the node will talk to is the wallet that has to be provisioned, and a second
# copy of its address is a second thing to keep in step.
setting() {
  sed -n "s/^[[:space:]]*$1:[[:space:]]*\"\{0,1\}\([^\"]*\)\"\{0,1\}[[:space:]]*$/\1/p" "$CONFIG"
}

if [[ -n "${FAFNIR_API:-}" ]]; then
  API="$FAFNIR_API"
else
  # The wallet block is the second "http:" in the document, so the whole file
  # cannot be grepped blindly. A flag rather than an awk range: a range whose
  # end pattern also matches its start line is one line long, and every
  # top-level key here matches both.
  WALLET_BLOCK="$(awk '/^wallet_config:/{f=1;next} f&&/^[a-z_]/{f=0} f' "$CONFIG")"
  scheme="$(printf '%s' "$WALLET_BLOCK" | sed -n 's/^[[:space:]]*protocol:[[:space:]]*"\(.*\)".*/\1/p' | head -n 1)"
  host="$(printf '%s' "$WALLET_BLOCK" | sed -n 's/^[[:space:]]*url:[[:space:]]*"\(.*\)".*/\1/p' | head -n 1)"
  port="$(printf '%s' "$WALLET_BLOCK" | sed -n 's/^[[:space:]]*port:[[:space:]]*"\(.*\)".*/\1/p' | head -n 1)"

  if [[ -z "$scheme" || -z "$host" ]]; then
    echo "no wallet_config.api.http in $CONFIG, and no FAFNIR_API given" >&2
    exit 1
  fi

  API="$scheme://$host"
  [[ -n "$port" ]] && API="$API:$port"
fi

echo "wallet     $API"

# ===== Is there already an identity? =========================================

if did="$(curl -sSf "$API/dids/default" 2>/dev/null)"; then
  echo "did        $(printf '%s' "$did" | jq -r .did)"
  echo "unchanged  the wallet already has a default DID"
  exit 0
fi

# Distinguish "no identity yet" from "no wallet": the first is this script's
# job, the second is not, and the errors look nothing alike to a reader who is
# told only that a curl failed.
if ! curl -sSf -o /dev/null "$API/keys/all" 2>/dev/null; then
  cat >&2 <<MSG
The wallet is not answering at $API.

  task wallet:up        start it
  task wallet:logs      see why it did not
MSG
  exit 1
fi

# ===== The key ===============================================================
# Generated here and handed over, because the wallet imports PEM rather than
# minting its own. It is written to a temporary file that is removed on the way
# out: this is the node's private key, and it has no business staying on disk
# outside the wallet.

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

case "$ALGORITHM" in
  ED25519) openssl genpkey -algorithm ED25519 -out "$scratch/key.pem" ;;
  P-256)   openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$scratch/key.pem" ;;
  SECP256K1) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp256k1 -out "$scratch/key.pem" ;;
  *)
    echo "unknown FAFNIR_KEY_ALGORITHM $ALGORITHM: use ED25519, P-256 or SECP256K1" >&2
    exit 1
    ;;
esac

PEM="$(cat "$scratch/key.pem")"

# The id is what the wallet names the key file by, and an empty one makes it try
# to write to the directory itself — which fails with a message about an
# unwritable path rather than about a missing field.
jq -n --arg id "$KEY_ID" --arg alias "$ALIAS" --arg pem "$PEM" \
  '{id: $id, alias: $alias, pem: $pem}' > "$scratch/key.json"

if ! key="$(curl -sSf -X POST "$API/keys/new" \
  -H 'Content-Type: application/json' -d @"$scratch/key.json")"; then
  echo "registering the key failed" >&2
  exit 1
fi

echo "key        $(printf '%s' "$key" | jq -r '"\(.id) (\(.kty) \(.crv // "-"))"')"

# ===== The DID ===============================================================
# did:jwk, matching did_config.type in the node's configuration: the identifier
# is derived from the key itself, so it needs no registry and no domain. The
# key has to be associated at creation — a DID with no keys is refused.

jq -n --arg alias "$ALIAS" --arg pem "$PEM" --arg key "$KEY_ID" \
  '{builder: {Jwk: {pem: $pem}}, keys: [$key], alias: $alias}' > "$scratch/did.json"

if ! created="$(curl -sSf -X POST "$API/dids/new" \
  -H 'Content-Type: application/json' -d @"$scratch/did.json")"; then
  echo "creating the DID failed" >&2
  exit 1
fi

DID_ID="$(printf '%s' "$created" | jq -r .id)"

# The first DID a wallet holds is its default already. Promoting it anyway keeps
# this correct for a wallet that had others, and the call is idempotent.
if [[ "$(printf '%s' "$created" | jq -r .default)" != "true" ]]; then
  curl -sSf -X POST "$API/dids/default/$DID_ID" >/dev/null
fi

echo "did        $(printf '%s' "$created" | jq -r .did)"
echo
echo "  The node will pick this up on its next start."
