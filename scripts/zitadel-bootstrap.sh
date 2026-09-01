#!/usr/bin/env bash
#
# Provisions the Zitadel project and application this node logs in through, and
# writes the credentials to .env, where the Taskfile picks them up.
#
# It exists because the alternative is a console walkthrough: eight fields,
# performed slightly differently by everybody, and a client id that cannot be
# chosen — Zitadel generates it — so no committed configuration file can hold
# one that works. This turns that into `task auth:bootstrap`.
#
# It is idempotent. Run it again after `task auth:reset`, or after somebody
# deletes the application by hand, and it converges on the same state.

set -euo pipefail

ISSUER="${ZITADEL_ISSUER:-http://127.0.0.1:${ZITADEL_PORT:-1600}}"
CONFIG="${ALEXANDRIA_CONFIG:-config/config.yaml}"
PROJECT_NAME="${ZITADEL_PROJECT:-alexandria}"
APP_NAME="${ZITADEL_APP:-alexandria-node}"
ROLE="${ZITADEL_ROLE:-reader}"
ENV_FILE="${ENV_FILE:-.env}"

# ===== The values the node will actually send ================================
# Read out of the node's own configuration rather than restated here: the
# redirect URI has to match to the character, and a second copy of it is a
# second thing to keep in step.

setting() {
  sed -n "s/^[[:space:]]*$1:[[:space:]]*\"\{0,1\}\([^\"]*\)\"\{0,1\}[[:space:]]*$/\1/p" "$CONFIG" | head -n 1
}

REDIRECT_URI="${REDIRECT_URI:-$(setting redirect_url)}"
APP_URL="${APP_URL:-$(setting app_url)}"

if [[ -z "$REDIRECT_URI" ]]; then
  echo "no auth_config.redirect_url in $CONFIG, and no REDIRECT_URI given" >&2
  exit 1
fi

# ===== The token everything below is done with ===============================

pat() {
  if [[ -n "${ZITADEL_PAT:-}" ]]; then
    printf '%s' "$ZITADEL_PAT"
    return
  fi

  # Written by the instance when it created itself. It is copied out rather
  # than read with exec: the image is distroless, so there is no shell and no
  # cat in there to run.
  local scratch
  scratch="$(mktemp)"

  if docker compose cp zitadel:/machinekey/pat.txt "$scratch" >/dev/null 2>&1; then
    cat "$scratch"
  fi

  rm -f "$scratch"
}

PAT="$(pat | tr -d '[:space:]')"

if [[ -z "$PAT" ]]; then
  cat >&2 <<'MSG'
No personal access token found.

It is minted when the instance is first created, so an installation that
predates this script has none. Either:

  task auth:reset          destroy the local Zitadel and start over
  ZITADEL_PAT=... task auth:bootstrap    with a token you made in the console
MSG
  exit 1
fi

api() {
  local method="$1" path="$2" body="${3:-}"
  local args=(-sS -X "$method" -H "Authorization: Bearer $PAT"
              -H "Content-Type: application/json" -H "Accept: application/json")

  [[ -n "$body" ]] && args+=(-d "$body")

  curl "${args[@]}" "$ISSUER$path"
}

# fail_on_error stops on an API error rather than carrying a null id forward,
# where the failure would resurface three calls later as something unrelated.
fail_on_error() {
  local response="$1" what="$2"

  if [[ "$(jq -r 'if type == "object" and has("code") then "error" else "ok" end' <<<"$response")" == "error" ]]; then
    echo "$what: $(jq -r '.message // "unknown error"' <<<"$response")" >&2
    exit 1
  fi
}

# ===== Project ===============================================================

project_id() {
  api POST /management/v1/projects/_search \
    "{\"queries\":[{\"nameQuery\":{\"name\":\"$PROJECT_NAME\",\"method\":\"TEXT_QUERY_METHOD_EQUALS\"}}]}" |
    jq -r '.result[0].id // empty'
}

PROJECT_ID="$(project_id)"

if [[ -z "$PROJECT_ID" ]]; then
  # projectRoleAssertion puts the project's roles into the tokens it issues,
  # which is what makes auth_config.required_roles enforceable at all.
  response="$(api POST /management/v1/projects \
    "{\"name\":\"$PROJECT_NAME\",\"projectRoleAssertion\":true,\"projectRoleCheck\":false,\"hasProjectCheck\":false}")"
  fail_on_error "$response" "creating the project"
  PROJECT_ID="$(jq -r '.id' <<<"$response")"
  echo "project    $PROJECT_NAME ($PROJECT_ID) created"
else
  echo "project    $PROJECT_NAME ($PROJECT_ID) already there"
fi

# ===== Application ===========================================================

app_id() {
  api POST "/management/v1/projects/$PROJECT_ID/apps/_search" \
    "{\"queries\":[{\"nameQuery\":{\"name\":\"$APP_NAME\",\"method\":\"TEXT_QUERY_METHOD_EQUALS\"}}]}" |
    jq -r '.result[0].id // empty'
}

APP_ID="$(app_id)"
CLIENT_ID=""
CLIENT_SECRET=""

if [[ -z "$APP_ID" ]]; then
  # devMode is what lets a plain-http redirect URI be registered at all, and it
  # is why this script is a development tool: a deployment registers its
  # application against https, once, and keeps the credentials in its secret
  # store rather than in a dotfile.
  response="$(api POST "/management/v1/projects/$PROJECT_ID/apps/oidc" "$(
    jq -n --arg name "$APP_NAME" --arg redirect "$REDIRECT_URI" --arg logout "$APP_URL" '{
      name: $name,
      redirectUris: [$redirect],
      postLogoutRedirectUris: [$logout],
      responseTypes: ["OIDC_RESPONSE_TYPE_CODE"],
      grantTypes: ["OIDC_GRANT_TYPE_AUTHORIZATION_CODE", "OIDC_GRANT_TYPE_REFRESH_TOKEN"],
      appType: "OIDC_APP_TYPE_WEB",
      authMethodType: "OIDC_AUTH_METHOD_TYPE_BASIC",
      version: "OIDC_VERSION_1_0",
      devMode: true,
      accessTokenType: "OIDC_TOKEN_TYPE_JWT",
      accessTokenRoleAssertion: true,
      idTokenRoleAssertion: true,
      idTokenUserinfoAssertion: true
    }'
  )")"
  fail_on_error "$response" "creating the application"

  APP_ID="$(jq -r '.appId' <<<"$response")"
  CLIENT_ID="$(jq -r '.clientId' <<<"$response")"
  CLIENT_SECRET="$(jq -r '.clientSecret // empty' <<<"$response")"
  echo "app        $APP_NAME ($APP_ID) created"
else
  CLIENT_ID="$(api GET "/management/v1/projects/$PROJECT_ID/apps/$APP_ID" | jq -r '.app.oidcConfig.clientId')"
  echo "app        $APP_NAME ($APP_ID) already there"
fi

# The secret is shown once, at creation. A re-run against an application that
# already exists has no way to recover it, so it mints a new one — which is
# also the recovery path for a secret somebody lost.
if [[ -z "$CLIENT_SECRET" ]]; then
  response="$(api POST "/management/v1/projects/$PROJECT_ID/apps/$APP_ID/oidc_config/_generate_client_secret" '{}')"
  fail_on_error "$response" "generating a client secret"
  CLIENT_SECRET="$(jq -r '.clientSecret' <<<"$response")"
  echo "secret     regenerated"
fi

# ===== A role, and somebody holding it =======================================
# Best effort: the node works without roles, and a deployment that manages its
# own authorizations should not have this script fighting it.

if [[ -n "$ROLE" ]]; then
  api POST "/management/v1/projects/$PROJECT_ID/roles" \
    "{\"roleKey\":\"$ROLE\",\"displayName\":\"$ROLE\",\"group\":\"\"}" >/dev/null || true

  user_id="$(api POST /management/v1/users/_search \
    '{"query":{"limit":100},"queries":[{"typeQuery":{"type":"TYPE_HUMAN"}}]}' |
    jq -r '.result[0].id // empty')"

  if [[ -n "$user_id" ]]; then
    api POST "/management/v1/users/$user_id/grants" \
      "{\"projectId\":\"$PROJECT_ID\",\"roleKeys\":[\"$ROLE\"]}" >/dev/null || true
    echo "role       $ROLE granted to the console user"
  fi
fi

# ===== A service account, for the machine-to-machine flow ====================
# The node itself does not read these: they are what a peer node, a CLI or a CI
# job presents to /api/v1/auth/token. Provisioned here because a flow nobody can
# try is a flow nobody will use, and creating one by hand is another console
# walkthrough with another set of fields to get wrong.

M2M_USER="${ZITADEL_M2M_USER:-alexandria-service}"

machine_id() {
  api POST /management/v1/users/_search \
    "{\"queries\":[{\"userNameQuery\":{\"userName\":\"$M2M_USER\",\"method\":\"TEXT_QUERY_METHOD_EQUALS\"}}]}" |
    jq -r '.result[0].id // empty'
}

MACHINE_ID="$(machine_id)"

if [[ -z "$MACHINE_ID" ]]; then
  # A JWT access token, so the node verifies it against the published keys
  # rather than paying an introspection round trip per call.
  response="$(api POST /management/v1/users/machine "$(
    jq -n --arg name "$M2M_USER" '{
      userName: $name,
      name: $name,
      description: "Machine-to-machine access to the alexandria API",
      accessTokenType: "ACCESS_TOKEN_TYPE_JWT"
    }'
  )")"
  fail_on_error "$response" "creating the service account"
  MACHINE_ID="$(jq -r '.userId' <<<"$response")"
  echo "service    $M2M_USER ($MACHINE_ID) created"
else
  echo "service    $M2M_USER ($MACHINE_ID) already there"
fi

# Its secret, like the application's, is shown once. Regenerated on every run
# for the same reason, and written to the same place.
response="$(api PUT "/management/v1/users/$MACHINE_ID/secret" '{}')"
fail_on_error "$response" "generating the service account secret"
M2M_CLIENT_ID="$(jq -r '.clientId' <<<"$response")"
M2M_CLIENT_SECRET="$(jq -r '.clientSecret' <<<"$response")"

if [[ -n "$ROLE" ]]; then
  api POST "/management/v1/users/$MACHINE_ID/grants" \
    "{\"projectId\":\"$PROJECT_ID\",\"roleKeys\":[\"$ROLE\"]}" >/dev/null || true
fi

# ===== What the node reads ===================================================
# Into .env rather than into config/config.yaml: that file is committed, and a
# client secret does not belong in it. Task loads this automatically.

# Read before the file is written, not inside the heredoc: the redirection
# truncates the file first, so a key read from there would always come back
# empty and every run would end every open session.
SESSION_KEY=""

if [[ -f "$ENV_FILE" ]]; then
  SESSION_KEY="$(sed -n 's/^ALEXANDRIA_AUTH_CONFIG_SESSION_KEY=//p' "$ENV_FILE" | head -n 1)"
fi

if [[ -z "$SESSION_KEY" ]]; then
  SESSION_KEY="$(openssl rand -hex 32)"
fi

cat > "$ENV_FILE" <<ENV
# Written by scripts/zitadel-bootstrap.sh. Not committed: it holds a client
# secret and the key that seals every session cookie. Task loads it for every
# task, so \`task dev\` picks these up with no further ceremony.
ALEXANDRIA_AUTH_CONFIG_ENABLED=true
ALEXANDRIA_AUTH_CONFIG_ISSUER=$ISSUER
ALEXANDRIA_AUTH_CONFIG_CLIENT_ID=$CLIENT_ID
ALEXANDRIA_AUTH_CONFIG_CLIENT_SECRET=$CLIENT_SECRET
ALEXANDRIA_AUTH_CONFIG_SESSION_KEY=$SESSION_KEY

# The service account, for the machine-to-machine flow. Read by nothing — these
# are the credentials you hand to a peer node, a CLI or a CI job, which posts
# them to /api/v1/auth/token.
ZITADEL_M2M_CLIENT_ID=$M2M_CLIENT_ID
ZITADEL_M2M_CLIENT_SECRET=$M2M_CLIENT_SECRET
ENV

echo "client id  $CLIENT_ID"
echo "written    $ENV_FILE"
