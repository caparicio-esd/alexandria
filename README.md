# Alexandria Vocabulary Hub

![banner alexandria](./docs/static/banner.png)

<!-- State of the code: what CI says, what version is out, how to get it. -->

[![ci](https://github.com/caparicio-esd/alexandria/actions/workflows/ci.yaml/badge.svg)](https://github.com/caparicio-esd/alexandria/actions/workflows/ci.yaml)
[![release](https://github.com/caparicio-esd/alexandria/actions/workflows/release.yaml/badge.svg)](https://github.com/caparicio-esd/alexandria/actions/workflows/release.yaml)
[![go report card](https://goreportcard.com/badge/github.com/caparicio-esd/alexandria)](https://goreportcard.com/report/github.com/caparicio-esd/alexandria)
[![go reference](https://pkg.go.dev/badge/github.com/caparicio-esd/alexandria.svg)](https://pkg.go.dev/github.com/caparicio-esd/alexandria)
[![version](https://img.shields.io/github/v/tag/caparicio-esd/alexandria?label=version&sort=semver&color=blue)](https://github.com/caparicio-esd/alexandria/tags)
[![container](https://img.shields.io/badge/quay.io-alexandria-EE0000?logo=redhat&logoColor=white)](https://quay.io/repository/alexandria/alexandria)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![last commit](https://img.shields.io/github/last-commit/caparicio-esd/alexandria?color=6f42c1)](https://github.com/caparicio-esd/alexandria/commits/main)
[![issues](https://img.shields.io/github/issues/caparicio-esd/alexandria)](https://github.com/caparicio-esd/alexandria/issues)

<!-- What it is built on, and what it deploys onto. -->

[![go](https://img.shields.io/github/go-mod/go-version/caparicio-esd/alexandria?logo=go&logoColor=white&label=go)](go.mod)
[![postgres](https://img.shields.io/badge/postgres-17-4169E1?logo=postgresql&logoColor=white)](docker-compose.dev.yaml)
[![zitadel](https://img.shields.io/badge/zitadel-v4-2b3990?logo=auth0&logoColor=white)](#authentication)
[![caddy](https://img.shields.io/badge/caddy-2-1F88C0?logo=caddy&logoColor=white)](Caddyfile)
[![docker](https://img.shields.io/badge/docker-compose-2496ED?logo=docker&logoColor=white)](deploy/docker/README.md)
[![helm](https://img.shields.io/badge/helm-chart-0F1689?logo=helm&logoColor=white)](deploy/k8s/README.md)
[![kubernetes](https://img.shields.io/badge/kubernetes-ready-326CE5?logo=kubernetes&logoColor=white)](deploy/k8s/README.md)
[![task](https://img.shields.io/badge/task-runner-29BEB0?logo=task&logoColor=white)](Taskfile.yaml)
[![adr](https://img.shields.io/badge/decisions-ADR-informational)](docs/adr/README.md)

An IDS Vocabulary Hub: the service a dataspace uses to host, maintain, publish
and dereference the vocabularies its participants describe data with.

**Current state:** the identity and authorization layer is what exists today.
The node holds a decentralised identifier, serves the DID Document that makes it
resolvable, and delegates key material to an external wallet. Access to its API
is closed behind a Zitadel the caller never addresses directly — see
[Authentication](#authentication). The vocabulary work comes next, as a second
bounded context alongside it.

## What a vocabulary hub is for

Interoperability in an IDS dataspace rests on participants using the same terms
to describe data, services and contracts. Collections of those terms are
vocabularies, and the IDS Information Model is the one every participant shares
— which makes it, by construction, the lowest common denominator. Any specific
domain needs more than that.

A Vocabulary Hub is where the additional vocabularies live. It exists because
extending the Information Model is only useful if the extensions are published
and reachable the same way the core one is.

It has two jobs.

**Maintaining vocabularies.** Domain experts create, refine, document and
publish their terms here, and import third-party vocabularies so connectors can
use them. Terms are expected to be RDF; Linked Data conventions and formal
ontologies are encouraged and not enforced. What the hub gives back is access to
a whole vocabulary, a part of it, or an individual term.

**Runtime lookups.** A connector reading a Self-Description meets an attribute
whose IRI means nothing to it. It dereferences that IRI at the hub and gets back
a small RDF document: the term's class, its labels in whatever languages exist,
a short description. The meaning arrives at the point it is needed rather than
being agreed in advance.

The same lookup works a namespace at a time. Asking for an unknown namespace —
the way the Information Model uses `ids`
([w3id.org/idsa/core](http://w3id.org/idsa/core/)) and `idsc`
([w3id.org/idsa/code](http://w3id.org/idsa/code/)) — returns the whole
vocabulary with the relations between its terms. That document is larger, and a
connector that caches it stops asking, which is usually the cheaper trade.

## Requirements

| | Why |
|---|---|
| Go 1.26 or later | Builds the node |
| Docker | Runs Postgres, Zitadel and the TLS terminator |
| [Task](https://taskfile.dev) | Every command below |
| `openssl` | Generates the local certificate authority. Ships with macOS and every Linux |
| `jq`, `curl` | Used by `scripts/zitadel-bootstrap.sh` to drive Zitadel's API |
| — | The Fafnir wallet is brought up by `docker-compose.dev.yaml`; the node comes up without one and reports itself not ready |

Task is not optional any more, unlike earlier versions of this file: it loads
`.env` and points `docker compose` at `docker-compose.dev.yaml`, so the commands
underneath it are longer than they look.

## Getting the environment up

From a fresh checkout. The first command is the only one that needs sudo, and
only once per machine:

```bash
task tls:trust        # generate the project's local CA and trust it
task db:up            # Postgres for the node
task tls:up           # Caddy, the TLS terminator in front of everything
task auth:bootstrap   # Zitadel, provisioned; credentials written to .env
task dev              # the node, with hot reload
```

They are separate on purpose. TLS fronts the node whether or not authentication
is enabled, so it is not a dependency of `auth:bootstrap` — and provisioning
talks to Zitadel directly, so it works with Caddy down and before the authority
is trusted. Only the browser and the node itself need that trust.

After the first time, one command does all of it — it stops a node left running
from yesterday, brings the services up, re-provisions whatever drifted, and
starts the node:

```bash
task dev:auto
```

Then log in at:

```
https://alexandria.127.0.0.1.nip.io:8443/api/v1/auth/login
```

with `admin@alexandria.auth.127.0.0.1.nip.io` / `Password1!`.

What each one does, and what it leaves behind, is in [TLS](#tls) and
[Authentication](#authentication) below. To take it all down again:

```bash
task auth:reset       # destroys Zitadel's data and provisions it again
task db:reset         # destroys the node's database
docker compose -f docker-compose.dev.yaml down          # stop everything
docker compose -f docker-compose.dev.yaml down -v       # and delete every volume
```

## Usage

```bash
task dev:auto       # the whole environment, then the node
task dev            # just the node, hot reloading with air
```

```bash
task run            # run the application
task build          # build the binary into bin/alexandria
task check          # format + lint + tests

task db:up          # start Postgres, waiting until it accepts connections
task db:down        # stop it, keeping the data
task db:reset       # destroy the volume and start over
task db:psql        # a psql shell on it
task db:logs        # follow its logs

task auth:bootstrap # start Zitadel, provision it, and write .env
task auth:reset     # destroy it and provision a fresh one
task auth:up        # just start it
task auth:down      # stop it, keeping its data
task auth:console   # open the Zitadel console
task auth:logs      # follow its logs

task tls:ca         # create .certs/ — the project's certificate authority
task tls:trust      # trust it on this machine (sudo, once)
task tls:up         # just start Caddy
task tls:logs       # follow its logs
```

Without Task:

```bash
go run ./cmd/alexandria
go build -o bin/alexandria ./cmd/alexandria
go test -race ./...
go tool golangci-lint run
```

## Configuration

The node reads one flat YAML document. It is resolved in this order:

1. `--config <path>`
2. `$ALEXANDRIA_CONFIG`
3. `config.yaml` in `.`, `./config` or `/etc/alexandria`

[`config/config.yaml`](config/config.yaml) is the local development file and the
reference for every setting.

**Decoding is strict**: an unknown key is a startup error, not a shrug. A typo
that silently leaves a setting at its default is the worst kind of outage.

### Overriding from the environment

Any setting can be overridden without editing the file. The variable is
`ALEXANDRIA_` plus the dotted path, upper-cased, with underscores for dots:

```bash
ALEXANDRIA_WALLET_CONFIG_API_HTTP_PORT=7001 task dev
ALEXANDRIA_OBSERVABILITY_LOG_LEVEL=debug task dev
```

A key that appears in neither the file nor the defaults cannot be introduced by
the environment alone: the override applies to what the configuration already
declares.

### Credentials

The document holds them: `common_config.db` carries the user, password and
database name, and `common_config.admin_seed` the first tenant. That is a
deliberate trade. A deployment renders its own file — with Helm, or by mounting
one into the container — so the password that reaches production is generated
there and never exists in the repository.

**The file in this repository is committed, so what it holds is a development
password and nothing else.** Where a deployment would rather inject a secret
than render it, the environment override is the escape hatch:

```bash
ALEXANDRIA_COMMON_CONFIG_DB_PASSWORD=... alexandria
```

Key material is separate and still comes from Vault at run time.

Nothing prints a connection string: the pool logs `db.Redacted()`, because a DSN
in a log line is a password in a log aggregator, read by more people than the
database ever was.

## Database

`docker-compose.yaml` runs a Postgres for local development, on `127.0.0.1:1500`
to stay clear of anything else already bound. Its credentials mirror
`common_config.db`, which is where the node reads them from, and
and `max_conns` and `conn_max_lifetime` bound the pool — an unbounded pool is
how a traffic burst turns into "too many clients already" for everything else
sharing the server.

The pool is lazy and self-healing: pgx dials on first use and reconnects on its
own, so a database that is down at boot is not a reason to refuse to start. The
node logs a warning, comes up, fails readiness, and clears it by itself once the
server is back — no restart.

```console
$ task db:down && task dev
WARN  database unreachable at boot; the pool will keep retrying
$ curl -s https://alexandria.127.0.0.1.nip.io:8443/readyz | jq -c '.checks.database'
{"status":"failing","error":"database unreachable: ... connection refused"}
$ task db:up
$ curl -s https://alexandria.127.0.0.1.nip.io:8443/readyz | jq -c '.checks.database'
{"status":"ok"}
```

## Endpoints

| Path                    | Port     | Purpose                                                          |
| ----------------------- | -------- | ---------------------------------------------------------------- |
| `/healthz`              | api      | Liveness. Checks nothing external: a failure means restart me.   |
| `/readyz`               | api      | Readiness. Runs the dependency checks and names the failing one. |
| `/api/v1/auth/*`        | api      | The authentication proxy. See below.                             |
| `/ssi-auth/wallet/*`    | api      | The wallet API.                                                  |
| `/.well-known/did.json` | api      | The DID Document, as did:web resolution expects it.              |
| `/metrics`              | internal | Prometheus scrape endpoint.                                      |
| `/debug/pprof/*`        | internal | Profiling. Off by default.                                       |

The internal port is separate on purpose: publishing the API must not publish
the diagnostics, and a heap profile names everything the process has in memory.

Liveness and readiness are not interchangeable. A wallet outage must fail
readiness — take the node out of the load balancer — and must never fail
liveness, which would restart every replica in a loop and make the incident
worse.

```console
$ curl https://alexandria.127.0.0.1.nip.io:8443/readyz
{"status":"unavailable","checks":{"wallet":{"status":"failing","error":"no identity established: not ready"}}}
```

## TLS

Everything is served over HTTPS locally, through a Caddy in front:

```
browser ──https──► caddy :8443 ──http──► alexandria :1234   (on the host)
                          └─────http──► zitadel :8080      (a container)
```

It is not decoration. The session cookie carries the `Secure` attribute, which
means it cannot be tested at all over plain HTTP — and a setting that has to be
wrong locally and right in production is a setting that reaches production wrong.
The node itself has no TLS code: it listens in the clear on `internal_port` and
`has_tls_proxy: true` tells it to describe itself as https-fronted.

**The certificate authority lives in the project**, at `.certs/`, generated by
`task tls:ca`:

```
.certs/root.crt   the root certificate — public, this is what gets trusted
.certs/root.key   its signing key
```

Together they are the authority itself, not a server certificate: Caddy mints the
per-name certificates from them as it goes. `.certs/` is gitignored and the key is
written `600` — a committed CA is an impersonation kit for every machine that
trusted it.

`task tls:trust` installs the root into the system store. Only two things need
that trust — the browser, and the node when it calls its identity provider;
`task auth:bootstrap` does not, because it reaches Zitadel directly rather than
through Caddy. The step needs sudo, once per machine, and there is no way around
it: telling a machine to trust a new
authority is exactly the kind of change that should require an administrator.
Until it runs, every client refuses the connection, correctly:

```console
$ curl https://auth.127.0.0.1.nip.io:8443/
curl: (60) SSL certificate problem: unable to get local issuer certificate
```

**The names are nip.io.** `anything.127.0.0.1.nip.io` resolves to `127.0.0.1`
through public DNS, which is what keeps this working with no entry in
`/etc/hosts`. The obvious choice — `.localhost` — is resolved by curl and by
browsers but **not by Go**, so the node could not reach its own identity provider.
The cost is a dependency on an external DNS service; offline, the names do not
resolve.

**The port is 8443, not 443**, because Docker Desktop only forwards privileged
ports with its "allow privileged port mapping" setting on, and with it off the
connection is reset mid-handshake with nothing in any log. Set `TLS_PORT=443` if
yours allows it.

Both names and the port are overridable — `ZITADEL_DOMAIN`, `TLS_PORT` — but they
appear in four places that must agree: the `Caddyfile`, the compose file,
`auth_config.issuer` and `common_config.hosts.http`. Change them together, then
`task auth:reset`, because Zitadel stores the domain of its instance.

## Authentication

Identity comes from [Zitadel](https://github.com/zitadel/zitadel), and **nothing
outside this node ever addresses it**. There is no provider URL in a frontend's
configuration, no token in a browser's storage, and no second origin for a
client to be redirected to and back from. A caller talks to `/api/v1/auth`; this
process talks to Zitadel.

That is the point of the design, not a detail of it. The provider's address, its
client secret and its token vocabulary are deployment configuration **on this
side only** — moving Zitadel onto a private network, or replacing it with
another OpenID Provider, changes one YAML block and nothing any client ever
sees.

With `auth_config.enabled` on, every route under `/api/v1` is refused without a
credential — including the ones a module mounts later, because the guard is
installed on the versioned group itself rather than route by route. The only
exceptions are the routes that exist to obtain a credential, and the probes,
which sit outside the prefix entirely.

| Route                       | Purpose                                                                                                     |
| --------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `GET /api/v1/auth/login`    | Starts the authorization code flow. Redirects, or answers `{"authorization_url": …}` with `?response=json`. |
| `GET /api/v1/auth/callback` | Completes it, seals the session cookie, redirects to `return_to` or `app_url`.                              |
| `POST /api/v1/auth/refresh` | Renews the session from its refresh token.                                                                  |
| `POST /api/v1/auth/logout`  | Clears the cookie and revokes the refresh token at the provider.                                            |
| `POST /api/v1/auth/token`   | Proxies the client credentials grant, for a service account or a peer node.                                 |
| `GET /api/v1/auth/session`  | Who the caller is, with no token in the answer.                                                             |
| `GET /api/v1/auth/userinfo` | The provider's own view of the caller.                                                                      |

### The flow

```
browser                     alexandria                    zitadel
   │  GET /api/v1/auth/login    │                            │
   ├───────────────────────────►│  mint state, nonce, pkce   │
   │  302 + flow cookie (sealed)│                            │
   │◄───────────────────────────┤                            │
   │  GET /oauth/v2/authorize ─────────────────────────────► │
   │◄──────────────────────────────────── 302 ?code&state ───┤
   │  GET /api/v1/auth/callback │                            │
   ├───────────────────────────►│  check state               │
   │                            │  POST /oauth/v2/token ────►│
   │                            │◄─── access + id + refresh ─┤
   │                            │  check nonce, verify jwt   │
   │  302 + session cookie      │                            │
   │◄───────────────────────────┤                            │
   │  GET /api/v1/anything      │                            │
   ├───────────────────────────►│  open cookie, verify, 200  │
```

**The browser holds a cookie, not a token.** The tokens live inside it, sealed
with AES-256-GCM under a key only this node has, `HttpOnly` so no script can
read it, and stamped with an expiry inside the sealed payload rather than only
in the `Max-Age` the browser controls. A stolen cookie is a session, not a
bearer credential that works anywhere else — and a logout revokes the refresh
token at the provider, so it does not outlive the click.

**Four things are checked before a session exists**, and each answers a
different attack: `state` (a callback that answers somebody else's login),
`nonce` (an ID token minted elsewhere and replayed here), the PKCE verifier (an
intercepted authorization code), and `return_to`, which is refused unless it is
a path or on the configured origin — an unvalidated one turns the login into a
phishing hop. The flow cookie carrying the first three is single-use: the
callback clears it whether it succeeds or fails.

**Sessions renew themselves.** The guard refreshes 30 seconds before the access
token expires rather than after a call fails, so an active session never
surfaces the token's lifetime to the user. `POST /auth/refresh` exists for a
client that would rather drive it, and is public — by the time it is needed the
access token is, by definition, no longer good enough to pass the guard.

**Verification is local.** Tokens are checked against the provider's JWKS with
no round trip per request, the key set refreshing on its own schedule so a
rotation needs no restart. Zitadel issues opaque access tokens unless the
application asks for JWTs, so `auth_config.introspect` defaults to `fallback`:
verify locally, and introspect only what is not a JWS. `always` trades a round
trip per request for seeing a revocation the instant it happens.

### Two credentials, one rule

A browser presents the sealed cookie; a peer node or a CLI presents
`Authorization: Bearer`. When both are on the same request the header wins: a
call that presents a Bearer token is asking to be seen as that token's subject,
even from a browser holding a session for somebody else.

Getting either one is [From nothing to a token](#from-nothing-to-a-token),
below.

### In a handler

Both credentials resolve to the same `identity.Principal` on the request
context, so a handler never learns which door its caller came through:

```go
principal := identity.FromContext(c.Request.Context())
principal.Subject      // the provider's stable id for the caller
principal.Roles        // flattened out of whatever shape the provider used
principal.Machine      // a service account, with no human behind it
```

`auth_config.required_roles` gates the whole API. A single route that needs more
says so where it is mounted:

```go
admin := group.Group("/admin", rest.RequireRole("operator"))
```

Authorization failures are 403, never 401: logging in again would not help, and
a client that cannot tell the two apart will loop trying.

### Settings

| Key                              | What it does                                                                                                                    |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `enabled`                        | The whole context. Off, nothing is protected and no provider is contacted.                                                      |
| `issuer`                         | The issuer every token must name. Checked against the discovery document, so a mismatch is refused rather than trusted.         |
| `internal_issuer`                | Where _this process_ reaches the provider, when that is not where the browser does — a container name against a published host. |
| `client_id` / `client_secret`    | This node's registered application. The secret never leaves the process.                                                        |
| `audiences`                      | The `aud` an access token must carry — the Zitadel project id. Empty accepts any, which is only safe as the sole relying party. |
| `scopes`                         | Requested at the authorization endpoint. `offline_access` is what earns a refresh token.                                        |
| `redirect_url`                   | This node's callback, exactly as registered in Zitadel.                                                                         |
| `app_url` / `post_logout_url`    | Where the browser lands after a login, and after a logout.                                                                      |
| `introspect`                     | `never` \| `fallback` \| `always`. See above.                                                                                   |
| `roles_claim` / `required_roles` | Where roles live, and which ones gate the whole API.                                                                            |
| `jwks_refresh` / `http_timeout`  | How often signing keys are re-read, and the bound on every provider call.                                                       |
| `startup_discovery_timeout`      | How long startup blocks on the provider before continuing in the background.                                                    |
| `session.*`                      | The cookie: `name`, `domain`, `path`, `secure`, `same_site`, `ttl`, and the 32-byte `key` that seals it.                        |

The rules tighten in production — `common_config.connection.is_prod` — where a
missing `session.key`, a cookie without `secure`, or a client with no secret are
startup errors rather than warnings. A key left empty outside production mints a
random one per process, which means every restart ends every session; that is
the point, since a process that generates its own key must not be one anybody
depends on.

### From nothing to a token

The whole procedure, start to finish. Step 2 is the only one you need on a
machine that has never run this.

**1. Tear it down** — only the auth stack; the node's own Postgres holds none of
this:

```bash
docker compose rm -sfv zitadel zitadel-db zitadel-init
docker volume rm -f alexandria_zitadel-data alexandria_zitadel-machinekey
rm -f .env
```

(`docker compose` needs `-f docker-compose.dev.yaml`, or the `COMPOSE_FILE` that
Task exports, outside a task.)

**2. Bring it up:**

```bash
task auth:bootstrap
```

Which is two things. `task auth:up` starts Zitadel — published on
`127.0.0.1:1600`, which is where this talks to it, so provisioning needs neither
the TLS terminator up nor its authority trusted — and waits
for it to answer — on an empty database it migrates, creates the organization,
the console user, and a machine user whose personal access token it writes into
a volume. Then the bootstrap copies that token out and uses it to create the
project, the application, a `reader` role, and a service account, writing every
credential to `.env`:

```console
project    alexandria (388876013762772995) created
app        alexandria-node (388876013880213507) created
role       reader granted to the console user
service    alexandria-service (388876343518953475) created
client id  388876013880279043
written    .env
```

`task auth:reset` is steps 1 and 2 in one command.

**3. Start the node.** Task loads `.env`, so there is nothing to export:

```bash
task dev
```

**4. Check it came up authenticated:**

```console
$ curl -s https://alexandria.127.0.0.1.nip.io:8443/readyz | jq -c '.checks.identity_provider'
{"status":"ok"}

$ curl -s -o /dev/null -w '%{http_code}\n' alexandria.127.0.0.1.nip.io:8443/api/v1/ssi-auth/wallet/did
401
```

A 401 there is the point of the exercise. If it is 503, the node has not reached
Zitadel yet.

### Logging in — a human

Open the login route in a browser. There is no curl equivalent, because the
password is typed into Zitadel's own form and this node never sees it:

```
https://alexandria.127.0.0.1.nip.io:8443/api/v1/auth/login
```

The default credentials are `admin@alexandria.127.0.0.1` / `Password1!` — the
username follows `ZITADEL_ADMIN_USER` and `ZITADEL_DOMAIN`. Zitadel will ask to
set up MFA on first login; skipping is fine locally.

You land back on `app_url` with the session cookie set. From then on the browser
carries it and nothing else:

```console
$ curl -sb "alexandria_session=<the cookie>" alexandria.127.0.0.1.nip.io:8443/api/v1/auth/session
{"subject":"388876…","username":"admin@alexandria.127.0.0.1","roles":["reader"],"machine":false,…}
```

The cookie is `HttpOnly`, so it is not readable from the console's JavaScript —
copy it from the network tab or the storage inspector if you want to drive the
API from a terminal. `POST /api/v1/auth/logout` ends it here and revokes it at
Zitadel.

### Logging in — a machine

No browser, no cookie, and still no Zitadel: the service account posts its
credentials to this node, which relays them.

```bash
set -a; . ./.env; set +a          # or just run it under `task`

token=$(curl -s -X POST alexandria.127.0.0.1.nip.io:8443/api/v1/auth/token \
  -d "client_id=$ZITADEL_M2M_CLIENT_ID" \
  -d "client_secret=$ZITADEL_M2M_CLIENT_SECRET" | jq -r .access_token)

curl -s -H "Authorization: Bearer $token" alexandria.127.0.0.1.nip.io:8443/api/v1/auth/session
```

```json
{ "subject": "388876343518953475", "machine": true, "roles": [], "scopes": [] }
```

`machine: true` is the node reporting a token with no human behind it. The empty
roles are worth knowing about: the service account **is** granted `reader` in
Zitadel — `task auth:bootstrap` does it, and the console shows the grant — but
Zitadel does not assert project roles into a client credentials token in this
configuration. Gate machine callers on the subject or on `machine` for now;
`required_roles` bites on human sessions.

Those credentials are the service account's own. A peer node in the dataspace
gets its own service account, and this node never learns its secret.

### What `.env` holds

```bash
ALEXANDRIA_AUTH_CONFIG_ENABLED=true          # read by the node
ALEXANDRIA_AUTH_CONFIG_ISSUER=…
ALEXANDRIA_AUTH_CONFIG_CLIENT_ID=…           # generated by Zitadel
ALEXANDRIA_AUTH_CONFIG_CLIENT_SECRET=…
ALEXANDRIA_AUTH_CONFIG_SESSION_KEY=…         # seals the session cookie
ZITADEL_M2M_CLIENT_ID=…                      # read by nothing; for you
ZITADEL_M2M_CLIENT_SECRET=…
```

The first five override `auth_config` in `config/config.yaml` by the usual
`ALEXANDRIA_` + dotted-path rule. The file is gitignored: settings live in the
committed YAML, secrets live here.

Re-running the bootstrap is safe. It finds what exists, mints fresh secrets —
which is also how you recover one that was lost, since Zitadel shows them only
at creation — and keeps the session key, so open sessions survive.

### When it goes wrong

| Symptom                                                   | Cause                                                                                                                                             |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Errors.App.NotFound` at Zitadel                          | The `client_id` does not exist there. Usually a `.env` from an instance that was since reset — re-run `task auth:bootstrap` and restart the node. |
| The node refuses to start, naming `auth_config.client_id` | No `.env`. Run `task auth:bootstrap`.                                                                                                             |
| `No personal access token found`                          | The instance predates the machine user. `task auth:reset`, or pass `ZITADEL_PAT=…`.                                                               |
| Every route answers 503                                   | The node has not reached Zitadel. It keeps retrying; check `task auth:logs`.                                                                      |
| A running `task dev` still fails after a reset            | It holds the old `.env` in its environment. Restart it.                                                                                           |

### Doing it by hand

Without the script: in the console, create a project, then a **Web** application
with authentication method **CODE**, redirect URI
`https://alexandria.127.0.0.1.nip.io:8443/api/v1/auth/callback`, **Development Mode** on so a
plain-http URI is accepted, and _user roles inside ID token_ under its token
settings. Copy the generated client id and secret into `.env`. For the machine
flow, add a service user and generate a client secret for it.

Every value the Zitadel containers read is overridable the way the Postgres ones
are — `ZITADEL_VERSION`, `ZITADEL_DB_USER`, `ZITADEL_DB_PASSWORD`,
`ZITADEL_DB_NAME`, `ZITADEL_MASTERKEY`, `ZITADEL_DOMAIN`, `ZITADEL_PORT`,
`ZITADEL_ORG`, `ZITADEL_ADMIN_USER`, `ZITADEL_ADMIN_PASSWORD` — so a second
checkout runs its own without editing the file. Moving the domain or the port
means moving `auth_config.issuer` with it, or discovery is refused:

```bash
ZITADEL_PORT=1700 docker compose up -d --wait zitadel
ALEXANDRIA_AUTH_CONFIG_ISSUER=http://127.0.0.1:1700 task auth:bootstrap
```

### When the provider is down

The node comes up anyway. It reports itself not ready, keeps retrying on a
capped backoff, and clears the check by itself once Zitadel answers — the same
posture as the wallet and the database, for the same reason: refusing to start
turns one outage into a restart loop.

While it is down the guard answers **503, not 401**. Telling a client its
perfectly good credential is bad would have it throw the session away over an
outage that is about to clear.

```console
$ curl -s https://alexandria.127.0.0.1.nip.io:8443/readyz | jq -c '.checks.identity_provider'
{"status":"failing","error":"identity provider not reached: not ready"}
```

The startup report says which provider the node loaded, and says plainly when it
loaded none — a node with an open API is the one fact nobody should have to
infer:

```
auth      https://auth.127.0.0.1.nip.io:8443 · client 388970273631698947
auth      disabled · api open
```

## Startup

The node blocks for `wallet_config.startup_link_timeout` trying to acquire its
identity from the wallet, retrying on a capped exponential backoff. Past that
budget it comes up anyway, reports itself not ready and keeps trying in the
background: a node and its wallet usually start together, so a short wait
catches the common case, while refusing to start would only produce a restart
loop.

The identity provider is acquired the same way, on
`auth_config.startup_discovery_timeout`, and so is the database connection. One
posture for all three dependencies: block briefly, then come up degraded and say
so through readiness. Nothing this node talks to is a reason to refuse to
start.

## Observability

**Logs** are structured through `log/slog` — text on a terminal, JSON anywhere
else, which is what both a developer and a log aggregator want. Every record
carries the module and component that emitted it, mirroring the package layout,
plus the request id where there is one:

```json
{
  "level": "WARN",
  "msg": "request",
  "module": "ssi-auth",
  "component": "rest",
  "status": 412,
  "route": "/ssi-auth/wallet/did",
  "err": "wallet is not linked",
  "request_id": "peer-42"
}
```

The access log's severity follows the status class — 5xx is an error, 4xx a
warning — so a failure is visible as a failure rather than as an INFO line that
happens to carry a 404. An inbound `X-Request-Id` is honoured rather than
replaced, so a call from another node stays correlated end to end. The probes
log at debug: an orchestrator polls them every few seconds, and escalating a
readiness 503 during startup trains everyone to ignore errors.

**Metrics** come from the OpenTelemetry SDK through a Prometheus exporter — one
pipeline, so traces will hang off the same resource. Alongside the Go runtime
metrics:

- `http_server_request_duration_seconds` — labelled by route _template_, never
  the filled-in path, so identifiers stay out of the index and no caller can
  mint unbounded series.
- `http_server_active_requests`
- `alexandria_build_info{version}` — which build is running, for the moment a
  latency graph jumps.

## Layout

```
cmd/alexandria/            Composition root. Wiring only, no business logic.
internal/config/           Deployment document loader.
internal/httpapi/          Process-wide HTTP boundary: the health probes.
internal/observability/    Logging, metrics, health registry, internal listener.
internal/storage/          Persistence infrastructure: the Postgres pool.
internal/auth-proxy/       The authentication bounded context, and the guard:
  identity/                  the authenticated caller, carried on the context
  oidc/                      driven adapter, the OpenID Provider over HTTP
  session/                   the sealed cookie the browser carries
  token/                     credential to principal: JWKS, or introspection
  rest/                      driving adapter, /auth and the guard middleware
internal/ssi-auth/         The identity bounded context:
  wallet/                    domain, entities and ports — imports no framework
  fafnir/                    driven adapter, the external wallet over HTTP
  rest/                      driving adapter, the HTTP API and its middleware
migrations/                Database migrations.
scripts/                   Provisioning: the Zitadel bootstrap and the local CA.
deploy/docker/             Deployment on one host, with Docker and Caddy.
deploy/k8s/                Deployment on Kubernetes: the Helm chart.
docs/adr/                  Architecture decision records.
Caddyfile                  The local TLS terminator's configuration.
docker-compose.dev.yaml    Postgres, Zitadel and Caddy for development.
```

The architecture is hexagonal. `wallet` declares the ports and depends on
nothing; the adapters happen to satisfy them; `cmd/alexandria` wires the
concrete implementations once. `config` sits beside the hexagon rather than
inside it — it is an input to the composition root, not a layer — and no service
receives the whole `Config`, only the values it declared a dependency on.

`ssi-auth` is one bounded context, not the application. The process-wide seams
are deliberately separate from it so the vocabulary context can be added beside
it rather than inside it: `httpapi` owns the routes that describe the node,
each context mounts its own subtree under its own prefix, and `observability`
and `config` serve the process rather than any one context.

## Tooling

Tools are declared in the `tool` block of `go.mod` and run with `go tool <name>`,
so there is nothing to install globally and versions stay pinned in the
repository.

## Docker

```bash
docker build --build-arg VERSION=$(git describe --tags --always --dirty) -t alexandria .
docker run --rm \
  -v "$PWD/config:/etc/alexandria:ro" \
  -p 1234:1234 -p 2112:2112 \
  alexandria
```

The image carries no configuration, so mount one where the search path expects
it — or point `$ALEXANDRIA_CONFIG` at it. Without a document the node exits
rather than starting on guessed defaults.

Published images are built from this same Dockerfile by
[.github/workflows/release.yaml](.github/workflows/release.yaml) on every `v*`
tag, for `linux/amd64` and `linux/arm64`.

## Deploying

Three descriptions of how to run this, each honest about what it is for. The
reasoning is in [0006](docs/adr/0006-one-image-three-deployment-shapes.md).

| | For |
|---|---|
| [docker-compose.dev.yaml](docker-compose.dev.yaml) | Development. Infrastructure only — the node runs on the host under `task dev` |
| [deploy/docker/](deploy/docker/README.md) | One host, with Docker. The whole stack, Caddy issuing from Let's Encrypt |
| [deploy/k8s/](deploy/k8s/README.md) | A Helm chart, with the database and identity provider behind flags that are off by default |

Both deployments need a two-pass install, because Zitadel mints the OAuth client
id and it cannot be chosen. Neither pretends otherwise.

## Decisions

[docs/adr/](docs/adr/README.md) holds a record per decision that was expensive
to make and would be expensive to reverse — what was decided, what it costs, and
what would have to be true to decide otherwise. Start there rather than here if
you are trying to work out why something is the shape it is.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
