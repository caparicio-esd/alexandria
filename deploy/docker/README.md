# Deploying with Docker

A whole node on one machine: the service, its database, the identity provider it
authenticates through, and the proxy that terminates TLS for both. Nothing here
is reachable from outside except through Caddy on ports 80 and 443.

This is not `docker-compose.dev.yaml` with the values changed. That file runs
the node on the host, against a certificate authority the project generates for
itself, with passwords that are committed on purpose. None of that survives
contact with a deployment, so the two files stay separate.

## What you need first

- A host with Docker and the compose plugin.
- Two DNS names pointing at it — one for the node, one for the identity
  provider. They must resolve publicly **before** the first start: Caddy issues
  from Let's Encrypt, which validates by connecting back on port 80.
- Ports 80 and 443 open.

## Setup

```sh
cd deploy/docker
cp .env.example .env
$EDITOR .env            # domains, passwords, master key — every field is commented
```

The random values:

```sh
openssl rand -hex 32    # POSTGRES_PASSWORD, ZITADEL_DB_PASSWORD, session key
openssl rand -hex 16    # ZITADEL_MASTERKEY — exactly 32 characters
```

Then bring it up. This is a three-step dance, and it is unavoidable: Zitadel
generates the node's client id — it cannot be chosen — so the node has no
credentials to start with until the provider it authenticates against exists.

```sh
docker compose up -d    # the node starts without OAuth credentials and says so
bash bootstrap.sh       # registers the node in Zitadel, writes them into .env
docker compose up -d    # again, now that they exist
```

`bootstrap.sh` is idempotent. Run it again after changing a domain, or after
somebody deletes the application in the console, and it converges on the same
state without disturbing the session key.

## Afterwards

The node is at `https://$ALEXANDRIA_DOMAIN`, the Zitadel console at
`https://$AUTH_DOMAIN/ui/console`. Log into the console once with the
administrator from `.env` and change the password — Zitadel will insist.

```sh
docker compose logs -f alexandria
docker compose ps
```

## Upgrading

```sh
$EDITOR .env            # bump ALEXANDRIA_IMAGE to the new tag
docker compose pull alexandria
docker compose up -d alexandria
```

Pin a tag rather than tracking `:latest`. Tags are published by
`.github/workflows/release.yaml` on every `v*` git tag, and `:latest` moving
underneath a `docker compose pull` is a change to how every login behaves.

The same applies to `ZITADEL_VERSION`, more so: read its release notes before
moving it. It owns every account in the deployment.

## What must be backed up

- The `postgres-data` volume — the node's own data.
- The `zitadel-data` volume — every user, project and application.
- `.env`, and `ZITADEL_MASTERKEY` above all. It encrypts everything Zitadel
  stores, and there is no recovery from losing it: the database becomes
  unreadable with it gone. `caddy-data` is worth keeping too — losing it means
  re-issuing certificates, which Let's Encrypt rate-limits.

## What is deliberately not published

Postgres, Zitadel's database, and the node's internal listener — `/metrics` and
`/debug/pprof` on port 2112 — are reachable on the compose network and nowhere
else. Zitadel's own port is published on `127.0.0.1` only, so `bootstrap.sh` can
reach the management API from a shell on the host without waiting for a
certificate. Scrape metrics by joining the network, not by opening a port.

## The wallet

`WALLET_HOST` in `.env` is not part of this stack. The node links to an SSI
wallet at startup and comes up reporting itself not ready until it answers;
point that variable at wherever yours actually runs.
