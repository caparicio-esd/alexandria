# Deploying on Kubernetes

One chart, in [charts/alexandria](charts/alexandria): the node, and — behind
two flags that are off by default — the Postgres and the Zitadel it needs.

The two flags are off because a real cluster usually has both already: a managed
database with backups, and an identity provider shared across services. They
exist so that a first install, and the local development cluster below, can be
one command.

## The two-pass install

Zitadel mints the OAuth client id and it cannot be chosen, so the provider has
to exist before the node can be told what it is. Every install is therefore two
passes, and the chart says so in its install notes rather than pretending
otherwise.

```sh
helm dependency update deploy/k8s/charts/alexandria

helm upgrade --install alexandria deploy/k8s/charts/alexandria \
  --namespace alexandria --create-namespace \
  -f my-values.yaml \
  --set auth.sessionKey="$(openssl rand -hex 32)"
```

The node comes up and refuses everything under `/api/v1`, which is correct: it
has no credentials. Register it, using the same script development uses:

The script authenticates with a personal access token. Under compose it reads
the one the instance minted for itself out of a volume; there is no equivalent
here, so make one by hand — once per installation. In the console: **Users →
Service Users**, create one with the *Org Owner* role, then **Personal Access
Tokens → New**.

```sh
kubectl -n alexandria port-forward svc/alexandria-zitadel 8080:8080 &

ZITADEL_PAT=<the token> \
ZITADEL_API=http://127.0.0.1:8080 \
ZITADEL_ISSUER=https://auth.example.org \
REDIRECT_URI=https://alexandria.example.org/api/v1/auth/callback \
APP_URL=https://alexandria.example.org/ \
ENV_FILE=/tmp/alexandria.env \
  bash scripts/zitadel-bootstrap.sh
```

It writes `/tmp/alexandria.env`. Put `ALEXANDRIA_AUTH_CONFIG_CLIENT_ID` into
`auth.clientId` and the client secret into the Secret (see below), then upgrade
again.

## Where the secrets go

Three values are secret: the database password, the OAuth client secret, and the
session key that seals every cookie.

By default the chart renders them into a Secret from the values you pass, which
means the values file holding them is itself a secret and must not be committed.
For anything beyond a test cluster, set `existingSecret` to a Secret you manage
yourself — sealed-secrets, external-secrets, or by hand — carrying:

```
ALEXANDRIA_COMMON_CONFIG_DB_PASSWORD
ALEXANDRIA_AUTH_CONFIG_CLIENT_SECRET
ALEXANDRIA_AUTH_CONFIG_SESSION_KEY
```

The chart then never sees them and they never reach the release's stored
manifest. `auth.sessionKey` in particular must be stable: it is what every
replica seals cookies with, so a value regenerated on upgrade logs everyone out,
and a value that differs between replicas means a session works or does not
depending on which pod answers.

## Development, on a local cluster

[values-dev.yaml](charts/alexandria/values-dev.yaml) brings up everything —
node, database, identity provider — reachable over
[nip.io](https://nip.io), which resolves `anything.127.0.0.1.nip.io` to
`127.0.0.1`. So there is no DNS to run and no `/etc/hosts` to edit.

With kind, and an ingress controller that publishes on the host:

```sh
kind create cluster --config deploy/k8s/kind-cluster.yaml
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml
kubectl -n ingress-nginx wait --for=condition=ready pod \
  -l app.kubernetes.io/component=controller --timeout=180s

helm dependency update deploy/k8s/charts/alexandria
helm upgrade --install alexandria deploy/k8s/charts/alexandria \
  -f deploy/k8s/charts/alexandria/values-dev.yaml \
  --namespace alexandria --create-namespace \
  --set auth.sessionKey="$(openssl rand -hex 32)"
```

Then <http://alexandria.127.0.0.1.nip.io> and
<http://auth.127.0.0.1.nip.io/ui/console>, and the two-pass bootstrap above.

If the ingress controller is not on `127.0.0.1` — a cluster on another machine,
minikube without `minikube tunnel` — put its address in the names instead:

```sh
  --set ingress.host=alexandria.$(minikube ip).nip.io \
  --set auth.host=auth.$(minikube ip).nip.io
```

This is not the primary development path. `task dev:auto` at the repository root
is faster and gives you a hot-reloading binary on the host; this exists for
testing the chart itself and for reproducing something that only happens in a
cluster.

### It runs over plain http

Deliberately. A public certificate cannot be issued for a nip.io name pointing
at a cluster with no public address, and a self-signed one means every client
needs the root installed — which is the development story the repository
already has, with Caddy and `task tls:ca`, outside Kubernetes.

The one consequence is that the session cookie loses its `Secure` attribute.
Nothing else differs.

## Production

[values-prod.yaml](charts/alexandria/values-prod.yaml) is the shape of a
deployment rather than one: an external database, an identity provider that
already exists, cert-manager issuing the certificate, two replicas spread across
nodes, and the secrets in an `existingSecret`. Copy it and fill in the
addresses.

Pin `image.tag`. `:latest` moving underneath a `helm upgrade` is a change to how
every login behaves, and it is not what a rollback rolls back to. Tags are
published by [.github/workflows/release.yaml](../../.github/workflows/release.yaml)
on every `v*` git tag.

## What is deliberately not exposed

The internal listener — `/metrics` and, when switched on, `/debug/pprof` — is on
a second container port and a second Service port, and the Ingress routes
neither. Scrape it from inside the cluster, with `serviceMonitor.enabled=true`
if the Prometheus operator is installed.

## The wallet

The node's identity: it holds the private key and does the signing, and the node
never sees key material.

`wallet.deploy.enabled` puts one in the cluster, alongside the node. It is not a
subchart — the wallet publishes no chart of its own — so what the chart carries
is the minimum that runs it: a Deployment whose migration step is an init
container, a Service, its configuration, and a Secret holding the database
credential it reads while `is_vault_real` is false. No Ingress routes it.

It does **not** deploy a database. Point `wallet.deploy.database.host` at one
that exists; [values-dev.yaml](charts/alexandria/values-dev.yaml) creates a
logical database for it inside the bundled Postgres with an initdb script.

### The claim is the identity

While `is_vault_real` is false the wallet keeps private keys as **files**, one
per key id, under `VAULT_PATH`. Its Postgres holds only their metadata and the
DID records. So `wallet.deploy.persistence` — not the database — is what the
node's identity actually is, and the chart gives that claim a
`helm.sh/resource-policy: keep` so `helm uninstall` leaves it behind.

Losing the claim while keeping the database is the worse of the two failures:
the wallet goes on answering `/dids/default` with a DID it can no longer sign
with, so the node reports itself ready and every signature fails.

The Deployment is one replica with a `Recreate` strategy, because the claim is
ReadWriteOnce.

### Why production leaves it off

Two things make the bundled wallet a test-cluster story, and
[values-prod.yaml](charts/alexandria/values-prod.yaml) leaves it off for both:

- that claim has no backup of its own, and what it holds is not reissuable;
- the wallet's database credential is a Secret this chart renders, not a Vault.

## Probes

Liveness is `/healthz` and asks only whether the process is still serving. It
deliberately does not depend on the database or the identity provider: a
provider that goes away would otherwise restart every pod in a loop, which is
strictly worse than serving 503 until it comes back.

Readiness is `/readyz` and does depend on them, which is the point — the node
comes up before its wallet and its provider answer and reports itself not ready
until they do.

## A warning you can ignore

```
coalesce.go:289: warning: destination for zitadel.ingress.tls is a table.
```

Helm comparing this chart's `ingress.tls` table against the Zitadel subchart's
`ingress.tls` list while it merges values. Nothing is passed between them — the
rendered Zitadel Ingress is exactly what `zitadel.ingress` in the values says —
and the warning appears whether or not that subchart is enabled.
