# 0005. TLS is terminated by a proxy, in development too

Status: Accepted
Date: 2026-09-02

## Context

The session cookie of [0004](0004-authentication-terminated-at-the-node.md) has
to carry `Secure` in a deployment. On `http://localhost` it cannot, so the usual
arrangement is a setting that is `false` locally and `true` in the deployment
file — which is exactly how a `Secure`-flag bug reaches production unnoticed:
nothing that runs on a laptop ever exercises the production value.

The same is true of the OAuth redirect URI, of `SameSite` behaviour, and of
anything that reads the forwarded host.

## Decision

Development runs behind a TLS terminator, the same way a deployment does. Caddy
holds the certificate; the node and Zitadel speak plain HTTP behind it. The
node's `internal_port` is what the process binds; `port` is what the world sees.

The names come from [nip.io](https://nip.io) —
`alexandria.127.0.0.1.nip.io` resolves to `127.0.0.1` — so there is no
`/etc/hosts` to edit. A `.localhost` name would need one: curl and browsers
resolve those themselves, Go does not.

The certificates are issued by an authority the project generates into `.certs/`
with `task tls:ca` and that the machine trusts once with `task tls:trust`. The
authority lives in the repository rather than in the machine's Caddy directory,
so a checkout carries what it needs and nothing points outside it. `.certs/` is
gitignored: committing a signing key would hand anyone who clones the repository
the ability to impersonate any site on every machine that trusts it.

Port 8443, not 443: Docker Desktop only forwards privileged ports when a setting
is on, and when it is off the connection is reset mid-handshake with no error
anywhere.

## Consequences

`session.secure` is `true` in the development configuration and in every
deployment file. There is no environment-conditional cookie setting to get
wrong.

Setup costs one `sudo`, once per machine, and a developer who skips it gets a
node that cannot reach its own issuer. `task dev:auto` checks for exactly that
and says so rather than failing obscurely.

The Kubernetes development values are the one exception: they run plain HTTP.
Issuing for a nip.io name from a cluster with no public address does not work,
and a self-signed one means every client needs the root — which is this
decision, outside Kubernetes, already. The consequence is stated in
[deploy/k8s/README.md](../../deploy/k8s/README.md) rather than hidden.

## What would change this

Nothing foreseeable. The cost is one command per machine and the thing it buys —
that the security-relevant settings are the same everywhere — is the whole
point.
