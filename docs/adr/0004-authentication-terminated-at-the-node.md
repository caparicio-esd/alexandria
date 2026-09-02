# 0004. Authentication is terminated at the node, not at the client

Status: Accepted
Date: 2026-09-01

## Context

The API has to be closed. The conventional answer is that each client performs
the OpenID Connect flow itself, holds the token, and sends it as a bearer: the
browser gets a public client with PKCE, a peer node gets its own credentials.

That answer distributes the identity provider's address, the client id and the
flow across every client. Moving Zitadel, putting it on a private network, or
replacing it with another provider then becomes a change every client sees. It
also puts a token in browser storage, which is a token in reach of any script
that gets onto the page.

The node is already the only thing every caller talks to.

## Decision

The node is the relying party, and nothing outside it addresses the identity
provider.

A browser navigates to `/api/v1/auth/login`. This process holds the client
secret, walks the authorization code flow with PKCE, terminates the callback at
`/api/v1/auth/callback`, and hands back a sealed `HttpOnly` cookie — not a
token. A service account posts its credentials to `/api/v1/auth/token` and gets
an access token back without ever learning where Zitadel is. Everything else
under `/api/v1` passes the guard.

Verification is `introspect: fallback` by default: a JWT is verified locally
against cached JWKS, anything else is introspected. Zitadel issues opaque tokens
unless the application asks for JWTs, and this makes both work without a setting
to get wrong.

Discovery at startup follows the same rule as the wallet in
[0003](0003-key-material-lives-in-an-external-wallet.md): bounded wait, then up
anyway, not ready, retrying. The node answers 503 rather than 401 while the
provider is unreachable — an unavailable provider is not a rejected credential,
and a client that cannot tell the difference will retry the wrong thing.

## Consequences

The provider's address is deployment configuration on one side only. That is
what lets `internal_issuer` differ from `issuer` — the browser is sent to a
public name, the process reaches the same provider at a service name inside the
cluster — and it is what makes the Kubernetes and compose deployments possible
without hairpin routing.

The session cookie is sealed with a key that must be identical across replicas
and stable across restarts. That is a real operational obligation, and it is why
`auth.sessionKey` is required by the Helm chart rather than generated: a
generated key would log everyone out on every upgrade, silently.

The node is now on the critical path for authentication, and holds a client
secret it did not have to hold.

Roles come from `urn:zitadel:iam:org:project:roles`, which is a Zitadel-shaped
claim name in a place that otherwise names nothing vendor-specific. It is
configuration, so another provider is a values change.

## What would change this

A second relying party in the same deployment — a separate frontend that has to
authenticate on its own — makes the node a bottleneck rather than a
simplification.
