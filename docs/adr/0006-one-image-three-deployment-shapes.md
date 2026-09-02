# 0006. One image, three deployment shapes

Status: Accepted
Date: 2026-09-02

## Context

The node has to run in three places: a developer's laptop, a single Docker host
belonging to someone who wants to deploy it themselves, and a Kubernetes
cluster. Those have genuinely different needs — hot reload against a local
authority, one machine with real certificates, a chart with probes and secrets
management — and the temptation is to serve all three from one parameterised
compose file.

That does not work. The development file runs the node on the host with
committed passwords against a certificate authority the project generated; none
of that survives contact with a deployment, and a file that tries to be both
ends up wrong in both.

## Decision

One image, built once per git tag by
[.github/workflows/release.yaml](../../.github/workflows/release.yaml) and
published to Quay for `linux/amd64` and `linux/arm64`. It is distroless and
runs as `nonroot`; it contains the binary and nothing else — no shell, no curl,
no configuration.

Three deployment descriptions, each honest about what it is for:

- [docker-compose.dev.yaml](../../docker-compose.dev.yaml) — infrastructure
  only. The node runs on the host, under `task dev`.
- [deploy/docker/](../../deploy/docker/) — the whole stack on one host, with
  Caddy issuing from Let's Encrypt.
- [deploy/k8s/](../../deploy/k8s/) — a Helm chart, with the database and identity provider
  behind flags that are off by default, because a real cluster usually has both
  already.

Configuration is mounted, never baked in: a bind mount under compose, a
ConfigMap under Kubernetes, both at `/etc/alexandria`. So the same published
image runs every deployment, and rolling back is a tag.

The image cross-compiles rather than emulating — the build stage runs on the
runner's architecture and Go targets the requested one — which makes the arm64
image a compile instead of an amd64 toolchain under QEMU.

## Consequences

Distroless means there is nothing inside the container to probe with. The
compose deployment therefore has no healthcheck for the node — Caddy retries the
upstream instead — while the chart has real `/healthz` and `/readyz` probes,
because there the kubelet probes from outside. That asymmetry is a consequence
of the base image, not an oversight.

Three files describing overlapping stacks will drift. What holds them together
is that all three configure the same node through the same keys, and the
`ALEXANDRIA_`-prefixed environment overrides of
[0002](0002-one-configuration-document.md) are the same mechanism in all of
them.

Both deployments need a two-pass install, because Zitadel mints the OAuth client
id and it cannot be chosen. Neither pretends otherwise: the compose README walks
through it and the chart says so in its install notes.

## What would change this

A second service in the same repository would make one image per service and a
shared chart library the right shape instead.
