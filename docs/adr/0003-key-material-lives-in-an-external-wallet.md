# 0003. Key material lives in an external wallet

Status: Accepted
Date: 2026-08-31

## Context

The node holds a decentralised identifier and has to sign with it: DID
Documents, verifiable presentations, and eventually whatever the vocabulary
layer needs to attest. Something has to hold the private key.

Holding it in the process is the shortest path and the one that was not taken.
A key in the process is a key in every heap dump, every core file and every
`/debug/pprof/heap`; it is a key that has to be mounted into the container,
rotated by whatever rotates files, and backed up by whoever backs up volumes.
It also makes the node the wrong shape for the dataspace it belongs to, where
participants are expected to have a wallet.

## Decision

The node never holds a private key. It talks to an external SSI wallet — Fafnir
today, over HTTP — through an adapter in `internal/ssi-auth/fafnir`, behind a
port the `wallet` package owns. Signing and key generation happen there.

The link is established at startup and is allowed to fail. `startup_link_timeout`
bounds how long startup waits; past it the node comes up anyway, reports itself
not ready through `/readyz`, and keeps retrying in the background with a capped
backoff.

The wallet is not deployed by this repository. Every deployment file points at
one and none brings one up.

## Consequences

The node's most sensitive dependency is a network call, which means it is also a
failure mode: no wallet, no DID Document, no signing. Reporting not-ready rather
than refusing to start is what makes that survivable — an orchestrator holds
traffic off, the node keeps retrying, and it starts serving when the wallet
does.

`Fafnir` is a value in the configuration and an adapter behind a port, so a
second wallet implementation is a second adapter. Nothing above `internal/ssi-auth`
knows which one is in use.

Local development needs a wallet running somewhere, which is real friction and
the reason the node is built to come up without one.

## What would change this

Nothing short of the dataspace itself deciding that participants hold their own
keys, which would be a change to the model rather than to this node.
