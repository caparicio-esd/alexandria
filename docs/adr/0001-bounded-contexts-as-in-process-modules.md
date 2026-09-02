# 0001. Bounded contexts are in-process modules, not services

Status: Accepted
Date: 2026-08-29

## Context

Alexandria is a vocabulary hub. What exists today is the identity and
authorization layer that has to come first; the vocabulary work is a second
bounded context that will sit alongside it, and there will be more after that —
this node is one of several in a dataspace whose siblings already split catalog,
contracts, transfer and gateway apart.

The pull towards making each of those a service of its own is strong, and the
sibling projects have felt it. Against that: there is one team, one deployment,
and no context that has a different scaling profile from the others. A network
boundary drawn now would buy independent deployment nobody has asked for, and
cost a distributed transaction, a second failure mode and a second set of
credentials on every call that crosses it.

## Decision

Each bounded context is a Go package under `internal/` that assembles itself:
`ssi-auth` and `auth-proxy` today. Every one exposes the same three things — a
`Deps` struct of what it needs from outside, a `New` that returns an assembled
`Module`, and `Start`/`Close`. `cmd/alexandria` is the only place that knows all
of them exist.

A module is a composition root of its own. It takes the whole `*config.Config`
and picks out its own sections; the root does not hand it a narrowed struct, and
nothing else reaches inside it. It registers its own readiness check and mounts
its own routes on the router it is given.

The boundary is enforced by convention and review, not by the compiler.

## Consequences

Turning one of these into a service later is a mechanical change: the seam is
already the module interface, and what would become a network call is already a
function call across a package boundary that nothing else crosses.

The compiler will not stop somebody importing `internal/ssi-auth/fafnir` from
`internal/auth-proxy`. Nothing today does, and nothing should; if that stops
being true, the answer is an import linter, not a service.

Startup is one process, which means one failure mode. A context that cannot
reach its dependency — the wallet, the identity provider — does not take the
node down: it retries in the background and reports itself not ready, and the
node answers 503 for what it cannot serve. That behaviour is why `Start` is
allowed to return before its dependencies answer.

## What would change this

A context whose load is genuinely different from the rest — the vocabulary
store under heavy read traffic while identity is idle — or a second team owning
one of them. Either makes independent deployment worth its price.
