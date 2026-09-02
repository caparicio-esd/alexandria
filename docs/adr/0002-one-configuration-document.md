# 0002. One configuration document, overridden from the environment

Status: Accepted
Date: 2026-08-29

## Context

This node runs in three shapes — a laptop, a Docker host, a Kubernetes cluster
— and it is also one of several services in a dataspace that share a deployment
file. Its sections have to be readable at the root of a document that describes
only this node, and nested under an `ssi_auth` key in a document that describes
five.

Secrets are the complication. The development configuration is committed, which
is only safe if no credential is ever the value that runs. A separate secrets
file is one more thing to keep in step; a settings-from-env-only design means
nothing about the deployment can be read without running it.

## Decision

One YAML document, loaded by Viper. `--config` wins, then `$ALEXANDRIA_CONFIG`,
then a search for `config.yaml` in `.`, `./config`, `/etc/alexandria`. The
loader accepts the sections at the root or nested, so both kinds of file work
unchanged.

Every key is overridable from the environment: the variable is `ALEXANDRIA_`
plus the dotted path, upper-cased. `ALEXANDRIA_COMMON_CONFIG_DB_PASSWORD` sets
`common_config.db.password`.

The split is by sensitivity, not by environment. Settings live in the document,
where they can be read and diffed. Secrets are empty there and come from the
environment: `.env` in development, a Secret in Kubernetes, `.env` again under
compose.

Defaults are registered on the loader rather than in the structs, so a document
written before a setting existed still loads and still behaves sensibly.

## Consequences

The deployment files under `deploy/` and `k8s/` are committed and carry no
credentials, and every one of them is a readable description of what the node
will do. The Helm chart renders the same document into a ConfigMap and injects
three variables from a Secret.

A setting can be overridden two ways, which means a value that surprises you has
two places to look. The convention that only secrets come from the environment
is what keeps that bounded — it is a convention, and nothing enforces it.

Viper's environment binding only sees keys that exist in the document or in the
defaults, so a typo in a variable name is silent. Every deployment file
therefore carries the full set of keys, placeholders included.

## What would change this

Vault holding key material for real — `is_vault_real` is the switch that is
already there and still false. That moves secrets out of the environment
entirely and leaves the document doing only what it does well.
