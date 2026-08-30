# alexandria

A vocabulary hub for a dataspace.

**Current state:** the identity and authorization layer is what exists today.
The node holds a decentralised identifier, serves the DID Document that makes it
resolvable, and delegates key material to an external wallet. The vocabulary
work comes next, as a second bounded context alongside it.

## Requirements

- Go 1.26 or later
- Docker, for the local Postgres
- [Task](https://taskfile.dev) (optional, for the shortcuts)
- A Fafnir wallet reachable over HTTP

## Usage

```bash
task db:up          # start the local Postgres and wait for it
task dev            # hot reload with air
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
$ curl -s localhost:1200/readyz | jq -c '.checks.database'
{"status":"failing","error":"database unreachable: ... connection refused"}
$ task db:up
$ curl -s localhost:1200/readyz | jq -c '.checks.database'
{"status":"ok"}
```

## Endpoints

| Path | Port | Purpose |
| --- | --- | --- |
| `/healthz` | api | Liveness. Checks nothing external: a failure means restart me. |
| `/readyz` | api | Readiness. Runs the dependency checks and names the failing one. |
| `/ssi-auth/wallet/*` | api | The wallet API. |
| `/.well-known/did.json` | api | The DID Document, as did:web resolution expects it. |
| `/metrics` | internal | Prometheus scrape endpoint. |
| `/debug/pprof/*` | internal | Profiling. Off by default. |

The internal port is separate on purpose: publishing the API must not publish
the diagnostics, and a heap profile names everything the process has in memory.

Liveness and readiness are not interchangeable. A wallet outage must fail
readiness — take the node out of the load balancer — and must never fail
liveness, which would restart every replica in a loop and make the incident
worse.

```console
$ curl localhost:1200/readyz
{"status":"unavailable","checks":{"wallet":{"status":"failing","error":"no identity established: not ready"}}}
```

## Startup

The node blocks for `wallet_config.startup_link_timeout` trying to acquire its
identity from the wallet, retrying on a capped exponential backoff. Past that
budget it comes up anyway, reports itself not ready and keeps trying in the
background: a node and its wallet usually start together, so a short wait
catches the common case, while refusing to start would only produce a restart
loop.

## Observability

**Logs** are structured through `log/slog` — text on a terminal, JSON anywhere
else, which is what both a developer and a log aggregator want. Every record
carries the module and component that emitted it, mirroring the package layout,
plus the request id where there is one:

```json
{"level":"WARN","msg":"request","module":"ssi-auth","component":"rest",
 "status":412,"route":"/ssi-auth/wallet/did","err":"wallet is not linked",
 "request_id":"peer-42"}
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

- `http_server_request_duration_seconds` — labelled by route *template*, never
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
internal/ssi-auth/         The identity bounded context:
  wallet/                    domain, entities and ports — imports no framework
  fafnir/                    driven adapter, the external wallet over HTTP
  rest/                      driving adapter, the HTTP API and its middleware
migrations/                Database migrations.
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
  -p 1200:1200 -p 2112:2112 \
  alexandria
```

The image carries no configuration, so mount one where the search path expects
it — or point `$ALEXANDRIA_CONFIG` at it. Without a document the node exits
rather than starting on guessed defaults.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
