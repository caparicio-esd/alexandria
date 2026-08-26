# alexandria

## Requirements

- Go 1.26 or later
- [Task](https://taskfile.dev) (optional, for the shortcuts)

## Usage

```bash
task run            # run the application
task dev            # hot reload with air
task build          # build the binary into bin/alexandria
task check          # format + lint + tests
```

Without Task:

```bash
go run ./cmd/alexandria
go build -o bin/alexandria ./cmd/alexandria
go test -race ./...
go tool golangci-lint run
```

## Layout

```
cmd/alexandria/   Entry point. Wiring only, no business logic.
internal/         Module-private code, not importable from outside.
migrations/       Database migrations.
```

## Tooling

Tools are declared in the `tool` block of `go.mod` and run with `go tool <name>`,
so there is nothing to install globally and versions stay pinned in the repository.

## Docker

```bash
docker build --build-arg VERSION=$(git describe --tags --always --dirty) -t alexandria .
docker run --rm alexandria
```
