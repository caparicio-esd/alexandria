# alexandria

## Requisitos

- Go 1.26 o superior
- [Task](https://taskfile.dev) (opcional, para los atajos)

## Uso

```bash
task run            # ejecuta la aplicacion
task dev            # recarga en caliente con air
task build          # compila en bin/alexandria
task check          # formato + lint + tests
```

Sin Task:

```bash
go run ./cmd/alexandria
go build -o bin/alexandria ./cmd/alexandria
go test -race ./...
go tool golangci-lint run
```

## Estructura

```
cmd/alexandria/   Punto de entrada. Solo wiring, sin logica de negocio.
internal/         Codigo privado del modulo, no importable desde fuera.
migrations/       Migraciones de base de datos.
```

## Herramientas

Se declaran en el bloque `tool` de `go.mod` y se ejecutan con `go tool <nombre>`,
sin instalacion global y con versiones fijadas en el repositorio.

## Docker

```bash
docker build --build-arg VERSION=$(git describe --tags --always --dirty) -t alexandria .
docker run --rm alexandria
```
