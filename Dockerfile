FROM golang:1.26-alpine AS build

WORKDIR /src

# Cacheable dependency layer: only invalidated when go.mod/go.sum change.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 go build \
    -tags=jwx_es256k \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /alexandria ./cmd/alexandria

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /alexandria /alexandria
USER nonroot:nonroot
ENTRYPOINT ["/alexandria"]
