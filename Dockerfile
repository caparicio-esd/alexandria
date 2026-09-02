# Cross-compiles rather than emulating: the build stage always runs on the
# runner's own architecture ($BUILDPLATFORM) and Go targets the requested one.
# Under buildx a linux/arm64 image then costs a compile instead of a full amd64
# toolchain running under QEMU, which is minutes rather than tens of minutes.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build

WORKDIR /src

# Cacheable dependency layer: only invalidated when go.mod/go.sum change.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Supplied by buildx. Defaulted so a plain `docker build` still works.
ARG TARGETOS=linux
ARG TARGETARCH
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -tags=jwx_es256k \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /alexandria ./cmd/alexandria

FROM gcr.io/distroless/static-debian12:nonroot

# The node reads its deployment file from here when no --config flag and no
# $ALEXANDRIA_CONFIG are given. Nothing is baked in: a deployment mounts its
# own — a bind mount under compose, a ConfigMap under Kubernetes.
VOLUME ["/etc/alexandria"]

COPY --from=build /alexandria /alexandria
USER nonroot:nonroot
ENTRYPOINT ["/alexandria"]
