# syntax=docker/dockerfile:1

# Base images are pinned by tag and digest: the tag says what the image is, the digest makes a
# rebuild of an old commit produce the same image and keeps a scanner result attributable.
FROM --platform=$BUILDPLATFORM golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61 AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/

# Cross-compilation is done by the Go toolchain rather than by emulating the target platform,
# which is why the build stage runs on BUILDPLATFORM.
ARG TARGETOS
ARG TARGETARCH

# Build information shown by --version, in the startup log and in the interface footer. A
# release passes them; a local build keeps these defaults.
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

RUN CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build -trimpath \
      -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
      -o /out/keymaker ./cmd/keymaker

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

LABEL org.opencontainers.image.title="Keymaker" \
      org.opencontainers.image.description="Local web interface to inventory, audit, revoke and create OVHcloud API keys" \
      org.opencontainers.image.source="https://github.com/kentrow/keymaker" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=build /out/keymaker /keymaker

# The binary defaults to loopback, which no published port can reach inside a network
# namespace. Here the boundary is the host-side mapping, which is why the documented run
# command publishes on 127.0.0.1.
ENV KEYMAKER_ADDR=0.0.0.0:8080

EXPOSE 8080
USER nonroot:nonroot

# The image carries no shell and no HTTP client, so the binary checks itself: the healthcheck
# command asks GET /healthz on the loopback and exits 0 or 1. Orchestrators that bring their
# own probe can still call /healthz directly.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/keymaker", "healthcheck"]

ENTRYPOINT ["/keymaker"]
