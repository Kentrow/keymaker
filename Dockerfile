# syntax=docker/dockerfile:1

# Base images are pinned by tag and digest: the tag says what the image is, the digest makes a
# rebuild of an old commit produce the same image and keeps a scanner result attributable.
FROM --platform=$BUILDPLATFORM golang:1.27.1-bookworm@sha256:648f440f42a0958804efb24df176f806f9d353b41f1c0627f666428e40310f6b AS build

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

# No HEALTHCHECK instruction: the image carries no shell and no HTTP client to run one with.
# GET /healthz is served for orchestrators and probes that bring their own.
ENTRYPOINT ["/keymaker"]
