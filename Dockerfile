# syntax=docker/dockerfile:1

# --- Build stage -----------------------------------------------------------
# Base images are pinned by digest (the tag documents the version, Dependabot
# bumps both): a moved tag must not change what the release is built from.
FROM golang:1.27-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS builder

WORKDIR /src

# Dependencies first (layer cached until go.mod/go.sum change).
COPY go.mod go.sum ./
RUN go mod download

# Source.
COPY . .

# Static binary — no CGO, stripped, trimmed paths for reproducibility.
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/waf ./cmd/waf

# --- Runtime stage ---------------------------------------------------------
# distroless/static: ~2 MB, ships CA certificates + tzdata, runs as nonroot.
# Debian 13: debian12 still ships tzdata 2026b (DLA-4792-1, fixed in 2026c).
FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3

WORKDIR /app

COPY --from=builder /out/waf /app/waf
COPY --from=builder /src/configs/config.example.yaml /app/configs/config.example.yaml

EXPOSE 8080

# No shell/curl in distroless — the binary probes itself.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/app/waf", "-healthcheck"]

USER nonroot:nonroot
ENTRYPOINT ["/app/waf"]
CMD ["-config", "/app/configs/config.example.yaml"]
