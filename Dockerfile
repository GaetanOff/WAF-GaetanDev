# syntax=docker/dockerfile:1

# --- Build stage -----------------------------------------------------------
FROM golang:1.27-alpine AS builder

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
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

COPY --from=builder /out/waf /app/waf
COPY --from=builder /src/web/challenge.html /app/web/challenge.html
COPY --from=builder /src/configs/config.example.yaml /app/configs/config.example.yaml

EXPOSE 8080

# No shell/curl in distroless — the binary probes itself.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/app/waf", "-healthcheck"]

USER nonroot:nonroot
ENTRYPOINT ["/app/waf"]
CMD ["-config", "/app/configs/config.example.yaml"]
