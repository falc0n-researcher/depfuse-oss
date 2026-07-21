# ──────────────────────────────────────────────────────────────
# Depfuse — multi-stage build → scratch runtime (<15 MB image)
# ──────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

RUN CGO_ENABLED=0 go build \
    -ldflags "-s -w \
      -X github.com/falc0n-researcher/depfuse-oss/internal/version.Version=${VERSION} \
      -X github.com/falc0n-researcher/depfuse-oss/internal/version.Commit=${COMMIT} \
      -X github.com/falc0n-researcher/depfuse-oss/internal/version.Date=${DATE}" \
    -o /depfuse ./cmd/depfuse

# ── Runtime ──────────────────────────────────────────────────
FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /depfuse /depfuse

ENTRYPOINT ["/depfuse"]
