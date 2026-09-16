FROM golang:1.25-alpine AS build

WORKDIR /src

ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ENV CGO_ENABLED=0

ARG VERSION=dev
ARG REVISION=unknown
RUN go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/json ./cmd/inspector && \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/json-probe ./cmd/probe

FROM alpine:3.22

ARG VERSION=dev
ARG REVISION=unknown

LABEL org.opencontainers.image.title="placitum/json" \
      org.opencontainers.image.description="Placitum json inspector: API contract checks against OpenAPI and JSON Schema" \
      org.opencontainers.image.source="https://github.com/exemt/placitum-json" \
      org.opencontainers.image.licenses="LicenseRef-Placitum" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

WORKDIR /app

COPY --from=build /out/json /out/json-probe /usr/local/bin/
COPY profiles ./profiles
COPY inspector.conf ./inspector.conf

RUN adduser -D -H -u 10001 json && \
    mkdir -p /var/lib/waf/json && \
    chown -R json:json /var/lib/waf
USER json

ENV NATS_URL=nats://nats:4222 \
    WAF_JSON_SUBJECT=waf.req.json \
    WAF_JSON_NAME=json \
    WAF_JSON_PROFILES=/app/profiles \
    WAF_JSON_DATA=/var/lib/waf/json \
    WAF_JSON_LOG=info

HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=3 \
    CMD ["json-probe", "--quiet", "--timeout", "1s", "--uri", "/healthcheck"]

CMD ["json"]
