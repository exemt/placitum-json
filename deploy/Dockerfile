# Контекст сборки -- корень инспектора (inspectors/json), не корень
# репозитория: модуль Go самостоятелен и ничего оттуда не берёт.
#
#     docker build -f deploy/Dockerfile -t placitum/json .
#     docker buildx build -f deploy/Dockerfile -t placitum/json \
#         "https://github.com/exemt/placitum-json.git#develop"

FROM golang:1.25-alpine AS build

WORKDIR /src

# Прокси модулей -- аргументом: в изолированном контуре подставляют своё зеркало.
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}

# Зависимости отдельным слоем: они меняются на порядок реже кода, а тянуть
# разборщик OpenAPI заново на каждую правку профиля -- минута на ровном месте.
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

# CGO не нужен: и разборщик OpenAPI, и валидатор JSON Schema -- чистый Go.
# Отсюда и статический бинарник, и возможность собрать образ без libc.
ENV CGO_ENABLED=0

# Профили из образа обязаны подниматься: опечатка в спеке иначе ловится только
# стартом контейнера, потому что контракт компилируется целиком при загрузке.
COPY profiles ./profiles

RUN go test ./...

RUN go build -trimpath -ldflags="-s -w" -o /out/json ./cmd/inspector && \
    go build -trimpath -ldflags="-s -w" -o /out/json-probe ./cmd/probe

FROM alpine:3.22

# Версия и ревизия приходят снаружи: .git в контекст сборки не попадает.
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

# Проба идёт тем же путём, что и реальная инспекция: вердикт в ответе означает,
# что живы соединение с шиной, подписка, профили, скомпилированные контракты и
# пул воркеров. TCP-пинг до NATS не сказал бы ни про одно из этого.
#
# Профиль _probe отвечает deny на путь вне своих привязок -- обменник для проверки
# живости не нужен.
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=3 \
    CMD ["json-probe", "--quiet", "--timeout", "1s", "--uri", "/healthcheck"]

CMD ["json"]
