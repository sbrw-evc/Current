# Umbrella Flow: one image for every role of the pipeline.
#   FLOW_ROLE=all (default) | collector | enricher | api | detector
#   `flow demo -target host:2055` runs the demo exporter.
# Build: make image (from app/), or docker compose build in deploy/flow.
FROM node:22-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.26-alpine AS backend
ARG VERSION=dev
ARG COMMIT=
ARG BUILT_AT=
WORKDIR /src
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.builtAt=${BUILT_AT}" -o /flow ./cmd/flow \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=backend /flow /flow
COPY --from=web /web/dist /web
COPY --from=backend --chown=65532:65532 /out/data /data
ENV FLOW_WEB_DIR=/web FLOW_ADDR=:8080 FLOW_DATA_DIR=/data FLOW_ROLE=all FLOW_NETFLOW_ADDR=:2055 FLOW_SFLOW_ADDR=:6343 FLOW_BMP_ADDR=:10179
VOLUME /data
# HTTP (web console, API, /metrics), NetFlow v5/v9 / IPFIX, sFlow, BMP
EXPOSE 8080/tcp 2055/udp 6343/udp 10179/tcp
USER nonroot
HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=3 CMD ["/flow", "-healthcheck"]
ENTRYPOINT ["/flow"]
