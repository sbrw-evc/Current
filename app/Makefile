.PHONY: build build-web build-api test test-api test-web run dev-api dev-web image stack stack-demo demo openbao-dev fmt

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null)
BUILT_AT ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS = -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.builtAt=$(BUILT_AT)
IMAGE ?= current
# Where the demo exporter sends flows (the collector of `make run` / deploy/current).
DEMO_TARGET ?= 127.0.0.1:2055

build: build-web build-api

build-web:
	cd web && npm ci && npm run build

build-api:
	cd backend && go build -ldflags "$(LDFLAGS)" -o current ./cmd/current

# Tests with PostgreSQL / ClickHouse use localhost:5432 (postgres/postgres) and localhost:9000;
# FLOW_TEST_POSTGRES=off and FLOW_TEST_CLICKHOUSE=off skip them. OpenBao is faked in tests.
test: test-api test-web

test-api:
	cd backend && go vet ./... && go test ./...

test-web:
	cd web && npm run typecheck && npm test

fmt:
	cd backend && gofmt -l -w .

run: build
	cd backend && ./current -web ../web/dist

dev-api:
	cd backend && go run ./cmd/current -web ../web/dist

dev-web:
	cd web && npm run dev

image:
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg BUILT_AT=$(BUILT_AT) \
		-t $(IMAGE):$(VERSION) -t $(IMAGE):latest .

# The whole Docker stack from deploy/current (Current, PostgreSQL, ClickHouse, NATS, OpenBao).
stack:
	cd ../deploy/current && ([ -f .env ] || cp .env.example .env) && docker compose up -d --build

# The stack plus the demo exporter container (--profile demo).
stack-demo:
	cd ../deploy/current && ([ -f .env ] || cp .env.example .env) && docker compose --profile demo up -d --build

# Synthetic NetFlow v9 / IPFIX / sFlow traffic from this machine to DEMO_TARGET.
demo:
	cd backend && go run ./cmd/current demo -target $(DEMO_TARGET)

openbao-dev:
	docker run -d --rm --name current-openbao-dev -p 127.0.0.1:8200:8200 -e BAO_DEV_ROOT_TOKEN_ID=dev-root openbao/openbao:2.7.1 server -dev -dev-listen-address=0.0.0.0:8200
	sleep 2
	docker exec -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN=dev-root current-openbao-dev bao secrets enable -path=flow -version=2 kv
	@echo 'OpenBao dev is up. In the setup wizard enter: address http://127.0.0.1:8200, token dev-root, KV v2 mount flow.'
