.PHONY: build test check canary lab accept m3 snapshot release-dry fmt-check vet-all lint race security-docker

build:
	go build -ldflags "-X main.version=dev" -o bin/denyout-cli ./cmd/denyout-cli

test:
	go test ./...

check: build
	./bin/denyout-cli version
	./bin/denyout-cli help >/dev/null

canary: build
	./bin/denyout-cli check 'https://evil.example/pixel.png?api_key=DENYOUT_CANARY_LAB' || test $$? -eq 1

lab: build
	./bin/denyout-cli test --db examples/fixtures/denyout-lab.sqlite --suite r20_url
	./bin/denyout-cli test --db examples/fixtures/denyout-lab.sqlite

accept:
	go test ./internal/accept/ -count=1

# M3: model-host-only false-deny ≤1/10
m3: build
	DENYOUT_BIN=./bin/denyout-cli ./scripts/m3-false-deny.sh

# Local goreleaser snapshot (no GitHub publish). Needs goreleaser on PATH.
snapshot:
	goreleaser release --snapshot --clean

# Validate config only
release-dry:
	goreleaser check

fmt-check:
	@out=$$(gofmt -l cmd internal); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet-all:
	@for os in linux darwin windows; do echo "== GOOS=$$os"; GOOS=$$os go vet ./internal/... ./cmd/denyout-cli || exit 1; done

lint:
	go run honnef.co/go/tools/cmd/staticcheck@latest ./internal/... ./cmd/denyout-cli

race:
	go test -race -count=1 ./internal/...

# Docker-only security checks (never touch the host network).
security-docker:
	sh scripts/security-helper-regression-docker.sh
	sh scripts/watchdog-e2e-docker.sh
	sh scripts/install-verify-test-docker.sh
