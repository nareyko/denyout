.PHONY: build test check canary lab accept m3 snapshot release-dry

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
