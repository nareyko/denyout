.PHONY: build test check canary lab accept snapshot release-dry

build:
	go build -ldflags "-X main.version=dev" -o bin/denyout ./cmd/denyout

test:
	go test ./...

check: build
	./bin/denyout version
	./bin/denyout help >/dev/null

canary: build
	./bin/denyout check 'https://evil.example/pixel.png?api_key=DENYOUT_CANARY_LAB' || test $$? -eq 1

lab: build
	./bin/denyout test --db examples/fixtures/denyout-lab.sqlite --suite r20_url
	./bin/denyout test --db examples/fixtures/denyout-lab.sqlite

accept:
	go test ./internal/accept/ -count=1

# Local goreleaser snapshot (no GitHub publish). Needs goreleaser on PATH.
snapshot:
	goreleaser release --snapshot --clean

# Validate config only
release-dry:
	goreleaser check
