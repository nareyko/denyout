.PHONY: build test check canary lab accept

build:
	go build -o bin/denyout ./cmd/denyout

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
