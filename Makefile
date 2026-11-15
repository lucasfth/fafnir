.PHONY: build test check cli-workflow fuzz security clean

VERSION ?= $(shell cat VERSION)
LDFLAGS = -X github.com/lucasfth/fafnir/internal/cli.Version=$(VERSION)

build:
	go build -trimpath -ldflags '$(LDFLAGS)' -o bin/fafnir ./cmd/fafnir

test:
	go test -race ./...

check:
	go vet ./...
	go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

cli-workflow: build
	test/built-cli-workflow.sh bin/fafnir

fuzz:
	go test ./internal/crypt -run '^$$' -fuzz '^FuzzParseEnv$$' -fuzztime 30s -parallel 2
	go test ./internal/crypt -run '^$$' -fuzz '^FuzzInspect$$' -fuzztime 30s -parallel 2

security: check cli-workflow fuzz

clean:
	rm -rf bin dist coverage.out
