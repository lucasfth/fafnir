.PHONY: build test check cli-workflow fuzz security clean

build:
	go build -trimpath -o bin/fafnir ./cmd/fafnir

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
