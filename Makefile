.PHONY: build test check fuzz clean

build:
	go build -trimpath -o bin/fafnir ./cmd/fafnir

test:
	go test -race ./...

check:
	go vet ./...
	go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

fuzz:
	go test ./internal/crypt -run '^$$' -fuzz '^FuzzParseEnv$$' -fuzztime 10s -parallel 2
	go test ./internal/crypt -run '^$$' -fuzz '^FuzzInspect$$' -fuzztime 10s -parallel 2

clean:
	rm -rf bin dist coverage.out
