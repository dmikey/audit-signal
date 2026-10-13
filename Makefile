.PHONY: build test smoke
build:
	go build -trimpath -o bin/slither-agent ./cmd/slither-agent
test:
	go test -race ./...
	go vet ./...
smoke: build
	./bin/slither-agent setup --solc-version 0.8.28
	./bin/slither-agent audit --target examples/VulnerableVault.sol --scope example/vault --ai none --solc-version 0.8.28
