.PHONY: build test smoke risk-smoke
build:
	go build -trimpath -o bin/audit-signal ./cmd/audit-signal
test:
	go test -race ./...
	go vet ./...
smoke: build
	./bin/audit-signal setup --solc-version 0.8.28
	./bin/audit-signal audit --target examples/VulnerableVault.sol --scope example/vault --ai none --solc-version 0.8.28
risk-smoke: smoke
	./bin/audit-signal risk --report reports/report.json --project examples/risk --source-root . --plan examples/risk/plan.json --solc .slither-venv/.solc-select/artifacts/solc-0.8.28/solc-0.8.28
