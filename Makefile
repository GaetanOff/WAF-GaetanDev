BINARY := waf
MAIN := ./cmd/waf

# Gates SDD (AGENTS.md, specs/validation.md) : une cible par gate, mêmes outils
# que la CI (.github/workflows).
SPECS_API := specs/api/admin.openapi.yaml specs/api/public.openapi.yaml
CONFORMANCE_TESTS := Schema|Contract|OpenAPI|Conformance
LOAD_SCRIPT := tests/load/basic.js

.PHONY: build test lint run docker-build gates spec-lint typecheck conformance behavior security perf

build:
	go build -o $(BINARY) $(MAIN)

test:
	go test ./...

lint:
	golangci-lint run ./...

run:
	go run $(MAIN)

docker-build:
	docker build -t gaetandev/waf:local .

# G1 à G5 ; G6 (perf) exige un WAF en cours d'exécution et k6, G7 est humaine.
gates: spec-lint typecheck conformance behavior security

# G1 — contrats OpenAPI.
spec-lint:
	npx --yes @stoplight/spectral-cli@6 lint $(SPECS_API) --ruleset .spectral.yaml

# G2 — le compilateur Go tient lieu de vérificateur de types.
typecheck:
	go vet ./...
	go build ./...

# G3 — tests de conformance aux contrats (routes OpenAPI, schémas JSON).
conformance:
	go test ./... -run '$(CONFORMANCE_TESTS)'

# G4 — les scénarios Gherkin sont exécutés comme tests Go (aucun runner Gherkin).
behavior:
	go test ./... -race

# G5 — vulnérabilités connues des dépendances et de la toolchain.
security:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# G6 — charge contre un WAF lancé localement (WAF_URL, défaut http://127.0.0.1:8080).
perf:
	k6 run $(LOAD_SCRIPT)
