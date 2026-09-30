BINARY := waf
MAIN := ./cmd/waf

# Gates SDD (AGENTS.md, specs/validation.md) : une cible par gate, mêmes outils
# que la CI (.github/workflows).
SPECS_API := specs/api/admin.openapi.yaml specs/api/public.openapi.yaml
CONFORMANCE_TESTS := Schema|Contract|OpenAPI|Conformance
LOAD_SCRIPT := tests/load/basic.js
# Version exacte : `@6` exécutait la dernière 6.x publiée, non relue.
SPECTRAL := @stoplight/spectral-cli@6.16.3
# Couverture minimale des tests (requirements.md, qualité : > 80 %).
COVERAGE_MIN := 80
COVERAGE_PROFILE := coverage.out

.PHONY: build test lint run docker-build gates spec-lint typecheck conformance behavior coverage-check security perf

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
# G2 comprend golangci-lint (lint), comme en CI.
gates: spec-lint typecheck lint conformance behavior security

# G1 — contrats OpenAPI.
spec-lint:
	npx --yes $(SPECTRAL) lint $(SPECS_API) --ruleset .spectral.yaml

# G2 — le compilateur Go tient lieu de vérificateur de types.
typecheck:
	go vet ./...
	go build ./...

# G3 — tests de conformance aux contrats (routes OpenAPI, schémas JSON).
conformance:
	go test ./... -run '$(CONFORMANCE_TESTS)'

# G4 — les scénarios Gherkin sont exécutés comme tests Go (aucun runner Gherkin),
# sous le détecteur de courses ; la couverture totale doit atteindre COVERAGE_MIN.
behavior:
	go test ./... -race -coverprofile=$(COVERAGE_PROFILE) -covermode=atomic
	$(MAKE) coverage-check

coverage-check:
	@go tool cover -func=$(COVERAGE_PROFILE) | awk -v min=$(COVERAGE_MIN) '/^total:/ { \
		sub("%", "", $$3); \
		if ($$3 + 0 < min) { printf "coverage %s%% is below %s%%\n", $$3, min; exit 1 } \
		printf "coverage %s%% (minimum %s%%)\n", $$3, min }'

# G5 — vulnérabilités connues des dépendances et de la toolchain.
# `go run pkg@version` suit le go.mod de govulncheck (go 1.26) : avec un Go
# local plus ancien et GOTOOLCHAIN=auto, l'outil était compilé en 1.26 et
# refusait d'analyser ce module (go 1.27). La toolchain du module est imposée.
security:
	GOTOOLCHAIN=$$(go env GOVERSION) go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# G6 — charge contre un WAF lancé localement (WAF_URL, défaut http://127.0.0.1:8080).
perf:
	k6 run $(LOAD_SCRIPT)
