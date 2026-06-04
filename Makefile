BINARY := waf
MAIN := ./cmd/waf

.PHONY: build test lint run docker-build

build:
	go build -o $(BINARY) $(MAIN)

test:
	go test ./...

lint:
	go vet ./...

run:
	go run $(MAIN)

docker-build:
	docker build -t gaetandev/waf:local .
