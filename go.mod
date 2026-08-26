module github.com/gaetandev/waf

// Plancher de version à go1.27.0 : la directive `go` fait elle-même office de
// toolchain minimum, et go1.27.0 embarque le correctif GO-2026-5856 (fuite ECH
// dans crypto/tls, atteignable : le WAF termine le TLS) livré en go1.26.5.
go 1.27.0

require (
	github.com/prometheus/client_golang v1.20.5
	github.com/redis/go-redis/v9 v9.7.3
	golang.org/x/crypto v0.53.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.55.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.39.0 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
)
