module github.com/gaetandev/waf

go 1.26.0

// GO-2026-5856 (fuite ECH dans crypto/tls, atteignable : le WAF termine le
// TLS) est corrigé dans la stdlib de go1.26.5 — forcer ce toolchain minimum.
toolchain go1.26.5

require (
	github.com/google/uuid v1.6.0
	github.com/prometheus/client_golang v1.20.5
	github.com/redis/go-redis/v9 v9.7.3
	golang.org/x/crypto v0.52.0
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
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
)
