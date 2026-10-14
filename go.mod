module github.com/gaetandev/waf

// Plancher de version à go1.27.2 : la directive `go` fait elle-même office de
// toolchain minimum. go1.27.0 embarquait le correctif GO-2026-5856 (fuite ECH
// dans crypto/tls, atteignable : le WAF termine le TLS) ; go1.27.2 corrige les
// vulnérabilités stdlib signalées par Trivy sur go1.27.1 (CVE-2026-78667,
// CVE-2026-78669, CVE-2026-97031 et suivantes).
go 1.27.2

require (
	github.com/prometheus/client_golang v1.25.0
	github.com/redis/go-redis/v9 v9.23.0
	golang.org/x/crypto v0.58.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.3 // indirect
	github.com/prometheus/common v0.72.0 // indirect
	github.com/prometheus/procfs v0.22.0 // indirect
	go.uber.org/atomic v1.12.0 // indirect
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)
