package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gaetandev/waf/internal/config"
)

const (
	defaultConfigPath     = "configs/config.example.yaml"
	defaultHealthCheckURL = "http://127.0.0.1:8080/waf/health"

	storageBackendRedis = "redis"
)

func main() {
	if err := run(); err != nil {
		slog.Error("waf stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	startedAt := time.Now()
	flags := parseFlags()
	if flags.healthCheck {
		return runHealthCheck(flags.healthCheckURL)
	}
	cfg, err := loadConfig(flags)
	if err != nil {
		return err
	}
	timeouts, err := parseServerTimeouts(*cfg)
	if err != nil {
		return err
	}

	a := &app{cfg: cfg, startedAt: startedAt}
	defer a.stop.run()
	if err := a.build(); err != nil {
		return err
	}
	return a.serve(timeouts)
}

// warnUntrustedInfrastructureHeaders signale les contrôles privés d'entrée par
// la suppression des CF-* quand cloudflare.trusted est faux (ADR-019 option B).
// Un avertissement et non une erreur : ces réglages restaient valides avant la
// décision, et un déploiement peut les laisser en place le temps de basculer.
func warnUntrustedInfrastructureHeaders(cfg config.Config) {
	if cfg.Cloudflare.Trusted {
		return
	}
	if cfg.Geo.Enabled {
		slog.Warn("geo rules have no input: CF-IPCountry is stripped while cloudflare.trusted is false", "adr", "ADR-019")
	}
	if cfg.TLSFingerprint.Enabled && strings.HasPrefix(strings.ToUpper(cfg.TLSFingerprint.JA3Header), "CF-") {
		slog.Warn("tls_fingerprint.ja3_header is stripped while cloudflare.trusted is false", "header", cfg.TLSFingerprint.JA3Header, "adr", "ADR-019")
	}
}

// poolShadowedDomains retourne les hôtes dont domains[].upstream diffère de
// upstream.address alors que upstream_pool est actif. Le pool, global, sert
// alors tous les hôtes (FR-26 ; pool par domaine différé) : ces upstreams ne
// reçoivent aucune requête. Un avertissement et non une erreur — la clé est
// obligatoire dans domains[], et la configuration reste celle que FR-26 décrit.
func poolShadowedDomains(cfg config.Config) []string {
	if !cfg.UpstreamPool.Enabled {
		return nil
	}
	var hosts []string
	for _, domain := range cfg.Domains {
		if domain.Upstream != cfg.Upstream.Address {
			hosts = append(hosts, domain.Host)
		}
	}
	return hosts
}

// geoChallengeInert signale geo.challenge_countries sans moteur de risque :
// la contribution geo n'est lue que par le moteur (FR-16), les pays listés ne
// sont alors jamais challengés. Un avertissement et non une erreur — la
// configuration reste valide, et le moteur peut être activé plus tard.
func geoChallengeInert(cfg config.Config) bool {
	return cfg.Geo.Enabled && len(cfg.Geo.ChallengeCountries) > 0 && !cfg.RiskEngine.Enabled
}

// domainHosts retourne les hôtes déclarés dans domains[].
func domainHosts(domains []config.DomainConfig) []string {
	hosts := make([]string, 0, len(domains))
	for _, domain := range domains {
		hosts = append(hosts, domain.Host)
	}
	return hosts
}

func parseDuration(field string, value string) (time.Duration, error) {
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be a valid Go duration: %w", field, err)
	}

	return duration, nil
}

// runHealthCheck probes the health endpoint and returns an error on any
// non-200 response. It powers the container HEALTHCHECK without requiring a
// shell or curl in the (distroless/scratch) runtime image.
func runHealthCheck(url string) error {
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("healthcheck request: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck status %d", response.StatusCode)
	}
	return nil
}
