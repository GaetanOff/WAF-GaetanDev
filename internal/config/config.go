package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	envAdminToken         = "WAF_ADMIN_TOKEN"
	envChallengeSecretKey = "WAF_CHALLENGE_SECRET_KEY"
	envRedisPassword      = "WAF_REDIS_PASSWORD"
	envOriginSecret       = "WAF_ORIGIN_SECRET"
)

// Config mirrors specs/schemas/config.schema.json.
type Config struct {
	Version             string           `yaml:"version"`
	Server              ServerConfig     `yaml:"server"`
	Upstream            UpstreamConfig   `yaml:"upstream"`
	Cloudflare          Cloudflare       `yaml:"cloudflare"`
	RateLimit           RateLimit        `yaml:"rate_limit"`
	AntiDDoS            AntiDDoS         `yaml:"antiddos"`
	Trust               Trust            `yaml:"trust"`
	RiskEngine          RiskEngine       `yaml:"risk_engine"`
	Integrity           Integrity        `yaml:"integrity"`
	Behavioral          Behavioral       `yaml:"behavioral"`
	ThreatIntel         ThreatIntel      `yaml:"threat_intel"`
	Adaptive            Adaptive         `yaml:"adaptive"`
	Geo                 Geo              `yaml:"geo"`
	TLSFingerprint      TLSFingerprint   `yaml:"tls_fingerprint"`
	Deception           Deception        `yaml:"deception"`
	Rules               Rules            `yaml:"rules"`
	OriginProtection    OriginProtection `yaml:"origin_protection"`
	Cluster             Cluster          `yaml:"cluster"`
	SecurityHeaders     SecurityHeaders  `yaml:"security_headers"`
	Slowloris           Slowloris        `yaml:"slowloris"`
	StaticAssets        StaticAssets     `yaml:"static_assets"`
	UpstreamPool        UpstreamPool     `yaml:"upstream_pool"`
	Audit               Audit            `yaml:"audit"`
	GDPR                GDPR             `yaml:"gdpr"`
	Alerting            Alerting         `yaml:"alerting"`
	SelfProtection      SelfProtection   `yaml:"self_protection"`
	ACME                ACME             `yaml:"acme"`
	Maintenance         Maintenance      `yaml:"maintenance"`
	Challenge           Challenge        `yaml:"challenge"`
	Whitelist           []string         `yaml:"whitelist"`
	Blacklist           []string         `yaml:"blacklist"`
	WhitelistUserAgents []string         `yaml:"whitelist_user_agents"`
	HoneypotPaths       []string         `yaml:"honeypot_paths"`
	Domains             []DomainConfig   `yaml:"domains"`
	Logging             Logging          `yaml:"logging"`
	Storage             Storage          `yaml:"storage"`
	Admin               Admin            `yaml:"admin"`
}

type ServerConfig struct {
	Listen                  string `yaml:"listen"`
	AdminListen             string `yaml:"admin_listen"`
	ReadTimeout             string `yaml:"read_timeout"`
	WriteTimeout            string `yaml:"write_timeout"`
	IdleTimeout             string `yaml:"idle_timeout"`
	GracefulShutdownTimeout string `yaml:"graceful_shutdown_timeout"`
	// MaxHeaderValueCount borne le nombre de valeurs d'en-tête acceptées par
	// requête (FR-23, http.Server.MaxHeaderValueCount — Go 1.27+). 0 laisse le
	// défaut Go (http.DefaultMaxHeaderValueCount, 500).
	MaxHeaderValueCount int       `yaml:"max_header_value_count"`
	TLS                 ServerTLS `yaml:"tls"`
}

// ServerTLS configure la terminaison TLS sur le WAF (FR-33, ADR-017). Les
// certificats par domaine sont définis dans Domains[].TLS et sélectionnés par
// SNI ; CertFile/KeyFile fournissent un certificat par défaut optionnel.
type ServerTLS struct {
	Enabled      bool     `yaml:"enabled"`
	Listen       string   `yaml:"listen"`
	MinVersion   string   `yaml:"min_version"`
	CipherSuites []string `yaml:"cipher_suites"`
	RedirectHTTP bool     `yaml:"redirect_http"`
	CertFile     string   `yaml:"cert_file"`
	KeyFile      string   `yaml:"key_file"`
}

// DomainTLS porte le certificat statique d'un domaine, sélectionné par SNI.
type DomainTLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type UpstreamConfig struct {
	Address      string `yaml:"address"`
	Timeout      string `yaml:"timeout"`
	TLSVerify    bool   `yaml:"tls_verify"`
	MaxIdleConns int    `yaml:"max_idle_conns"`
	// PreserveHost conserve l'en-tête Host entrant vers l'upstream au lieu de le
	// réécrire vers l'hôte de l'upstream. Indispensable quand l'upstream route
	// par nom d'hôte (ex: un nginx/OpenResty en aval qui sélectionne le vhost
	// par server_name). Défaut false = comportement historique (Host = upstream).
	PreserveHost bool `yaml:"preserve_host"`
}

type Cloudflare struct {
	Trusted          bool   `yaml:"trusted"`
	AutoUpdateRanges bool   `yaml:"auto_update_ranges"`
	UpdateInterval   string `yaml:"update_interval"`
}

type RateLimit struct {
	Enabled           bool    `yaml:"enabled"`
	RequestsPerSecond float64 `yaml:"requests_per_second"`
	Burst             int     `yaml:"burst"`
	RequestsPerMinute int     `yaml:"requests_per_minute"`
	RequestsPerHour   int     `yaml:"requests_per_hour"`
}

type AntiDDoS struct {
	Enabled                 bool           `yaml:"enabled"`
	GlobalRequestsPerSecond int            `yaml:"global_requests_per_second"`
	GlobalWindow            string         `yaml:"global_window"`
	PressureLevels          PressureLevels `yaml:"pressure_levels"`
	RetryAfterSeconds       int            `yaml:"retry_after_seconds"`
	UnderAttack             UnderAttack    `yaml:"under_attack"`
}

// UnderAttack configure le mode « sous attaque » (FR-39, ADR-018) : sous pression
// avérée, le WAF force le challenge JS des requêtes sans clearance pour délester un
// flood L7 distribué tout en laissant les humains récupérer via PoW.
type UnderAttack struct {
	Enabled           bool   `yaml:"enabled"`
	Scope             string `yaml:"scope"`            // per_domain | global
	TriggerPressure   string `yaml:"trigger_pressure"` // elevated | high | critical
	ExitPressure      string `yaml:"exit_pressure"`    // normal | elevated | high | critical
	Cooldown          string `yaml:"cooldown"`         // durée sous exit_pressure avant sortie
	Shadow            bool   `yaml:"shadow"`           // calcule/journalise sans forcer (FR-38)
	MaxTrackedDomains int    `yaml:"max_tracked_domains"`
}

type PressureLevels struct {
	ElevatedMultiplier float64 `yaml:"elevated_multiplier"`
	HighMultiplier     float64 `yaml:"high_multiplier"`
	CriticalMultiplier float64 `yaml:"critical_multiplier"`
}

type Trust struct {
	InitialScore       int    `yaml:"initial_score"`
	ChallengeThreshold int    `yaml:"challenge_threshold"`
	BlockThreshold     int    `yaml:"block_threshold"`
	ScoreTTL           string `yaml:"score_ttl"`
	MaxVisitors        int    `yaml:"max_visitors"`
}

type RiskEngine struct {
	Enabled                      bool               `yaml:"enabled"`
	Profile                      string             `yaml:"profile"`
	ShadowMode                   bool               `yaml:"shadow_mode"`
	BlockMinConfidence           float64            `yaml:"block_min_confidence"`
	MinCorroboratingFamilies     int                `yaml:"min_corroborating_families"`
	Tiers                        RiskTiers          `yaml:"tiers"`
	Weights                      map[string]float64 `yaml:"weights"`
	FamilyCorroborationThreshold int                `yaml:"family_corroboration_threshold"`
	HumanCredit                  HumanCredit        `yaml:"human_credit"`
	VerifiedBots                 VerifiedBots       `yaml:"verified_bots"`
}

type RiskTiers struct {
	Observe   int `yaml:"observe"`
	Throttle  int `yaml:"throttle"`
	Challenge int `yaml:"challenge"`
	Tarpit    int `yaml:"tarpit"`
	Block     int `yaml:"block"`
}

type HumanCredit struct {
	ChallengePassed   int    `yaml:"challenge_passed"`
	StableFingerprint int    `yaml:"stable_fingerprint"`
	StickyTrustTTL    string `yaml:"sticky_trust_ttl"`
}

type VerifiedBots struct {
	Enabled         bool     `yaml:"enabled"`
	SuccessCacheTTL string   `yaml:"success_cache_ttl"`
	FailureCacheTTL string   `yaml:"failure_cache_ttl"`
	Crawlers        []string `yaml:"crawlers"`
}

type Integrity struct {
	Enabled        bool  `yaml:"enabled"`
	MaxBodyBytes   int64 `yaml:"max_body_bytes"`
	MaxPathLength  int   `yaml:"max_path_length"`
	MaxQueryLength int   `yaml:"max_query_length"`
}

type Behavioral struct {
	Enabled    bool `yaml:"enabled"`
	MaxRecords int  `yaml:"max_records"`
}

type ThreatIntel struct {
	Enabled        bool      `yaml:"enabled"`
	CacheTTL       string    `yaml:"cache_ttl"`
	BlocklistCIDRs []string  `yaml:"blocklist_cidrs"`
	SuspectCIDRs   []string  `yaml:"suspect_cidrs"`
	AbuseIPDB      AbuseIPDB `yaml:"abuseipdb"`
}

type AbuseIPDB struct {
	Enabled bool   `yaml:"enabled"`
	URL     string `yaml:"url"`
	APIKey  string `yaml:"api_key"`
}

type Adaptive struct {
	Enabled       bool   `yaml:"enabled"`
	MaxDifficulty int    `yaml:"max_difficulty"`
	DecayTau      string `yaml:"decay_tau"`
}

type Geo struct {
	Enabled               bool     `yaml:"enabled"`
	AllowedCountries      []string `yaml:"allowed_countries"`
	BlockedCountries      []string `yaml:"blocked_countries"`
	ChallengeCountries    []string `yaml:"challenge_countries"`
	ChallengeContribution int      `yaml:"challenge_contribution"`
}

type TLSFingerprint struct {
	Enabled          bool     `yaml:"enabled"`
	JA3Header        string   `yaml:"ja3_header"`
	JA3Blacklist     []string `yaml:"ja3_blacklist"`
	SwapContribution int      `yaml:"swap_contribution"`
}

type Deception struct {
	Enabled          bool   `yaml:"enabled"`
	TarpitMaxConns   int    `yaml:"tarpit_max_connections"`
	TarpitChunks     int    `yaml:"tarpit_chunks"`
	TarpitChunkDelay string `yaml:"tarpit_chunk_delay"`
}

type Rules struct {
	Enabled bool   `yaml:"enabled"`
	File    string `yaml:"file"`
}

type OriginProtection struct {
	Enabled bool   `yaml:"enabled"`
	Secret  string `yaml:"secret"`
}

type Cluster struct {
	Enabled bool   `yaml:"enabled"`
	Channel string `yaml:"channel"`
}

type StaticAssets struct {
	Enabled    bool     `yaml:"enabled"`
	Extensions []string `yaml:"extensions"`
}

type UpstreamPool struct {
	Enabled     bool                `yaml:"enabled"`
	Strategy    string              `yaml:"strategy"`
	Upstreams   []PoolUpstream      `yaml:"upstreams"`
	HealthCheck UpstreamHealthCheck `yaml:"health_check"`
}

type PoolUpstream struct {
	Address string `yaml:"address"`
	Weight  int    `yaml:"weight"`
	Backup  bool   `yaml:"backup"`
}

type Audit struct {
	Enabled    bool   `yaml:"enabled"`
	MaxEntries int    `yaml:"max_entries"`
	File       string `yaml:"file"`
}

type GDPR struct {
	AnonymizeIP bool `yaml:"anonymize_ip"`
}

type Maintenance struct {
	Enabled    bool `yaml:"enabled"`
	ErrorPages bool `yaml:"error_pages"`
}

type ACME struct {
	Enabled             bool     `yaml:"enabled"`
	Domains             []string `yaml:"domains"`
	Email               string   `yaml:"email"`
	CacheDir            string   `yaml:"cache_dir"`
	TLSListen           string   `yaml:"tls_listen"`
	HTTPChallengeListen string   `yaml:"http_challenge_listen"`
}

type SelfProtection struct {
	Enabled            bool   `yaml:"enabled"`
	VerifyMaxPerMinute int    `yaml:"verify_max_per_minute"`
	AdminMaxFailures   int    `yaml:"admin_max_failures"`
	AdminLockout       string `yaml:"admin_lockout"`
}

type Alerting struct {
	Enabled    bool           `yaml:"enabled"`
	Cooldown   string         `yaml:"cooldown"`
	MaxRetries int            `yaml:"max_retries"`
	Webhooks   []AlertWebhook `yaml:"webhooks"`
}

type AlertWebhook struct {
	Type string `yaml:"type"`
	URL  string `yaml:"url"`
}

type UpstreamHealthCheck struct {
	Path               string `yaml:"path"`
	Interval           string `yaml:"interval"`
	Timeout            string `yaml:"timeout"`
	HealthyThreshold   int    `yaml:"healthy_threshold"`
	UnhealthyThreshold int    `yaml:"unhealthy_threshold"`
}

type Slowloris struct {
	Enabled       bool   `yaml:"enabled"`
	MaxConnsPerIP int    `yaml:"max_connections_per_ip"`
	HeaderTimeout string `yaml:"header_timeout"`
}

type SecurityHeaders struct {
	Enabled               bool     `yaml:"enabled"`
	HSTSMaxAge            int      `yaml:"hsts_max_age"`
	HSTSIncludeSubdomains bool     `yaml:"hsts_include_subdomains"`
	FrameOptions          string   `yaml:"frame_options"`
	ContentTypeNosniff    bool     `yaml:"content_type_nosniff"`
	ReferrerPolicy        string   `yaml:"referrer_policy"`
	PermissionsPolicy     string   `yaml:"permissions_policy"`
	CSP                   string   `yaml:"csp"`
	StripHeaders          []string `yaml:"strip_headers"`
}

type Challenge struct {
	Enabled       bool   `yaml:"enabled"`
	SecretKey     string `yaml:"secret_key"`
	TokenTTL      string `yaml:"token_ttl"`
	CookieTTL     string `yaml:"cookie_ttl"`
	CookieName    string `yaml:"cookie_name"`
	PowDifficulty int    `yaml:"pow_difficulty"`
	MinElapsedMS  int    `yaml:"min_elapsed_ms"`
	MaxElapsedMS  int    `yaml:"max_elapsed_ms"`
}

type DomainConfig struct {
	Host     string `yaml:"host"`
	Upstream string `yaml:"upstream"`
	// ChallengeEnabled surcharge Challenge.Enabled pour ce domaine (FR-06). Le
	// pointeur distingue « clé absente » (nil → hérite du global) de la valeur
	// explicite false : avec un bool nu, toute entrée domains[] déclarée pour son
	// seul upstream ou son certificat TLS aurait désactivé le challenge en silence.
	ChallengeEnabled  *bool              `yaml:"challenge_enabled"`
	RateLimitOverride *RateLimitOverride `yaml:"rate_limit_override"`
	TrustOverride     *TrustOverride     `yaml:"trust_override"`
	ProtectedPaths    []string           `yaml:"protected_paths"`
	PublicPaths       []string           `yaml:"public_paths"`
	TLS               *DomainTLS         `yaml:"tls"`
}

type RateLimitOverride struct {
	RequestsPerSecond float64 `yaml:"requests_per_second"`
	Burst             int     `yaml:"burst"`
}

type TrustOverride struct {
	ChallengeThreshold int `yaml:"challenge_threshold"`
	BlockThreshold     int `yaml:"block_threshold"`
}

type Logging struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	Output string `yaml:"output"`
}

type Storage struct {
	Backend string       `yaml:"backend"`
	Redis   *RedisConfig `yaml:"redis"`
}

type RedisConfig struct {
	Address  string `yaml:"address"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
	TLS      bool   `yaml:"tls"`
}

type Admin struct {
	Enabled bool   `yaml:"enabled"`
	Token   string `yaml:"token"`
}

type ValidationError struct {
	Fields []string
}

func (e ValidationError) Error() string {
	return "invalid config: " + strings.Join(e.Fields, "; ")
}

func Load(path string) (*Config, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}

	cfg := Default()
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}

	cfg.applyEnvOverrides()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func Default() Config {
	return Config{
		Server: ServerConfig{
			AdminListen:             ":9090",
			ReadTimeout:             "30s",
			WriteTimeout:            "30s",
			IdleTimeout:             "60s",
			GracefulShutdownTimeout: "15s",
			MaxHeaderValueCount:     100,
			TLS: ServerTLS{
				Enabled:      false, // opt-in : terminaison TLS par domaine (FR-33)
				Listen:       ":443",
				MinVersion:   "1.2",
				RedirectHTTP: true,
			},
		},
		Upstream: UpstreamConfig{
			Timeout:      "30s",
			TLSVerify:    true,
			MaxIdleConns: 100,
		},
		Cloudflare: Cloudflare{
			Trusted:        true,
			UpdateInterval: "24h",
		},
		RateLimit: RateLimit{
			Enabled:           true,
			RequestsPerSecond: 50,
			Burst:             100,
			RequestsPerMinute: 1000,
			RequestsPerHour:   10000,
		},
		AntiDDoS: AntiDDoS{
			Enabled:                 true,
			GlobalRequestsPerSecond: 50000,
			GlobalWindow:            "1s",
			PressureLevels: PressureLevels{
				ElevatedMultiplier: 1,
				HighMultiplier:     2,
				CriticalMultiplier: 4,
			},
			RetryAfterSeconds: 5,
			UnderAttack: UnderAttack{
				Enabled:           true,
				Scope:             "per_domain",
				TriggerPressure:   "high",
				ExitPressure:      "elevated",
				Cooldown:          "30s",
				Shadow:            false,
				MaxTrackedDomains: 1024,
			},
		},
		Trust: Trust{
			InitialScore:       50,
			ChallengeThreshold: 40,
			BlockThreshold:     10,
			ScoreTTL:           "1h",
			MaxVisitors:        100000,
		},
		RiskEngine: RiskEngine{
			Enabled: true,
			Profile: "balanced",
			// Shadow par défaut : le moteur calcule et journalise ses décisions
			// sans les appliquer, le temps de la calibration (NFR-15 : >= 24 h de
			// shadow avant enforcement). Passer à false après observation des
			// métriques de faux positifs.
			ShadowMode:               true,
			BlockMinConfidence:       0.6,
			MinCorroboratingFamilies: 2,
			Tiers: RiskTiers{
				Observe:   25,
				Throttle:  45,
				Challenge: 65,
				Tarpit:    80,
				Block:     90,
			},
			Weights: map[string]float64{
				"reputation":   1.0,
				"behavioral":   1.0,
				"tls":          0.8,
				"fingerprint":  1.0,
				"integrity":    1.2,
				"rate":         0.6,
				"geo":          0.5,
				"human_credit": 1.0,
			},
			FamilyCorroborationThreshold: 50,
			HumanCredit: HumanCredit{
				ChallengePassed:   -40,
				StableFingerprint: -15,
				StickyTrustTTL:    "30m",
			},
			VerifiedBots: VerifiedBots{
				Enabled:         true,
				SuccessCacheTTL: "12h",
				FailureCacheTTL: "10m",
				Crawlers:        []string{"googlebot", "bingbot", "duckduckbot", "applebot"},
			},
		},
		Integrity: Integrity{
			Enabled:        true,
			MaxBodyBytes:   10 << 20, // 10 MB
			MaxPathLength:  2048,
			MaxQueryLength: 4096,
		},
		Behavioral: Behavioral{
			Enabled:    true,
			MaxRecords: 50,
		},
		ThreatIntel: ThreatIntel{
			Enabled:  false, // opt-in : nécessite des feeds et/ou une clé API
			CacheTTL: "1h",
			AbuseIPDB: AbuseIPDB{
				Enabled: false,
				URL:     "https://api.abuseipdb.com/api/v2/check",
			},
		},
		Adaptive: Adaptive{
			Enabled:       true,
			MaxDifficulty: 24,
			DecayTau:      "5m",
		},
		Geo: Geo{
			Enabled:               false, // opt-in : nécessite des règles par pays
			ChallengeContribution: 60,
		},
		TLSFingerprint: TLSFingerprint{
			Enabled:          true,
			JA3Header:        "Cf-Bot-Management-Ja3Hash",
			SwapContribution: 50,
		},
		Deception: Deception{
			Enabled:          true,
			TarpitMaxConns:   500,
			TarpitChunks:     20,
			TarpitChunkDelay: "1s",
		},
		Audit: Audit{
			Enabled:    true,
			MaxEntries: 1000,
		},
		GDPR: GDPR{
			AnonymizeIP: true,
		},
		Alerting: Alerting{
			Enabled:    false, // opt-in : nécessite des webhooks
			Cooldown:   "5m",
			MaxRetries: 3,
		},
		SelfProtection: SelfProtection{
			Enabled:            true,
			VerifyMaxPerMinute: 60,
			AdminMaxFailures:   5,
			AdminLockout:       "5m",
		},
		ACME: ACME{
			Enabled:             false, // opt-in : TLS direct (hors Cloudflare)
			CacheDir:            "./certs",
			TLSListen:           ":443",
			HTTPChallengeListen: ":80",
		},
		Maintenance: Maintenance{
			Enabled:    false, // bascule operationnelle
			ErrorPages: true,
		},
		StaticAssets: StaticAssets{
			Enabled: true,
			Extensions: []string{
				".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
				".woff", ".woff2", ".ttf", ".eot", ".map", ".webp",
			},
		},
		Slowloris: Slowloris{
			Enabled:       true,
			MaxConnsPerIP: 50,
			HeaderTimeout: "10s",
		},
		SecurityHeaders: SecurityHeaders{
			Enabled:               true,
			HSTSMaxAge:            31536000,
			HSTSIncludeSubdomains: true,
			FrameOptions:          "DENY",
			ContentTypeNosniff:    true,
			ReferrerPolicy:        "strict-origin-when-cross-origin",
			StripHeaders:          []string{"Server", "X-Powered-By"},
		},
		Challenge: Challenge{
			Enabled:       true,
			TokenTTL:      "30s",
			CookieTTL:     "24h",
			CookieName:    "waf_session",
			PowDifficulty: 16,
			// Plancher de durée désactivé par défaut (0) : sur un client rapide la
			// PoW se résout en quelques dizaines de ms, et un plancher positif
			// rejetait ces résolutions légitimes en challenge_too_fast -> boucle.
			// La résistance anti-bot vient de la PoW + fingerprint + cookie, pas du
			// chrono. Un opérateur peut réactiver un plancher en le passant > 0.
			MinElapsedMS: 0,
			MaxElapsedMS: 60000,
		},
		WhitelistUserAgents: []string{
			"Googlebot",
			"Bingbot",
			"Slurp",
			"DuckDuckBot",
			"Baiduspider",
			"facebookexternalhit",
			"LinkedInBot",
			"Twitterbot",
		},
		HoneypotPaths: []string{
			"/.env",
			"/wp-admin",
			"/wp-login.php",
			"/.git/config",
			"/phpinfo.php",
			"/admin.php",
		},
		Logging: Logging{
			Level:  "info",
			Format: "json",
			Output: "stdout",
		},
		Storage: Storage{
			Backend: "memory",
		},
		Admin: Admin{
			Enabled: true,
		},
	}
}

func (c *Config) Validate() error {
	var fields []string

	requireString(&fields, "version", c.Version)
	requireString(&fields, "server.listen", c.Server.Listen)
	requireString(&fields, "upstream.address", c.Upstream.Address)
	validateURL(&fields, "upstream.address", c.Upstream.Address)
	validateDuration(&fields, "server.read_timeout", c.Server.ReadTimeout)
	validateDuration(&fields, "server.write_timeout", c.Server.WriteTimeout)
	validateDuration(&fields, "server.idle_timeout", c.Server.IdleTimeout)
	validateDuration(&fields, "server.graceful_shutdown_timeout", c.Server.GracefulShutdownTimeout)
	validateDuration(&fields, "upstream.timeout", c.Upstream.Timeout)
	validateDuration(&fields, "cloudflare.update_interval", c.Cloudflare.UpdateInterval)
	validateDuration(&fields, "antiddos.global_window", c.AntiDDoS.GlobalWindow)
	validateDuration(&fields, "trust.score_ttl", c.Trust.ScoreTTL)
	validateDuration(&fields, "risk_engine.human_credit.sticky_trust_ttl", c.RiskEngine.HumanCredit.StickyTrustTTL)
	validateDuration(&fields, "risk_engine.verified_bots.success_cache_ttl", c.RiskEngine.VerifiedBots.SuccessCacheTTL)
	validateDuration(&fields, "risk_engine.verified_bots.failure_cache_ttl", c.RiskEngine.VerifiedBots.FailureCacheTTL)
	validateDuration(&fields, "challenge.token_ttl", c.Challenge.TokenTTL)
	validateDuration(&fields, "challenge.cookie_ttl", c.Challenge.CookieTTL)

	// 0 = défaut Go (500). Une borne haute évite qu'une valeur absurde annule de
	// fait la protection FR-23 ; alignée sur config.schema.json.
	if c.Server.MaxHeaderValueCount < 0 || c.Server.MaxHeaderValueCount > 10000 {
		fields = append(fields, "server.max_header_value_count must be between 0 and 10000")
	}
	if c.Upstream.MaxIdleConns < 1 {
		fields = append(fields, "upstream.max_idle_conns must be >= 1")
	}
	if c.RateLimit.RequestsPerSecond < 1 {
		fields = append(fields, "rate_limit.requests_per_second must be >= 1")
	}
	if c.RateLimit.Burst < 1 {
		fields = append(fields, "rate_limit.burst must be >= 1")
	}
	if c.AntiDDoS.GlobalRequestsPerSecond < 1 {
		fields = append(fields, "antiddos.global_requests_per_second must be >= 1")
	}
	validatePressureLevels(&fields, c.AntiDDoS.PressureLevels)
	if c.AntiDDoS.RetryAfterSeconds < 1 {
		fields = append(fields, "antiddos.retry_after_seconds must be >= 1")
	}
	validateUnderAttack(&fields, c.AntiDDoS.UnderAttack)
	validateRange(&fields, "trust.initial_score", c.Trust.InitialScore, 0, 100)
	validateRange(&fields, "trust.challenge_threshold", c.Trust.ChallengeThreshold, 0, 100)
	validateRange(&fields, "trust.block_threshold", c.Trust.BlockThreshold, 0, 100)
	if c.Trust.BlockThreshold >= c.Trust.ChallengeThreshold {
		fields = append(fields, "trust.block_threshold must be lower than trust.challenge_threshold")
	}
	if c.Trust.MaxVisitors < 1 {
		fields = append(fields, "trust.max_visitors must be >= 1")
	}
	validateRiskEngine(&fields, c.RiskEngine)
	if c.Integrity.Enabled {
		if c.Integrity.MaxBodyBytes < 1 {
			fields = append(fields, "integrity.max_body_bytes must be >= 1")
		}
		if c.Integrity.MaxPathLength < 1 {
			fields = append(fields, "integrity.max_path_length must be >= 1")
		}
		if c.Integrity.MaxQueryLength < 1 {
			fields = append(fields, "integrity.max_query_length must be >= 1")
		}
	}
	if c.Behavioral.Enabled && c.Behavioral.MaxRecords < 1 {
		fields = append(fields, "behavioral.max_records must be >= 1")
	}
	if c.ThreatIntel.Enabled {
		validateDuration(&fields, "threat_intel.cache_ttl", c.ThreatIntel.CacheTTL)
		if c.ThreatIntel.AbuseIPDB.Enabled && c.ThreatIntel.AbuseIPDB.URL == "" {
			fields = append(fields, "threat_intel.abuseipdb.url is required when abuseipdb is enabled")
		}
	}
	if c.Adaptive.Enabled {
		validateDuration(&fields, "adaptive.decay_tau", c.Adaptive.DecayTau)
		validateRange(&fields, "adaptive.max_difficulty", c.Adaptive.MaxDifficulty, 8, 32)
		if c.Adaptive.MaxDifficulty < c.Challenge.PowDifficulty {
			fields = append(fields, "adaptive.max_difficulty must be >= challenge.pow_difficulty")
		}
	}
	if c.Geo.Enabled && c.Geo.ChallengeContribution != 0 {
		validateRange(&fields, "geo.challenge_contribution", c.Geo.ChallengeContribution, 0, 100)
	}
	if c.TLSFingerprint.Enabled && c.TLSFingerprint.SwapContribution != 0 {
		validateRange(&fields, "tls_fingerprint.swap_contribution", c.TLSFingerprint.SwapContribution, 0, 100)
	}
	if c.Deception.Enabled {
		validateDuration(&fields, "deception.tarpit_chunk_delay", c.Deception.TarpitChunkDelay)
		if c.Deception.TarpitMaxConns < 1 {
			fields = append(fields, "deception.tarpit_max_connections must be >= 1")
		}
	}
	if c.Rules.Enabled && c.Rules.File == "" {
		fields = append(fields, "rules.file is required when rules is enabled")
	}
	if c.OriginProtection.Enabled && len(c.OriginProtection.Secret) < 16 {
		fields = append(fields, "origin_protection.secret is required (>= 16 chars); set WAF_ORIGIN_SECRET")
	}
	if c.Cluster.Enabled && (c.Storage.Redis == nil || c.Storage.Redis.Address == "") {
		fields = append(fields, "cluster.enabled requires storage.redis.address")
	}
	if c.Alerting.Enabled {
		validateDuration(&fields, "alerting.cooldown", c.Alerting.Cooldown)
		if len(c.Alerting.Webhooks) == 0 {
			fields = append(fields, "alerting.webhooks must not be empty when enabled")
		}
	}
	if c.ACME.Enabled && len(c.ACME.Domains) == 0 {
		fields = append(fields, "acme.domains must not be empty when enabled")
	}
	validateServerTLS(&fields, c)
	if c.SelfProtection.Enabled {
		validateDuration(&fields, "self_protection.admin_lockout", c.SelfProtection.AdminLockout)
		if c.SelfProtection.VerifyMaxPerMinute < 1 {
			fields = append(fields, "self_protection.verify_max_per_minute must be >= 1")
		}
		if c.SelfProtection.AdminMaxFailures < 1 {
			fields = append(fields, "self_protection.admin_max_failures must be >= 1")
		}
	}
	if c.Slowloris.Enabled {
		validateDuration(&fields, "slowloris.header_timeout", c.Slowloris.HeaderTimeout)
		if c.Slowloris.MaxConnsPerIP < 1 {
			fields = append(fields, "slowloris.max_connections_per_ip must be >= 1")
		}
	}
	if c.UpstreamPool.Enabled {
		if len(c.UpstreamPool.Upstreams) == 0 {
			fields = append(fields, "upstream_pool.upstreams must not be empty when enabled")
		}
		if c.UpstreamPool.Strategy != "" {
			validateEnum(&fields, "upstream_pool.strategy", c.UpstreamPool.Strategy, "round_robin", "least_conn", "ip_hash", "weighted")
		}
		validateDuration(&fields, "upstream_pool.health_check.interval", c.UpstreamPool.HealthCheck.Interval)
		validateDuration(&fields, "upstream_pool.health_check.timeout", c.UpstreamPool.HealthCheck.Timeout)
	}
	if c.Challenge.Enabled && len(c.Challenge.SecretKey) < 32 {
		fields = append(fields, "challenge.secret_key is required and must be at least 32 characters; set WAF_CHALLENGE_SECRET_KEY")
	}
	validateRange(&fields, "challenge.pow_difficulty", c.Challenge.PowDifficulty, 8, 24)
	if c.Challenge.MinElapsedMS < 0 {
		fields = append(fields, "challenge.min_elapsed_ms must be >= 0")
	}
	if c.Challenge.MaxElapsedMS <= c.Challenge.MinElapsedMS {
		fields = append(fields, "challenge.max_elapsed_ms must be greater than challenge.min_elapsed_ms")
	}
	validateEnum(&fields, "logging.level", c.Logging.Level, "debug", "info", "warn", "error")
	validateEnum(&fields, "logging.format", c.Logging.Format, "json", "pretty")
	validateEnum(&fields, "logging.output", c.Logging.Output, "stdout", "stderr")
	validateEnum(&fields, "storage.backend", c.Storage.Backend, "memory", "redis")
	if c.Storage.Backend == "redis" {
		if c.Storage.Redis == nil {
			fields = append(fields, "storage.redis is required when storage.backend is redis")
		} else {
			requireString(&fields, "storage.redis.address", c.Storage.Redis.Address)
		}
	}
	if c.Admin.Enabled && len(c.Admin.Token) < 32 {
		fields = append(fields, "admin.token is required and must be at least 32 characters; set WAF_ADMIN_TOKEN")
	}
	for i, domain := range c.Domains {
		prefix := fmt.Sprintf("domains[%d]", i)
		requireString(&fields, prefix+".host", domain.Host)
		requireString(&fields, prefix+".upstream", domain.Upstream)
		validateURL(&fields, prefix+".upstream", domain.Upstream)
	}

	if len(fields) > 0 {
		return ValidationError{Fields: fields}
	}

	return nil
}

// validateServerTLS valide la terminaison TLS par domaine (FR-33). Les
// vérifications de chargement réel des fichiers (parse PEM, concordance
// cert/clé) sont faites au démarrage par internal/tlsmgr (fail-fast).
func validateServerTLS(fields *[]string, c *Config) {
	if !c.Server.TLS.Enabled {
		return
	}
	if c.ACME.Enabled {
		*fields = append(*fields, "server.tls.enabled and acme.enabled are mutually exclusive on the same listener")
	}
	requireString(fields, "server.tls.listen", c.Server.TLS.Listen)
	if c.Server.TLS.MinVersion != "" {
		validateEnum(fields, "server.tls.min_version", c.Server.TLS.MinVersion, "1.2", "1.3")
	}
	// Certificat par défaut : cert_file et key_file vont par paire.
	hasDefault := c.Server.TLS.CertFile != "" || c.Server.TLS.KeyFile != ""
	if hasDefault {
		requireString(fields, "server.tls.cert_file", c.Server.TLS.CertFile)
		requireString(fields, "server.tls.key_file", c.Server.TLS.KeyFile)
	}
	// Certificats par domaine : paire complète obligatoire si le bloc tls existe.
	domainsWithTLS := 0
	for i, domain := range c.Domains {
		if domain.TLS == nil {
			continue
		}
		domainsWithTLS++
		prefix := fmt.Sprintf("domains[%d].tls", i)
		requireString(fields, prefix+".cert_file", domain.TLS.CertFile)
		requireString(fields, prefix+".key_file", domain.TLS.KeyFile)
	}
	// Avec TLS activé, il faut au moins une source de certificat.
	if !hasDefault && domainsWithTLS == 0 {
		*fields = append(*fields, "server.tls.enabled requires at least one certificate (server.tls.cert_file/key_file or a domains[].tls entry)")
	}
}

func validatePressureLevels(fields *[]string, cfg PressureLevels) {
	if cfg.ElevatedMultiplier < 1 {
		*fields = append(*fields, "antiddos.pressure_levels.elevated_multiplier must be >= 1")
	}
	if cfg.HighMultiplier < 1 {
		*fields = append(*fields, "antiddos.pressure_levels.high_multiplier must be >= 1")
	}
	if cfg.CriticalMultiplier < 1 {
		*fields = append(*fields, "antiddos.pressure_levels.critical_multiplier must be >= 1")
	}
	if cfg.ElevatedMultiplier > cfg.HighMultiplier || cfg.HighMultiplier > cfg.CriticalMultiplier {
		*fields = append(*fields, "antiddos.pressure_levels multipliers must be ordered elevated <= high <= critical")
	}
}

// pressureRank classe les niveaux de pression pour comparer trigger/exit (FR-39).
// -1 = inconnu.
func pressureRank(level string) int {
	switch level {
	case "normal":
		return 0
	case "elevated":
		return 1
	case "high":
		return 2
	case "critical":
		return 3
	default:
		return -1
	}
}

func validateUnderAttack(fields *[]string, cfg UnderAttack) {
	if !cfg.Enabled {
		return
	}
	validateEnum(fields, "antiddos.under_attack.scope", cfg.Scope, "per_domain", "global")
	validateEnum(fields, "antiddos.under_attack.trigger_pressure", cfg.TriggerPressure, "elevated", "high", "critical")
	validateEnum(fields, "antiddos.under_attack.exit_pressure", cfg.ExitPressure, "normal", "elevated", "high", "critical")
	validateDuration(fields, "antiddos.under_attack.cooldown", cfg.Cooldown)
	if trigger, exit := pressureRank(cfg.TriggerPressure), pressureRank(cfg.ExitPressure); trigger >= 0 && exit >= 0 && exit > trigger {
		*fields = append(*fields, "antiddos.under_attack.exit_pressure must be <= trigger_pressure")
	}
	if cfg.MaxTrackedDomains < 1 {
		*fields = append(*fields, "antiddos.under_attack.max_tracked_domains must be >= 1")
	}
}

func validateRiskEngine(fields *[]string, cfg RiskEngine) {
	validateEnum(fields, "risk_engine.profile", cfg.Profile, "lenient", "balanced", "strict")
	validateFloatRange(fields, "risk_engine.block_min_confidence", cfg.BlockMinConfidence, 0, 1)
	if cfg.MinCorroboratingFamilies < 1 {
		*fields = append(*fields, "risk_engine.min_corroborating_families must be >= 1")
	}
	validateRange(fields, "risk_engine.tiers.observe", cfg.Tiers.Observe, 0, 100)
	validateRange(fields, "risk_engine.tiers.throttle", cfg.Tiers.Throttle, 0, 100)
	validateRange(fields, "risk_engine.tiers.challenge", cfg.Tiers.Challenge, 0, 100)
	validateRange(fields, "risk_engine.tiers.tarpit", cfg.Tiers.Tarpit, 0, 100)
	validateRange(fields, "risk_engine.tiers.block", cfg.Tiers.Block, 0, 100)
	if cfg.Tiers.Observe >= cfg.Tiers.Throttle ||
		cfg.Tiers.Throttle >= cfg.Tiers.Challenge ||
		cfg.Tiers.Challenge >= cfg.Tiers.Tarpit ||
		cfg.Tiers.Tarpit >= cfg.Tiers.Block {
		*fields = append(*fields, "risk_engine.tiers must be strictly increasing")
	}
	validateRange(fields, "risk_engine.family_corroboration_threshold", cfg.FamilyCorroborationThreshold, 0, 100)
	allowedWeights := map[string]bool{
		"reputation":   true,
		"behavioral":   true,
		"tls":          true,
		"fingerprint":  true,
		"integrity":    true,
		"rate":         true,
		"geo":          true,
		"human_credit": true,
	}
	for family, weight := range cfg.Weights {
		if !allowedWeights[family] {
			*fields = append(*fields, fmt.Sprintf("risk_engine.weights.%s is not a supported signal family", family))
		}
		if weight < 0 {
			*fields = append(*fields, fmt.Sprintf("risk_engine.weights.%s must be >= 0", family))
		}
	}
}

func (c *Config) applyEnvOverrides() {
	if value := os.Getenv(envChallengeSecretKey); value != "" {
		c.Challenge.SecretKey = value
	}
	if value := os.Getenv(envAdminToken); value != "" {
		c.Admin.Token = value
	}
	if value := os.Getenv(envOriginSecret); value != "" {
		c.OriginProtection.Secret = value
	}
	if value := os.Getenv(envRedisPassword); value != "" {
		if c.Storage.Redis == nil {
			c.Storage.Redis = &RedisConfig{}
		}
		c.Storage.Redis.Password = value
	}
}

func requireString(fields *[]string, name, value string) {
	if strings.TrimSpace(value) == "" {
		*fields = append(*fields, name+" is required")
	}
}

func validateDuration(fields *[]string, name, value string) {
	if strings.TrimSpace(value) == "" {
		*fields = append(*fields, name+" is required")
		return
	}
	if _, err := time.ParseDuration(value); err != nil {
		*fields = append(*fields, name+" must be a valid Go duration")
	}
}

func validateRange(fields *[]string, name string, value, min, max int) {
	if value < min || value > max {
		*fields = append(*fields, fmt.Sprintf("%s must be between %d and %d", name, min, max))
	}
}

func validateFloatRange(fields *[]string, name string, value, min, max float64) {
	if value < min || value > max {
		*fields = append(*fields, fmt.Sprintf("%s must be between %.2f and %.2f", name, min, max))
	}
}

func validateEnum(fields *[]string, name, value string, allowed ...string) {
	if slices.Contains(allowed, value) {
		return
	}
	*fields = append(*fields, fmt.Sprintf("%s must be one of %s", name, strings.Join(allowed, ", ")))
}

func validateURL(fields *[]string, name, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		*fields = append(*fields, name+" must be an absolute URL")
	}
}

func IsValidationError(err error) bool {
	var validationError ValidationError
	return errors.As(err, &validationError)
}
