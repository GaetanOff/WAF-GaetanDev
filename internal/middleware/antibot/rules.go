package antibot

import (
	"net/http"
	"strings"

	"github.com/gaetandev/waf/internal/config"
)

const (
	ReasonHeadlessBrowser = "headless_browser_detected"
	ReasonSuspiciousUA    = "suspicious_user_agent"
	ReasonMissingUA       = "missing_user_agent"
	ReasonMissingHeader   = "missing_browser_header"
	ReasonHoneypot        = "honeypot_path"
	ReasonAutomationUA    = "automation_user_agent"
)

type Decision struct {
	Delta  int
	Block  bool
	Reason string
}

type Rules struct {
	honeypotPaths []string
}

func NewRules(cfg config.Config) Rules {
	return Rules{honeypotPaths: cfg.HoneypotPaths}
}

func (r Rules) Evaluate(req *http.Request) Decision {
	path := req.URL.Path
	for _, honeypotPath := range r.honeypotPaths {
		if path == honeypotPath {
			return Decision{Delta: -100, Block: true, Reason: ReasonHoneypot}
		}
	}

	userAgent := req.UserAgent()
	normalizedUA := strings.ToLower(userAgent)
	if strings.TrimSpace(userAgent) == "" {
		return Decision{Delta: -20, Reason: ReasonMissingUA}
	}
	if containsAny(normalizedUA, "selenium", "puppeteer") {
		return Decision{Delta: -100, Block: true, Reason: ReasonAutomationUA}
	}
	if containsAny(normalizedUA, "headlesschrome", "phantomjs", "swiftshader") {
		return Decision{Delta: -30, Reason: ReasonHeadlessBrowser}
	}
	if containsAny(normalizedUA, "python-requests", "curl/", "wget/", "go-http-client") {
		return Decision{Delta: -15, Reason: ReasonSuspiciousUA}
	}

	delta := 0
	if req.Header.Get("Accept-Language") == "" {
		delta -= 5
	}
	if req.Header.Get("Accept-Encoding") == "" {
		delta -= 5
	}
	if delta != 0 {
		return Decision{Delta: delta, Reason: ReasonMissingHeader}
	}

	return Decision{}
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}
