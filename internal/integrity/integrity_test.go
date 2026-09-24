package integrity

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gaetandev/waf/internal/config"
)

func testAnalyzer() Analyzer {
	cfg := config.Default()
	return NewAnalyzer(cfg)
}

func TestEvaluateDetections(t *testing.T) {
	analyzer := testAnalyzer()

	tests := []struct {
		name       string
		target     string
		wantMinCon int
		wantReason string
	}{
		{name: "clean", target: "http://example.test/articles/42?ref=news", wantMinCon: 0, wantReason: ""},
		{name: "traversal", target: "http://example.test/../../etc/passwd", wantMinCon: contribTraversal, wantReason: ReasonPathTraversal},
		{name: "encoded traversal", target: "http://example.test/x?p=..%2f..%2fetc", wantMinCon: contribTraversal, wantReason: ReasonPathTraversal},
		{name: "sql injection", target: "http://example.test/list?q=1+union+select+1", wantMinCon: contribInjection, wantReason: ReasonInjection},
		{name: "xss", target: "http://example.test/s?q=<script>alert(1)</script>", wantMinCon: contribInjection, wantReason: ReasonInjection},
		{name: "quote comment", target: "http://example.test/item?id=1'--", wantMinCon: contribInjection, wantReason: ReasonInjection},
		{name: "quote or", target: "http://example.test/login?u=a'+or+'1'='1", wantMinCon: contribInjection, wantReason: ReasonInjection},
		{name: "comment obfuscation", target: "http://example.test/list?q=1/**/union/**/select/**/1", wantMinCon: contribInjection, wantReason: ReasonInjection},
		{name: "encoded union", target: "http://example.test/search?q=1%20UNION%20SELECT%20%2A%20FROM%20users", wantMinCon: contribInjection, wantReason: ReasonInjection},
		// Régression : URL légitimes pénalisées par les sous-chaînes "--",
		// "select " et "/*".
		{name: "double dash slug", target: "http://example.test/blog/my--first-post", wantMinCon: 0},
		{name: "cli flag in query", target: "http://example.test/docs?flags=--verbose", wantMinCon: 0},
		{name: "git range", target: "http://example.test/compare/abc123--def456", wantMinCon: 0},
		{name: "select word", target: "http://example.test/search?q=please+select+your+size", wantMinCon: 0},
		{name: "glob path", target: "http://example.test/files/*/list", wantMinCon: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, tt.target, nil)
			result := analyzer.Evaluate(request)
			if result.Contribution < tt.wantMinCon {
				t.Fatalf("contribution = %d, want >= %d", result.Contribution, tt.wantMinCon)
			}
			if tt.wantReason != "" && result.Reason != tt.wantReason {
				t.Fatalf("reason = %q, want %q", result.Reason, tt.wantReason)
			}
			if tt.wantMinCon == 0 && result.Contribution != 0 {
				t.Fatalf("clean request contribution = %d, want 0", result.Contribution)
			}
		})
	}
}

func TestEvaluateExcessiveLength(t *testing.T) {
	analyzer := testAnalyzer()
	longQuery := "q=" + strings.Repeat("a", 5000)
	request := httptest.NewRequest(http.MethodGet, "http://example.test/search?"+longQuery, nil)

	if result := analyzer.Evaluate(request); result.Reason != ReasonExcessiveSize {
		t.Fatalf("reason = %q, want %q (contribution=%d)", result.Reason, ReasonExcessiveSize, result.Contribution)
	}
}

func TestHandlerPublishesIntegrityContribution(t *testing.T) {
	analyzer := testAnalyzer()
	request := httptest.NewRequest(http.MethodGet, "http://example.test/list?q=1+union+select+1", nil)
	response := httptest.NewRecorder()

	analyzer.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-WAF-Risk-integrity") == "" {
			t.Fatal("X-WAF-Risk-integrity not published")
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (integrity contributes, never blocks)", response.Code)
	}
}

func TestHandlerRejectsOversizedBody(t *testing.T) {
	analyzer := testAnalyzer()
	request := httptest.NewRequest(http.MethodPost, "http://example.test/upload", strings.NewReader("x"))
	request.ContentLength = (10 << 20) + 1
	response := httptest.NewRecorder()

	analyzer.Handler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("oversized body must not reach the next handler")
	})).ServeHTTP(response, request)

	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", response.Code)
	}
}

func TestHandlerSkipsWhenPassMarked(t *testing.T) {
	analyzer := testAnalyzer()
	request := httptest.NewRequest(http.MethodGet, "http://example.test/../../etc/passwd", nil)
	request.Header.Set("X-WAF-Action", "PASS")
	response := httptest.NewRecorder()

	analyzer.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-WAF-Risk-integrity") != "" {
			t.Fatal("PASS request must not be analyzed")
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", response.Code)
	}
}
