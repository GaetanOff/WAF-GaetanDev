package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gaetandev/waf/internal/audit"
	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/middleware/access"
	"github.com/gaetandev/waf/internal/selfprotect"
	"github.com/gaetandev/waf/internal/storage"
	"github.com/gaetandev/waf/internal/trust"
)

type Server struct {
	cfg         config.Config
	store       storage.Store
	scores      *trust.ScoreManager
	accessRules *access.RuleSet
	state       *State
	trail       *audit.Trail
	brute       *selfprotect.Window
	startedAt   time.Time
	httpServer  *http.Server
}

func NewServer(cfg config.Config, store storage.Store, scores *trust.ScoreManager, accessRules *access.RuleSet, startedAt time.Time) (*Server, error) {
	if cfg.Admin.Enabled && cfg.Admin.Token == "" {
		return nil, errors.New("admin token is required")
	}
	state, err := NewState(cfg, accessRules)
	if err != nil {
		return nil, err
	}
	var trail *audit.Trail
	if cfg.Audit.Enabled {
		trail, err = audit.NewTrail(cfg.Audit.MaxEntries, cfg.Audit.File)
		if err != nil {
			return nil, err
		}
	}
	var brute *selfprotect.Window
	if cfg.SelfProtection.Enabled {
		lockout, err := time.ParseDuration(cfg.SelfProtection.AdminLockout)
		if err != nil {
			return nil, fmt.Errorf("parse self_protection.admin_lockout: %w", err)
		}
		brute = selfprotect.NewWindow(cfg.SelfProtection.AdminMaxFailures, lockout)
	}
	server := &Server{
		cfg:         cfg,
		store:       store,
		scores:      scores,
		accessRules: accessRules,
		state:       state,
		trail:       trail,
		brute:       brute,
		startedAt:   startedAt,
	}
	server.httpServer = &http.Server{
		Addr:              cfg.Server.AdminListen,
		Handler:           server.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		// Même borne FR-23 que le listener public : l'API admin est censée être
		// sur loopback, mais la défense en profondeur ne coûte rien ici.
		MaxHeaderValueCount: cfg.Server.MaxHeaderValueCount,
	}
	return server, nil
}

func (s *Server) ListenAndServe() error {
	if s.httpServer == nil {
		return errors.New("admin http server is not initialized")
	}
	if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("admin server: %w", err)
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.trail != nil {
		_ = s.trail.Close()
	}
	if s.httpServer == nil {
		return nil
	}
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) Handler() http.Handler {
	return s.routes()
}
