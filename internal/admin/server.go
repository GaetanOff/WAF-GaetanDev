package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gaetandev/waf/internal/audit"
	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/logger"
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
	events      *eventLog
	counters    *trafficCounters
	trail       *audit.Trail
	brute       *selfprotect.Window
	startedAt   time.Time
	httpServer  *http.Server
	onBlacklist func(value string)
	// onBlacklistRemove est notifié de chaque retrait de la blacklist
	// (propagation cluster, FR-20).
	onBlacklistRemove func(value string)
	onPanic           func()
	applyConfig       ConfigApplier
	erasers           []func(ipHash string)
}

// WithErasers branche l'effacement RGPD (FR-28) sur les états par visiteur
// tenus hors du store de visiteurs : buckets de rate limit, profil
// comportemental, dernier JA3. Sans eux, POST /waf/admin/gdpr/erase ne
// supprimait que le visiteur.
func (s *Server) WithErasers(erasers ...func(ipHash string)) {
	s.erasers = append(s.erasers, erasers...)
}

// EventRecorder retourne le puits d'événements de sécurité à brancher sur le
// logger (logger.Logger.Recorder) : il alimente GET /waf/admin/events et les
// compteurs de GET /waf/stats.
func (s *Server) EventRecorder() logger.EventRecorder {
	return eventRecorders{s.counters, s.events}
}

// WithConfigApplier branche l'application à chaud de PATCH /waf/admin/config
// sur les composants runtime. Sans applier, l'endpoint répond 503 plutôt que de
// prétendre avoir appliqué une modification.
func (s *Server) WithConfigApplier(applier ConfigApplier) {
	s.applyConfig = applier
}

// WithPanicObserver est notifié de chaque panic récupéré d'un handler admin
// (NFR-04, waf_panics_total).
func (s *Server) WithPanicObserver(observer func()) {
	s.onPanic = observer
}

// WithBlacklistObserver est notifié de chaque entrée ajoutée à la blacklist
// (propagation cluster, FR-20).
func (s *Server) WithBlacklistObserver(observer func(value string)) {
	s.onBlacklist = observer
}

// WithBlacklistRemoveObserver est notifié de chaque entrée retirée de la
// blacklist (propagation cluster, FR-20).
func (s *Server) WithBlacklistRemoveObserver(observer func(value string)) {
	s.onBlacklistRemove = observer
}

// ApplyClusterBlacklistRemove retire une entrée que l'administrateur d'un
// autre nœud a retirée (FR-20). Seule une entrée ajoutée à l'exécution l'est :
// une entrée de la configuration de ce nœud reste en place.
func (s *Server) ApplyClusterBlacklistRemove(value string) error {
	_, err := s.state.RemoveRuntimeBlacklist(value)
	return err
}

// ApplyClusterBlacklist enregistre une entrée de blacklist reçue d'un autre
// nœud (FR-20) dans l'état admin, qui reste ainsi l'unique source du RuleSet :
// l'entrée survit aux modifications admin locales, apparaît dans
// GET /waf/admin/blacklist et peut y être retirée. Elle n'est ni republiée (le
// nœud émetteur l'a déjà diffusée) ni journalisée comme action d'administration.
func (s *Server) ApplyClusterBlacklist(value string) error {
	_, _, err := s.state.AddBlacklist(IPEntry{IP: value, Reason: clusterBlacklistReason})
	return err
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
		events:      newEventLog(),
		counters:    &trafficCounters{},
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
		MaxHeaderBytes:      cfg.Server.MaxHeaderBytes,
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
