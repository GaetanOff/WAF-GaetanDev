// Package redis implémente storage.Store sur Redis, pour les déploiements
// multi-instances (ADR-002). Sa sémantique d'exécution — écriture traversante,
// mode dégradé, expiration déléguée à Redis — est fixée par ADR-021.
package redis

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/gaetandev/waf/internal/config"
	"github.com/gaetandev/waf/internal/storage"
	"github.com/gaetandev/waf/internal/storage/memory"
	goredis "github.com/redis/go-redis/v9"
)

const (
	visitorKeyPrefix = "waf:visitor:"
	bucketKeyPrefix  = "waf:bucket:"

	// defaultTimeout borne une opération Redis sur le chemin de requête.
	// Surchargeable par storage.redis.timeout.
	defaultTimeout = 100 * time.Millisecond

	// pingTimeout est le budget de la vérification de connectivité au démarrage.
	// Plus large que defaultTimeout : au boot, une résolution DNS ou un
	// établissement TLS peut légitimement prendre un peu de temps.
	pingTimeout = 5 * time.Second

	// degradedThreshold est le nombre d'erreurs CONSÉCUTIVES qui font basculer le
	// nœud sur son état local, degradedWindow la durée avant nouvelle sonde
	// (ADR-021). Ce sont des détails de résilience, pas une politique
	// d'exploitation : ils ne sont donc pas exposés en configuration.
	degradedThreshold = 3
	degradedWindow    = 5 * time.Second

	// scanBatch borne un lot SCAN/MGET pour ListVisitors (API admin). Jamais de
	// KEYS : la commande bloque Redis le temps de parcourir tout l'espace de clés.
	scanBatch = 200
)

// commander est le sous-ensemble de l'API go-redis réellement utilisé. Passer
// par une interface permet de tester le mode dégradé, le calcul de TTL et la
// sérialisation SANS Redis en CI (ADR-002 : pas de Redis dans les tests), et
// documente au passage la surface de commandes dont dépend le WAF.
type commander interface {
	Get(ctx context.Context, key string) *goredis.StringCmd
	MGet(ctx context.Context, keys ...string) *goredis.SliceCmd
	Set(ctx context.Context, key string, value any, expiration time.Duration) *goredis.StatusCmd
	Del(ctx context.Context, keys ...string) *goredis.IntCmd
	Scan(ctx context.Context, cursor uint64, match string, count int64) *goredis.ScanCmd
	Ping(ctx context.Context) *goredis.StatusCmd
	Close() error
}

// Observer reçoit l'état du backend. Interface structurelle satisfaite par
// *metrics.Metrics : sans elle, le mode dégradé serait un état invisible.
type Observer interface {
	SetStorageDegraded(degraded bool)
	IncStorageError(operation string)
}

// Store est le backend Redis. Il satisfait storage.Store, dont aucune méthode ne
// retourne d'erreur : les échecs Redis sont donc traités ICI, jamais remontés à
// l'appelant. La réponse est toujours la même — servir l'état local et compter
// l'échec (ADR-021).
type Store struct {
	client      commander
	timeout     time.Duration
	local       *memory.Store
	maxVisitors int
	observer    Observer
	now         func() time.Time

	failures      atomic.Int64
	degradedUntil atomic.Int64 // instant de fin de fenêtre dégradée, en nanosecondes Unix
	probing       atomic.Bool  // fenêtre écoulée : la prochaine erreur re-bascule aussitôt
	degradedGauge atomic.Bool  // dernier état publié à l'Observer
}

// Option configure un Store à la construction.
type Option func(*Store)

// WithObserver branche les métriques d'exploitation (mode dégradé, erreurs).
func WithObserver(observer Observer) Option {
	return func(s *Store) {
		s.observer = observer
	}
}

// WithClock injecte l'horloge (tests, et cohérence avec memory.WithClock).
func WithClock(now func() time.Time) Option {
	return func(s *Store) {
		if now != nil {
			s.now = now
		}
	}
}

// withCommander substitue le client Redis (tests).
func withCommander(client commander) Option {
	return func(s *Store) {
		s.client = client
	}
}

// New ouvre le backend Redis et vérifie la connectivité.
//
// Redis injoignable au démarrage est une ERREUR DE DÉMARRAGE, pas un mode
// dégradé : l'opérateur a demandé `storage.backend: redis`, une adresse ou un
// mot de passe fautif doit se voir tout de suite. Démarrer en dégradé
// reproduirait le défaut que ce backend corrige — un WAF qui sert un état par
// nœud alors que la configuration promet un état partagé.
func New(cfg config.RedisConfig, maxVisitors int, opts ...Option) (*Store, error) {
	timeout := defaultTimeout
	if cfg.Timeout != "" {
		parsed, err := time.ParseDuration(cfg.Timeout)
		if err != nil {
			return nil, fmt.Errorf("storage.redis.timeout: %w", err)
		}
		if parsed <= 0 {
			return nil, errors.New("storage.redis.timeout must be positive")
		}
		timeout = parsed
	}

	store := &Store{
		timeout:     timeout,
		maxVisitors: maxVisitors,
		now:         time.Now,
	}
	for _, opt := range opts {
		opt(store)
	}
	// Le store local est construit APRÈS les options, pour qu'il partage
	// l'horloge du Store : sinon l'expiration de l'état de repli suivrait une
	// autre horloge que les décisions qui le lisent (cf. memory.WithClock).
	store.local = memory.New(maxVisitors, memory.WithClock(store.now))
	// Le client réel n'est construit que si aucun n'a été injecté : ouvrir une
	// connexion pour la remplacer aussitôt laisserait un client non fermé.
	if store.client == nil {
		options := &goredis.Options{
			Addr:        cfg.Address,
			Password:    cfg.Password,
			DB:          cfg.DB,
			DialTimeout: pingTimeout,
		}
		if cfg.TLS {
			options.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		store.client = goredis.NewClient(options)
	}

	ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
	defer cancel()
	if err := store.client.Ping(ctx).Err(); err != nil {
		store.local.Close()
		_ = store.client.Close()
		return nil, fmt.Errorf("redis storage backend at %s: %w", cfg.Address, err)
	}
	return store, nil
}

func (s *Store) GetVisitor(key string) (*storage.VisitorState, bool) {
	if s.degraded() {
		return s.local.GetVisitor(key)
	}

	ctx, cancel := s.operationContext()
	defer cancel()
	payload, err := s.client.Get(ctx, visitorKeyPrefix+key).Bytes()
	if errors.Is(err, goredis.Nil) {
		s.succeeded()
		return nil, false // absence de clé : réponse valide, pas une panne
	}
	if err != nil {
		s.failed("get_visitor")
		return s.local.GetVisitor(key)
	}
	s.succeeded()

	var visitor storage.VisitorState
	if err := json.Unmarshal(payload, &visitor); err != nil {
		// Valeur illisible : ce n'est pas un problème de connectivité, donc pas
		// une raison de basculer en dégradé. On la traite comme une absence.
		s.observeError("decode_visitor")
		return nil, false
	}
	if s.expired(visitor.ExpiresAt) {
		return nil, false
	}
	return &visitor, true
}

func (s *Store) SetVisitor(key string, visitor storage.VisitorState) {
	ttl, expired := s.ttlFor(visitor.ExpiresAt)
	if expired {
		s.DeleteVisitor(key)
		return
	}
	// Écriture traversante : l'état local reste chaud, donc un basculement en
	// mode dégradé hérite d'un état récent au lieu de repartir de zéro (ADR-021).
	s.local.SetVisitor(key, visitor)
	s.write(visitorKeyPrefix+key, visitor, ttl, "set_visitor")
}

func (s *Store) DeleteVisitor(key string) {
	s.local.DeleteVisitor(key)
	if s.degraded() {
		return
	}
	ctx, cancel := s.operationContext()
	defer cancel()
	if err := s.client.Del(ctx, visitorKeyPrefix+key).Err(); err != nil {
		s.failed("delete_visitor")
		return
	}
	s.succeeded()
}

// ListVisitors sert l'API admin. Le parcours est borné à maxVisitors entrées :
// un Redis partagé par un cluster peut porter des centaines de milliers de
// visiteurs, que personne ne veut voir sérialisés dans une réponse HTTP.
func (s *Store) ListVisitors() []storage.VisitorState {
	if s.degraded() {
		return s.local.ListVisitors()
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.timeout*scanBatch)
	defer cancel()

	visitors := make([]storage.VisitorState, 0)
	var cursor uint64
	for len(visitors) < s.maxVisitors {
		keys, next, err := s.client.Scan(ctx, cursor, visitorKeyPrefix+"*", scanBatch).Result()
		if err != nil {
			s.failed("list_visitors")
			return s.local.ListVisitors()
		}
		if len(keys) > 0 {
			if remaining := s.maxVisitors - len(visitors); len(keys) > remaining {
				keys = keys[:remaining]
			}
			values, err := s.client.MGet(ctx, keys...).Result()
			if err != nil {
				s.failed("list_visitors")
				return s.local.ListVisitors()
			}
			for _, value := range values {
				raw, ok := value.(string)
				if !ok {
					continue // clé expirée entre le SCAN et le MGET
				}
				var visitor storage.VisitorState
				if err := json.Unmarshal([]byte(raw), &visitor); err != nil {
					s.observeError("decode_visitor")
					continue
				}
				if s.expired(visitor.ExpiresAt) {
					continue
				}
				visitors = append(visitors, visitor)
			}
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	s.succeeded()
	return visitors
}

func (s *Store) GetBucket(key string) (*storage.RateBucket, bool) {
	if s.degraded() {
		return s.local.GetBucket(key)
	}

	ctx, cancel := s.operationContext()
	defer cancel()
	payload, err := s.client.Get(ctx, bucketKeyPrefix+key).Bytes()
	if errors.Is(err, goredis.Nil) {
		s.succeeded()
		return nil, false
	}
	if err != nil {
		s.failed("get_bucket")
		return s.local.GetBucket(key)
	}
	s.succeeded()

	var bucket storage.RateBucket
	if err := json.Unmarshal(payload, &bucket); err != nil {
		s.observeError("decode_bucket")
		return nil, false
	}
	if s.expired(bucket.ExpiresAt) {
		return nil, false
	}
	return &bucket, true
}

func (s *Store) SetBucket(key string, bucket storage.RateBucket) {
	ttl, expired := s.ttlFor(bucket.ExpiresAt)
	if expired {
		return // un bucket déjà périmé équivaut à un bucket plein : rien à écrire
	}
	s.local.SetBucket(key, bucket)
	s.write(bucketKeyPrefix+key, bucket, ttl, "set_bucket")
}

func (s *Store) Close() {
	s.local.Close()
	if err := s.client.Close(); err != nil {
		s.observeError("close")
	}
}

// write sérialise et écrit une valeur, hors mode dégradé.
func (s *Store) write(key string, value any, ttl time.Duration, operation string) {
	if s.degraded() {
		return
	}
	payload, err := json.Marshal(value)
	if err != nil {
		s.observeError(operation)
		return
	}
	ctx, cancel := s.operationContext()
	defer cancel()
	if err := s.client.Set(ctx, key, payload, ttl).Err(); err != nil {
		s.failed(operation)
		return
	}
	s.succeeded()
}

// ttlFor traduit une échéance absolue en TTL Redis. Le second retour signale un
// état DÉJÀ périmé, qu'il ne faut pas écrire. Une échéance nulle vaut « pas
// d'expiration » (TTL 0 côté Redis), comme pour le store mémoire — cas qui
// n'existe pas en pratique, le score manager et le rate limiter posent toujours
// une échéance.
func (s *Store) ttlFor(expiresAt time.Time) (time.Duration, bool) {
	if expiresAt.IsZero() {
		return 0, false
	}
	ttl := expiresAt.Sub(s.now())
	if ttl <= 0 {
		return 0, true
	}
	return ttl, false
}

// expired reproduit la sémantique d'expiration du store mémoire. Redis expire
// ses clés lui-même, mais l'écart d'horloge entre le WAF et Redis peut laisser
// remonter une entrée d'un cheveu périmée : la décision de sécurité doit suivre
// l'horloge du WAF, qui est celle du reste du pipeline.
func (s *Store) expired(expiresAt time.Time) bool {
	return !expiresAt.IsZero() && !expiresAt.After(s.now())
}

func (s *Store) operationContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), s.timeout)
}

// degraded indique si le nœud sert son état local.
func (s *Store) degraded() bool {
	until := s.degradedUntil.Load()
	if until == 0 {
		return false
	}
	if s.now().UnixNano() < until {
		return true
	}
	// Fenêtre écoulée : on repasse en nominal pour SONDER Redis. Une seule
	// erreur suffit alors à re-basculer — sinon chaque fenêtre coûterait
	// degradedThreshold opérations en timeout sur le chemin de requête.
	if s.degradedUntil.CompareAndSwap(until, 0) {
		s.probing.Store(true)
	}
	return false
}

// failed compte une erreur d'infrastructure et bascule au seuil.
func (s *Store) failed(operation string) {
	s.observeError(operation)
	if s.probing.Load() {
		s.enterDegraded()
		return
	}
	if s.failures.Add(1) < degradedThreshold {
		return
	}
	s.enterDegraded()
}

func (s *Store) enterDegraded() {
	s.failures.Store(0)
	s.probing.Store(false)
	s.degradedUntil.Store(s.now().Add(degradedWindow).UnixNano())
	s.publishDegraded(true)
}

// succeeded acquitte une opération nominale : le compteur d'erreurs
// consécutives repart de zéro et la sonde est validée.
func (s *Store) succeeded() {
	s.failures.Store(0)
	s.probing.Store(false)
	s.publishDegraded(false)
}

// publishDegraded ne notifie l'Observer que sur transition : la jauge est posée
// à chaque requête, la notifier à chaque fois n'apporterait rien.
func (s *Store) publishDegraded(degraded bool) {
	if s.degradedGauge.Swap(degraded) == degraded {
		return
	}
	if s.observer != nil {
		s.observer.SetStorageDegraded(degraded)
	}
}

func (s *Store) observeError(operation string) {
	if s.observer != nil {
		s.observer.IncStorageError(operation)
	}
}
