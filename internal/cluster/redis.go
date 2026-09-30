package cluster

import (
	"context"
	"crypto/tls"
	"sync/atomic"

	"github.com/gaetandev/waf/internal/config"
	"github.com/redis/go-redis/v9"
)

// RedisBus implémente Bus via Redis Pub/Sub (FR-20). En cas d'erreur de
// connexion, les publications échouent silencieusement côté appelant (fallback
// autonome) et la boucle d'abonnement s'arrête proprement à l'annulation du
// contexte. Chaque message est signé par une clé partagée par les nœuds : tout
// client capable de publier sur le canal pouvait sinon propager une blacklist,
// un score ou un circuit à tout le cluster.
type RedisBus struct {
	client   *redis.Client
	channel  string
	key      []byte
	rejected atomic.Int64
}

func NewRedisBus(cfg config.RedisConfig, channel string, key []byte) *RedisBus {
	options := &redis.Options{
		Addr:     cfg.Address,
		Password: cfg.Password,
		DB:       cfg.DB,
	}
	if cfg.TLS {
		options.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return &RedisBus{client: redis.NewClient(options), channel: channel, key: key}
}

func (b *RedisBus) Publish(ctx context.Context, event Event) error {
	payload, err := seal(b.key, event)
	if err != nil {
		return err
	}
	return b.client.Publish(ctx, b.channel, payload).Err()
}

func (b *RedisBus) Subscribe(ctx context.Context, handler func(Event)) error {
	sub := b.client.Subscribe(ctx, b.channel)
	go func() {
		defer func() { _ = sub.Close() }()
		channel := sub.Channel()
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-channel:
				if !ok {
					return
				}
				b.deliver(msg.Payload, handler)
			}
		}
	}()
	return nil
}

// deliver transmet au handler un message dont la signature est valide ; les
// autres sont comptés, jamais appliqués.
func (b *RedisBus) deliver(message string, handler func(Event)) {
	event, err := open(b.key, message)
	if err != nil {
		b.rejected.Add(1)
		return
	}
	handler(event)
}

// Rejected retourne le nombre de messages ignorés (signature absente ou
// invalide, JSON malformé, type inconnu) : waf_cluster_rejected_events_total.
func (b *RedisBus) Rejected() int64 {
	return b.rejected.Load()
}

func (b *RedisBus) Close() error {
	return b.client.Close()
}
