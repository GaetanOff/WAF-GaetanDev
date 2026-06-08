package cluster

import (
	"context"
	"crypto/tls"

	"github.com/gaetandev/waf/internal/config"
	"github.com/redis/go-redis/v9"
)

// RedisBus implémente Bus via Redis Pub/Sub (FR-20). En cas d'erreur de
// connexion, les publications échouent silencieusement côté appelant (fallback
// autonome) et la boucle d'abonnement s'arrête proprement à l'annulation du
// contexte.
type RedisBus struct {
	client  *redis.Client
	channel string
}

func NewRedisBus(cfg config.RedisConfig, channel string) *RedisBus {
	options := &redis.Options{
		Addr:     cfg.Address,
		Password: cfg.Password,
		DB:       cfg.DB,
	}
	if cfg.TLS {
		options.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return &RedisBus{client: redis.NewClient(options), channel: channel}
}

func (b *RedisBus) Publish(ctx context.Context, event Event) error {
	payload, err := encode(event)
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
				if event, err := decode([]byte(msg.Payload)); err == nil {
					handler(event)
				}
			}
		}
	}()
	return nil
}

func (b *RedisBus) Close() error {
	return b.client.Close()
}
