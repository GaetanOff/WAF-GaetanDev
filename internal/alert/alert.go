// Package alert envoie des alertes de sécurité vers des webhooks (FR-29) :
// Slack, Discord ou HTTP générique. L'envoi est asynchrone et non bloquant,
// avec retry à backoff exponentiel et déduplication par cooldown.
package alert

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// Types de webhook supportés.
const (
	SinkGeneric = "generic"
	SinkSlack   = "slack"
	SinkDiscord = "discord"
)

// Alert est le payload d'alerte (cf. schemas/alert.schema.json, forme condensée).
type Alert struct {
	Timestamp string `json:"timestamp"`
	Trigger   string `json:"trigger"`
	Severity  string `json:"severity"`
	Domain    string `json:"domain"`
	Title     string `json:"title"`
	Message   string `json:"message"`
}

// Sink est une destination de webhook.
type Sink struct {
	Type string
	URL  string
}

// Notifier dispatche les alertes de façon asynchrone vers les sinks.
type Notifier struct {
	sinks      []Sink
	cooldown   time.Duration
	maxRetries int
	client     *http.Client

	queue chan Alert
	stop  chan struct{}
	done  chan struct{}

	mu       sync.Mutex
	lastSent map[string]time.Time
	now      func() time.Time
}

func NewNotifier(sinks []Sink, cooldown time.Duration, maxRetries int, client *http.Client) *Notifier {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	if maxRetries < 0 {
		maxRetries = 0
	}
	n := &Notifier{
		sinks:      sinks,
		cooldown:   cooldown,
		maxRetries: maxRetries,
		client:     client,
		queue:      make(chan Alert, 256),
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
		lastSent:   make(map[string]time.Time),
		now:        time.Now,
	}
	go n.worker()
	return n
}

func (n *Notifier) worker() {
	defer close(n.done)
	for {
		select {
		case <-n.stop:
			return
		case alert := <-n.queue:
			n.deliver(alert)
		}
	}
}

// Notify construit et dispatche une alerte à partir d'un événement WAF.
func (n *Notifier) Notify(trigger string, domain string, reason string) {
	n.Dispatch(Alert{
		Timestamp: n.now().UTC().Format(time.RFC3339),
		Trigger:   trigger,
		Severity:  severityFor(trigger),
		Domain:    domain,
		Title:     "WAF " + trigger,
		Message:   reason,
	})
}

// Dispatch enfile une alerte si le cooldown (par trigger+domaine) est écoulé.
// Non bloquant ; déposée silencieusement si la file est pleine.
func (n *Notifier) Dispatch(alert Alert) {
	if !n.allow(alert) {
		return
	}
	select {
	case n.queue <- alert:
	default:
	}
}

func (n *Notifier) allow(alert Alert) bool {
	key := alert.Trigger + "|" + alert.Domain
	n.mu.Lock()
	defer n.mu.Unlock()
	now := n.now()
	if last, ok := n.lastSent[key]; ok && now.Sub(last) < n.cooldown {
		return false
	}
	n.lastSent[key] = now
	return true
}

func (n *Notifier) deliver(alert Alert) {
	for _, sink := range n.sinks {
		payload := encode(sink.Type, alert)
		n.sendWithRetry(sink.URL, payload)
	}
}

func (n *Notifier) sendWithRetry(url string, payload []byte) {
	backoff := 200 * time.Millisecond
	for attempt := 0; attempt <= n.maxRetries; attempt++ {
		if n.post(url, payload) {
			return
		}
		if attempt < n.maxRetries {
			time.Sleep(backoff)
			backoff *= 2
		}
	}
}

func (n *Notifier) post(url string, payload []byte) bool {
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return false
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := n.client.Do(request)
	if err != nil {
		return false
	}
	defer func() { _ = response.Body.Close() }()
	return response.StatusCode >= 200 && response.StatusCode < 300
}

func (n *Notifier) Close() {
	close(n.stop)
	<-n.done
}

// encode formate le payload selon le type de sink (Slack/Discord/générique).
func encode(sinkType string, alert Alert) []byte {
	text := "[" + alert.Severity + "] " + alert.Title + " — " + alert.Domain + " : " + alert.Message
	var payload any
	switch sinkType {
	case SinkSlack:
		payload = map[string]string{"text": text}
	case SinkDiscord:
		payload = map[string]string{"content": text}
	default:
		payload = alert
	}
	data, _ := json.Marshal(payload)
	return data
}

func severityFor(trigger string) string {
	switch trigger {
	case "circuit_breaker", "degraded_mode", "honeypot":
		return "critical"
	case "block":
		return "warning"
	default:
		return "info"
	}
}
