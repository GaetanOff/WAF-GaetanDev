// Package alert envoie des alertes de sécurité vers des webhooks (FR-29) :
// Slack, Discord ou HTTP générique. L'envoi est asynchrone et non bloquant,
// avec retry à backoff exponentiel et déduplication par cooldown.
package alert

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Types de webhook supportés.
const (
	SinkGeneric = "generic"
	SinkSlack   = "slack"
	SinkDiscord = "discord"
)

// Event décrit l'événement de sécurité source d'une alerte (entrée du Notifier).
// Le Notifier en dérive l'Alert enrichie (sévérité, titre, payload formaté).
type Event struct {
	Trigger    string
	Domain     string
	Reason     string
	IP         string
	Path       string
	Method     string
	Action     string
	RequestID  string
	Country    string
	TrustScore int
}

// Alert est le payload d'alerte enrichi (cf. schemas/alert.schema.json).
type Alert struct {
	Timestamp  string `json:"timestamp"`
	Trigger    string `json:"trigger"`
	Severity   string `json:"severity"`
	Domain     string `json:"domain"`
	Title      string `json:"title"`
	Message    string `json:"message"`
	Reason     string `json:"reason,omitempty"`
	IP         string `json:"ip,omitempty"`
	Path       string `json:"path,omitempty"`
	Method     string `json:"method,omitempty"`
	Action     string `json:"action,omitempty"`
	RequestID  string `json:"request_id,omitempty"`
	Country    string `json:"country,omitempty"`
	TrustScore int    `json:"trust_score"`
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

// Notify construit et dispatche une alerte enrichie à partir d'un événement WAF.
func (n *Notifier) Notify(ev Event) {
	n.Dispatch(Alert{
		Timestamp:  n.now().UTC().Format(time.RFC3339),
		Trigger:    ev.Trigger,
		Severity:   severityFor(ev.Trigger),
		Domain:     ev.Domain,
		Title:      titleFor(ev.Trigger),
		Message:    messageFor(ev),
		Reason:     ev.Reason,
		IP:         ev.IP,
		Path:       ev.Path,
		Method:     ev.Method,
		Action:     ev.Action,
		RequestID:  ev.RequestID,
		Country:    ev.Country,
		TrustScore: ev.TrustScore,
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

// encode formate le payload selon le type de sink. Discord et Slack reçoivent un
// message riche (embed / attachment coloré avec champs) ; le générique reçoit
// l'Alert JSON complète.
func encode(sinkType string, alert Alert) []byte {
	var payload any
	switch sinkType {
	case SinkSlack:
		payload = slackPayload{Attachments: []slackAttachment{slackAttachmentFor(alert)}}
	case SinkDiscord:
		payload = discordPayload{Embeds: []discordEmbed{discordEmbedFor(alert)}}
	default:
		payload = alert
	}
	data, _ := json.Marshal(payload)
	return data
}

// --- Rendu Discord (embeds) ---------------------------------------------------

type discordPayload struct {
	Embeds []discordEmbed `json:"embeds"`
}

type discordEmbed struct {
	Title       string         `json:"title"`
	Description string         `json:"description,omitempty"`
	Color       int            `json:"color"`
	Fields      []discordField `json:"fields,omitempty"`
	Footer      discordFooter  `json:"footer"`
	Timestamp   string         `json:"timestamp"`
}

type discordField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

type discordFooter struct {
	Text string `json:"text"`
}

func discordEmbedFor(a Alert) discordEmbed {
	fields := make([]discordField, 0, 6)
	for _, kv := range a.fields() {
		fields = append(fields, discordField{Name: kv[0], Value: kv[1], Inline: true})
	}
	return discordEmbed{
		Title:       a.Title,
		Description: a.Message,
		Color:       discordColor(a.Severity),
		Fields:      fields,
		Footer:      discordFooter{Text: footerText(a)},
		Timestamp:   a.Timestamp,
	}
}

func discordColor(severity string) int {
	switch severity {
	case "critical":
		return 0xE74C3C // rouge
	case "warning":
		return 0xE67E22 // orange
	default:
		return 0x3498DB // bleu
	}
}

// --- Rendu Slack (attachments) ------------------------------------------------

type slackPayload struct {
	Attachments []slackAttachment `json:"attachments"`
}

type slackAttachment struct {
	Color  string       `json:"color"`
	Title  string       `json:"title"`
	Text   string       `json:"text,omitempty"`
	Fields []slackField `json:"fields,omitempty"`
	Footer string       `json:"footer"`
}

type slackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

func slackAttachmentFor(a Alert) slackAttachment {
	fields := make([]slackField, 0, 6)
	for _, kv := range a.fields() {
		fields = append(fields, slackField{Title: kv[0], Value: kv[1], Short: true})
	}
	return slackAttachment{
		Color:  slackColor(a.Severity),
		Title:  a.Title,
		Text:   a.Message,
		Fields: fields,
		Footer: footerText(a),
	}
}

func slackColor(severity string) string {
	switch severity {
	case "critical":
		return "#E74C3C"
	case "warning":
		return "#E67E22"
	default:
		return "#3498DB"
	}
}

// --- Helpers communs ----------------------------------------------------------

// fields retourne les paires label/valeur non vides à afficher, dans l'ordre.
func (a Alert) fields() [][2]string {
	out := make([][2]string, 0, 6)
	add := func(label, value string) {
		if value != "" {
			out = append(out, [2]string{label, value})
		}
	}
	add("Domaine", a.Domain)
	add("Action", a.Action)
	add("IP", a.IP)
	add("Pays", a.Country)
	add("Méthode", a.Method)
	add("Chemin", a.Path)
	add("Raison", a.Reason)
	add("Score", strconv.Itoa(a.TrustScore))
	return out
}

func footerText(a Alert) string {
	if a.RequestID != "" {
		return "WAF GaetanDev • req " + a.RequestID
	}
	return "WAF GaetanDev"
}

// titleFor produit un titre lisible (avec emoji) à partir du trigger.
func titleFor(trigger string) string {
	switch trigger {
	case "honeypot":
		return "🍯 Honeypot déclenché"
	case "circuit_breaker":
		return "🔌 Circuit breaker ouvert"
	case "degraded_mode":
		return "🌊 Mode dégradé (anti-DDoS)"
	case "block":
		return "⛔ Requête bloquée"
	default:
		return "🛡️ Alerte WAF"
	}
}

// messageFor produit une phrase de description lisible pour l'embed.
func messageFor(ev Event) string {
	switch ev.Trigger {
	case "honeypot":
		return "Accès à un chemin piège (honeypot) — IP marquée et bloquée."
	case "circuit_breaker":
		return "Trop de violations consécutives : circuit ouvert pour cette IP."
	case "degraded_mode":
		return "Pression de trafic élevée : mitigations renforcées."
	case "block":
		return "Requête bloquée par le pare-feu applicatif."
	default:
		return ""
	}
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
