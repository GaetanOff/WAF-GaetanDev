// Package alert envoie des alertes de sécurité vers des webhooks (FR-29) :
// Slack, Discord ou HTTP générique. L'envoi est asynchrone et non bloquant,
// avec retry à backoff exponentiel et déduplication par cooldown.
package alert

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gaetandev/waf/internal/httpbody"
	"github.com/gaetandev/waf/internal/ttlcache"
)

// maxCooldownKeys borne le nombre de couples trigger+domaine suivis par le
// cooldown. Le domaine est le Host de la requête, fourni par le client.
const maxCooldownKeys = 10000

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
	// Immediate contourne la déduplication par cooldown. À réserver aux événements
	// de transition d'état discrets (entrée/sortie de mode), déjà débouncés en
	// amont — sinon une transition rapprochée d'une précédente serait avalée.
	Immediate bool
}

// Triggers émis (enum `trigger` de specs/schemas/alert.schema.json).
const (
	TriggerBlock            = "block"
	TriggerCircuitBreaker   = "circuit_breaker"
	TriggerHoneypot         = "honeypot"
	TriggerUnderAttackStart = "under_attack_start"
	TriggerUnderAttackEnd   = "under_attack_end"
)

// Alert est le payload d'alerte enrichi, envoyé tel quel au sink générique :
// son contrat est specs/schemas/alert.schema.json.
type Alert struct {
	ID         string `json:"id"`
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

// Observer reçoit l'issue de chaque livraison d'une alerte à un sink :
// waf_alerts_sent_total et waf_alerts_failed_total (FR-29).
type Observer interface {
	AlertSent(trigger string)
	AlertFailed(trigger string)
}

// Option configure un Notifier à sa construction, avant le démarrage des
// workers qui lisent ses champs.
type Option func(*Notifier)

// WithObserver branche l'observation des livraisons (métriques d'alertes).
func WithObserver(observer Observer) Option {
	return func(n *Notifier) { n.observer = observer }
}

type noopObserver struct{}

func (noopObserver) AlertSent(string)   {}
func (noopObserver) AlertFailed(string) {}

// Notifier dispatche les alertes de façon asynchrone vers les sinks.
//
// Chaque sink a sa propre file et son propre worker : avec un worker unique,
// un webhook hors service ((max_retries+1) timeouts de 5 s plus les backoffs
// par alerte) retardait la livraison aux autres sinks et remplissait la file,
// dont les alertes suivantes étaient jetées sans trace.
type Notifier struct {
	sinks      []*sinkQueue
	cooldown   time.Duration
	maxRetries int
	retryDelay time.Duration
	client     *http.Client
	observer   Observer

	// ctx est annulé par Close : il interrompt le backoff et la requête en cours.
	ctx     context.Context
	cancel  context.CancelFunc
	workers sync.WaitGroup

	// lastSent retient le dernier envoi par trigger+domaine le temps du
	// cooldown. C'était une map sans borne ni expiration : le domaine étant le
	// Host de la requête, des blocages sous des Host aléatoires y ajoutaient
	// une entrée chacun, pour toujours.
	lastSent *ttlcache.Cache[string, time.Time]
	now      func() time.Time
}

// sinkQueue est la file d'un sink, consommée par son seul worker.
type sinkQueue struct {
	sink  Sink
	queue chan Alert
	// failing : la dernière livraison a épuisé ses tentatives. Les suivantes
	// n'en font qu'une jusqu'au prochain succès, pour qu'un webhook hors
	// service coûte un timeout par alerte et non (max_retries+1) timeouts plus
	// les backoffs. Lu et écrit par le seul worker du sink.
	failing bool
}

// sinkQueueSize borne la file de chaque sink.
const sinkQueueSize = 256

// Backoff des retries (FR-29) : 1 s, 5 s puis 25 s, plafonné à 25 s au-delà
// de max_retries = 3.
const (
	defaultRetryDelay  = time.Second
	retryBackoffGrowth = 5
	maxRetryDelay      = 25 * time.Second
)

func NewNotifier(sinks []Sink, cooldown time.Duration, maxRetries int, client *http.Client, options ...Option) *Notifier {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	if maxRetries < 0 {
		maxRetries = 0
	}
	ctx, cancel := context.WithCancel(context.Background())
	n := &Notifier{
		cooldown:   cooldown,
		maxRetries: maxRetries,
		retryDelay: defaultRetryDelay,
		client:     client,
		observer:   noopObserver{},
		ctx:        ctx,
		cancel:     cancel,
		now:        time.Now,
	}
	for _, option := range options {
		option(n)
	}
	n.lastSent = ttlcache.New[string, time.Time](maxCooldownKeys, cooldown).WithClock(func() time.Time { return n.now() })
	for _, sink := range sinks {
		sq := &sinkQueue{sink: sink, queue: make(chan Alert, sinkQueueSize)}
		n.sinks = append(n.sinks, sq)
		n.workers.Add(1)
		go n.worker(sq)
	}
	return n
}

func (n *Notifier) worker(sq *sinkQueue) {
	defer n.workers.Done()
	for {
		select {
		case <-n.ctx.Done():
			return
		case alert := <-sq.queue:
			n.deliver(sq, alert)
		}
	}
}

// Notify construit et dispatche une alerte enrichie à partir d'un événement WAF.
func (n *Notifier) Notify(ev Event) {
	alert := n.alertFor(ev)
	if ev.Immediate {
		// Transition d'état : toujours livrée, sans passer par le cooldown.
		n.enqueue(alert)
		return
	}
	n.Dispatch(alert)
}

// alertFor dérive l'alerte enrichie (identifiant, sévérité, titre, message)
// d'un événement WAF.
func (n *Notifier) alertFor(ev Event) Alert {
	return Alert{
		ID:         newAlertID(),
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
	}
}

// newAlertID retourne un UUID v4 (RFC 9562) : l'identifiant requis par le
// schéma, qui permet au destinataire de dédoublonner une alerte relivrée par
// le retry.
func newAlertID() string {
	var raw [16]byte
	_, _ = rand.Read(raw[:]) // ne peut pas échouer (crypto/rand, Go 1.24+)
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16])
}

// Dispatch enfile une alerte si le cooldown (par trigger+domaine) est écoulé.
// Non bloquant.
func (n *Notifier) Dispatch(alert Alert) {
	if !n.allow(alert) {
		return
	}
	n.enqueue(alert)
}

// enqueue dépose l'alerte dans la file de chaque sink sans bloquer. Une file
// pleine jette l'alerte pour ce sink, comptée comme livraison échouée.
func (n *Notifier) enqueue(alert Alert) {
	for _, sq := range n.sinks {
		select {
		case sq.queue <- alert:
		default:
			n.observer.AlertFailed(alert.Trigger)
		}
	}
}

func (n *Notifier) allow(alert Alert) bool {
	key := alert.Trigger + "|" + alert.Domain
	allowed := false
	n.lastSent.Update(key, func(last time.Time, found bool) time.Time {
		now := n.now()
		if found && now.Sub(last) < n.cooldown {
			return last
		}
		allowed = true
		return now
	})
	return allowed
}

// Pending retourne le nombre de livraisons en attente, tous sinks confondus
// (waf_alerts_pending).
func (n *Notifier) Pending() int {
	pending := 0
	for _, sq := range n.sinks {
		pending += len(sq.queue)
	}
	return pending
}

// deliver livre l'alerte au sink ; la livraison compte comme envoyée ou
// échouée (tentatives épuisées). Une livraison interrompue par Close n'est pas
// comptée.
func (n *Notifier) deliver(sq *sinkQueue, alert Alert) {
	retries := n.maxRetries
	if sq.failing {
		retries = 0
	}
	delivered := n.sendWithRetry(sq.sink.URL, encode(sq.sink.Type, alert), retries)
	if n.ctx.Err() != nil {
		return
	}
	sq.failing = !delivered
	if delivered {
		n.observer.AlertSent(alert.Trigger)
	} else {
		n.observer.AlertFailed(alert.Trigger)
	}
}

func (n *Notifier) sendWithRetry(url string, payload []byte, retries int) bool {
	backoff := n.retryDelay
	for attempt := 0; ; attempt++ {
		if n.post(url, payload) {
			return true
		}
		if attempt >= retries || !n.wait(backoff) {
			return false
		}
		backoff = nextBackoff(backoff)
	}
}

func nextBackoff(delay time.Duration) time.Duration {
	return min(delay*retryBackoffGrowth, maxRetryDelay)
}

// wait attend d, ou retourne false si le Notifier est fermé entre-temps.
func (n *Notifier) wait(d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-n.ctx.Done():
		return false
	}
}

func (n *Notifier) post(url string, payload []byte) bool {
	request, err := http.NewRequestWithContext(n.ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return false
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := n.client.Do(request)
	if err != nil {
		return false
	}
	defer func() {
		httpbody.Drain(response.Body)
		_ = response.Body.Close()
	}()
	return response.StatusCode >= 200 && response.StatusCode < 300
}

// Close arrête les workers sans attendre la fin d'un backoff ni d'une requête
// en cours ; les alertes encore en file sont abandonnées.
func (n *Notifier) Close() {
	n.cancel()
	n.workers.Wait()
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
	case TriggerHoneypot:
		return "🍯 Honeypot déclenché"
	case TriggerCircuitBreaker:
		return "🔌 Circuit breaker ouvert"
	case TriggerUnderAttackStart:
		return "🚨 Mode sous attaque activé"
	case TriggerUnderAttackEnd:
		return "✅ Mode sous attaque levé"
	case TriggerBlock:
		return "⛔ Requête bloquée"
	default:
		return "🛡️ Alerte WAF"
	}
}

// messageFor produit une phrase de description lisible pour l'embed.
func messageFor(ev Event) string {
	switch ev.Trigger {
	case TriggerHoneypot:
		return "Accès à un chemin piège (honeypot) — IP marquée et bloquée."
	case TriggerCircuitBreaker:
		return "Trop de violations consécutives : circuit ouvert pour cette IP."
	case TriggerUnderAttackStart:
		return "Pression critique : challenge JS forcé pour les requêtes sans clearance (FR-39)."
	case TriggerUnderAttackEnd:
		return "Pression retombée : sortie du mode sous attaque, challenge forcé désactivé."
	case TriggerBlock:
		return "Requête bloquée par le pare-feu applicatif."
	default:
		return ""
	}
}

func severityFor(trigger string) string {
	switch trigger {
	case TriggerCircuitBreaker, TriggerHoneypot, TriggerUnderAttackStart:
		return "critical"
	case TriggerBlock:
		return "warning"
	default:
		return "info"
	}
}
