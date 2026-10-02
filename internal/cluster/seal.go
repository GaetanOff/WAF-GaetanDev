package cluster

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/gaetandev/waf/internal/signing"
)

// eventKeyPurpose dérive de challenge.secret_key la clé de signature des
// événements (FR-20) : distincte des clés du token, du cookie et des ip_hash.
const eventKeyPurpose = "waf/cluster-event/v1"

// maxEventSkew borne l'écart entre l'émission d'un événement (ts) et
// l'horloge du récepteur : au-delà, l'événement est un rejeu ou vient d'un
// nœud désynchronisé (FR-20).
const maxEventSkew = 2 * time.Minute

// EventKey retourne la clé de signature des événements, dérivée du secret
// partagé par tous les nœuds.
func EventKey(secret string) []byte {
	return signing.Derive([]byte(secret), eventKeyPurpose)
}

var (
	errUnsigned      = errors.New("cluster event is not signed")
	errBadSignature  = errors.New("cluster event signature is invalid")
	errUnknownEvent  = errors.New("cluster event type is unknown")
	errMissingSecret = errors.New("cluster event key is empty")
	errStaleEvent    = errors.New("cluster event timestamp is missing or outside the accepted window")
)

// knownEventTypes sont les seuls types appliqués. Un type inconnu, même
// signé, est refusé : il deviendrait sinon une série du label type de
// waf_cluster_sync_events_total.
var knownEventTypes = map[string]bool{
	EventBlacklistAdd:    true,
	EventBlacklistRemove: true,
	EventScoreCritical:   true,
	EventCircuitOpen:     true,
}

// seal encode l'événement en "<signature>.<JSON>". La signature porte sur les
// octets JSON transmis, pas sur un ré-encodage : le récepteur vérifie
// exactement ce qu'il décode.
func seal(key []byte, event Event) ([]byte, error) {
	if len(key) == 0 {
		return nil, errMissingSecret
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}
	return []byte(signing.Sign(key, string(payload)) + "." + string(payload)), nil
}

// open vérifie la signature d'un message du canal puis le décode. Un message
// non signé, mal signé, malformé, de type inconnu, ou dont le ts s'écarte de
// plus de maxEventSkew de now, est refusé : signé mais rejoué, un message
// capturé s'appliquait indéfiniment.
func open(key []byte, message string, now time.Time) (Event, error) {
	if len(key) == 0 {
		return Event{}, errMissingSecret
	}
	signature, payload, found := strings.Cut(message, ".")
	if !found || signature == "" {
		return Event{}, errUnsigned
	}
	if !signing.Verify(key, payload, signature) {
		return Event{}, errBadSignature
	}
	var event Event
	if err := json.Unmarshal([]byte(payload), &event); err != nil {
		return Event{}, err
	}
	if !knownEventTypes[event.Type] {
		return Event{}, errUnknownEvent
	}
	if event.TS.IsZero() || now.Sub(event.TS).Abs() > maxEventSkew {
		return Event{}, errStaleEvent
	}
	return event, nil
}
