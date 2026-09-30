package cluster

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/gaetandev/waf/internal/signing"
)

// eventKeyPurpose dérive de challenge.secret_key la clé de signature des
// événements (FR-20) : distincte des clés du token, du cookie et des ip_hash.
const eventKeyPurpose = "waf/cluster-event/v1"

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
)

// knownEventTypes sont les seuls types appliqués. Un type inconnu, même
// signé, est refusé : il deviendrait sinon une série du label type de
// waf_cluster_sync_events_total.
var knownEventTypes = map[string]bool{
	EventBlacklistAdd:  true,
	EventScoreCritical: true,
	EventCircuitOpen:   true,
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
// non signé, mal signé, malformé ou de type inconnu est refusé.
func open(key []byte, message string) (Event, error) {
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
	return event, nil
}
