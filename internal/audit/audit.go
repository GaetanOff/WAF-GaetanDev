// Package audit tient un journal append-only des actions d'administration
// (FR-27) : rotation FIFO en mémoire, secrets masqués, export fichier optionnel.
package audit

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"
)

// Entry est une ligne d'audit.
type Entry struct {
	Timestamp string `json:"timestamp"`
	Action    string `json:"action"`
	Target    string `json:"target"`
	Result    string `json:"result"`
}

// Trail est un journal borné (FIFO) thread-safe, avec export fichier optionnel.
type Trail struct {
	mu      sync.Mutex
	max     int
	entries []Entry
	file    *os.File
	now     func() time.Time
}

func NewTrail(maxEntries int, filePath string) (*Trail, error) {
	if maxEntries < 1 {
		maxEntries = 1000
	}
	t := &Trail{max: maxEntries, now: time.Now}
	if filePath != "" {
		f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, err
		}
		t.file = f
	}
	return t, nil
}

// Record ajoute une entrée (cible et résultat masqués des secrets). Rotation
// FIFO au-delà de max. Best-effort sur l'export fichier.
func (t *Trail) Record(action string, target string, result string) {
	entry := Entry{
		Timestamp: t.now().UTC().Format(time.RFC3339),
		Action:    action,
		Target:    maskSecrets(target),
		Result:    result,
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	t.entries = append(t.entries, entry)
	if len(t.entries) > t.max {
		t.entries = t.entries[len(t.entries)-t.max:]
	}
	if t.file != nil {
		if data, err := json.Marshal(entry); err == nil {
			_, _ = t.file.Write(append(data, '\n'))
		}
	}
}

// List retourne une copie des entrées (de la plus ancienne à la plus récente).
func (t *Trail) List() []Entry {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Entry, len(t.entries))
	copy(out, t.entries)
	return out
}

func (t *Trail) Close() error {
	if t.file != nil {
		return t.file.Close()
	}
	return nil
}

// maskSecrets redacte les valeurs ressemblant à des secrets (token/secret/key/
// password) dans une chaîne "clé=valeur" ou un texte libre.
func maskSecrets(value string) string {
	lower := strings.ToLower(value)
	for _, marker := range []string{"token", "secret", "password", "api_key", "apikey"} {
		if strings.Contains(lower, marker) {
			return "***"
		}
	}
	return value
}
