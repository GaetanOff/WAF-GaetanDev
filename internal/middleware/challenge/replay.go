package challenge

import (
	"strings"
	"sync"
)

const (
	// maxUsedTokens borne la mémoire du garde anti-rejeu (~6 Mo). Une entrée
	// n'existe qu'après une soumission réussie (token signé + PoW + fingerprint)
	// et vit le temps du token : avec token_ttl à 30s, la borne correspond à
	// ~2 000 vérifications réussies par seconde.
	maxUsedTokens = 1 << 16
	// usedTokensSweepSeconds espace les purges des tokens expirés.
	usedTokensSweepSeconds = 10
)

// usedTokens retient les tokens de challenge déjà acceptés par /waf/verify
// jusqu'à leur expiration (FR-30). Le token est un HMAC sans état : sans cette
// mémoire, une seule PoW résolue se rejouait jusqu'à expiration, chaque
// soumission appliquant de nouveau le bonus de score.
//
// La mémoire est locale à l'instance. Saturée (après purge), elle laisse passer
// sans retenir : refuser bloquerait les visiteurs légitimes au pire moment, et
// le rejeu reste lié à l'IP et au domaine signés dans le token.
type usedTokens struct {
	mu        sync.Mutex
	expiresAt map[string]int64 // signature du token -> expiration (Unix)
	capacity  int
	lastSweep int64
}

func newUsedTokens(capacity int) *usedTokens {
	return &usedTokens{expiresAt: make(map[string]int64), capacity: capacity}
}

// consume marque le token comme utilisé et indique s'il l'était déjà. La
// vérification et l'écriture sont atomiques : deux soumissions concurrentes du
// même token ne passent pas toutes les deux.
func (u *usedTokens) consume(token string, expiresAt int64, now int64) (alreadyUsed bool) {
	signature := token[strings.LastIndexByte(token, '.')+1:]
	u.mu.Lock()
	defer u.mu.Unlock()
	if expiry, seen := u.expiresAt[signature]; seen && expiry > now {
		return true
	}
	// Saturée, la mémoire n'est repurgée qu'une fois par seconde : une purge
	// par soumission coûterait un parcours complet sous le verrou.
	full := len(u.expiresAt) >= u.capacity
	if now-u.lastSweep >= usedTokensSweepSeconds || (full && now > u.lastSweep) {
		u.sweep(now)
	}
	if len(u.expiresAt) < u.capacity {
		// Copie : la sous-chaîne retiendrait le token entier (URL de redirection
		// comprise) aussi longtemps que l'entrée.
		u.expiresAt[strings.Clone(signature)] = expiresAt
	}
	return false
}

func (u *usedTokens) sweep(now int64) {
	u.lastSweep = now
	for signature, expiry := range u.expiresAt {
		if expiry <= now {
			delete(u.expiresAt, signature)
		}
	}
}
