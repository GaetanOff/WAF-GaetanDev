package storage

import "time"

// VisitorState est l'état persisté d'un visiteur. Sa forme JSON — celle que le
// backend Redis écrit — est le contrat specs/schemas/visitor.schema.json :
// clés snake_case, pointeurs nuls sérialisés en null.
type VisitorState struct {
	IPHash               string     `json:"ip_hash"`
	Domain               string     `json:"domain"`
	Score                int        `json:"score"`
	FirstSeen            time.Time  `json:"first_seen"`
	LastSeen             time.Time  `json:"last_seen"`
	ExpiresAt            time.Time  `json:"expires_at"`
	ReqCount             int64      `json:"req_count"`
	ViolationCount       int        `json:"violation_count"`
	LastViolation        *time.Time `json:"last_violation"`
	LastRateLimitPenalty *time.Time `json:"last_rate_limit_penalty"`
	ChallengePassed      bool       `json:"challenge_passed"`
	ChallengeAttempts    int        `json:"challenge_attempts"`
	ChallengeFailures    int        `json:"challenge_failures"`
	FPHash               *string    `json:"fp_hash"`
	StickyTrustUntil     *time.Time `json:"sticky_trust_until"`
	CircuitOpen          bool       `json:"circuit_open"`
	CircuitOpenUntil     *time.Time `json:"circuit_open_until"`
}

type RateBucket struct {
	IPHash     string
	Tokens     float64
	LastRefill time.Time
	Rate       float64
	Capacity   float64
	ExpiresAt  time.Time
}

type Store interface {
	GetVisitor(key string) (*VisitorState, bool)
	SetVisitor(key string, visitor VisitorState)
	DeleteVisitor(key string)
	ListVisitors() []VisitorState
	GetBucket(key string) (*RateBucket, bool)
	SetBucket(key string, bucket RateBucket)
	// UpdateBuckets lit les buckets de keys (nil si absent ou expiré), laisse
	// update calculer leur nouvel état — même ordre, même longueur — et
	// l'écrit, atomiquement vis-à-vis de toute autre mise à jour de ces clés,
	// y compris depuis une autre instance pour un backend partagé. update peut
	// être rappelée (conflit) : elle ne doit dépendre que de current.
	UpdateBuckets(keys []string, update func(current []*RateBucket) []RateBucket)
	Close()
}
