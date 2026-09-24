package storage

import "time"

type VisitorState struct {
	IPHash               string
	Domain               string
	Score                int
	FirstSeen            time.Time
	LastSeen             time.Time
	ExpiresAt            time.Time
	ReqCount             int64
	ViolationCount       int
	LastViolation        *time.Time
	LastRateLimitPenalty *time.Time
	ChallengePassed      bool
	ChallengeAttempts    int
	ChallengeFailures    int
	FPHash               *string
	StickyTrustUntil     *time.Time
	CircuitOpen          bool
	CircuitOpenUntil     *time.Time
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
