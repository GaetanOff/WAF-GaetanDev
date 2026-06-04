package storage

import "time"

type VisitorState struct {
	IPHash            string
	Domain            string
	Score             int
	FirstSeen         time.Time
	LastSeen          time.Time
	ExpiresAt         time.Time
	ReqCount          int64
	ViolationCount    int
	ChallengePassed   bool
	ChallengeAttempts int
	ChallengeFailures int
	FPHash            *string
	CircuitOpen       bool
	CircuitOpenUntil  *time.Time
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
	Close()
}
