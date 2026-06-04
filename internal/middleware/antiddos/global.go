package antiddos

import (
	"sync"
	"time"
)

type GlobalRateDetector struct {
	mu        sync.Mutex
	threshold int
	window    time.Duration
	events    []time.Time
	now       func() time.Time
}

func NewGlobalRateDetector(threshold int, window time.Duration) *GlobalRateDetector {
	if threshold < 1 {
		threshold = DefaultGlobalRequestsPerSecond
	}
	if window <= 0 {
		window = DefaultGlobalWindow
	}
	return &GlobalRateDetector{
		threshold: threshold,
		window:    window,
		now:       time.Now,
	}
}

func (d *GlobalRateDetector) Record() int {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := d.now()
	d.events = append(d.events, now)
	d.pruneLocked(now)
	return len(d.events)
}

func (d *GlobalRateDetector) IsExceeded() bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.pruneLocked(d.now())
	return len(d.events) > d.threshold
}

func (d *GlobalRateDetector) RecordAndIsExceeded() bool {
	return d.Record() > d.threshold
}

func (d *GlobalRateDetector) pruneLocked(now time.Time) {
	cutoff := now.Add(-d.window)
	firstActive := 0
	for firstActive < len(d.events) && !d.events[firstActive].After(cutoff) {
		firstActive++
	}
	if firstActive == 0 {
		return
	}
	copy(d.events, d.events[firstActive:])
	d.events = d.events[:len(d.events)-firstActive]
}
