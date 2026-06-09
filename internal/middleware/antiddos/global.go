package antiddos

import (
	"sync"
	"time"
)

type PressureLevel string

const (
	PressureNormal   PressureLevel = "normal"
	PressureElevated PressureLevel = "elevated"
	PressureHigh     PressureLevel = "high"
	PressureCritical PressureLevel = "critical"
)

type PressureConfig struct {
	ElevatedMultiplier float64
	HighMultiplier     float64
	CriticalMultiplier float64
}

type GlobalRateDetector struct {
	mu        sync.Mutex
	threshold int
	window    time.Duration
	pressure  PressureConfig
	buckets   []rateBucket
	now       func() time.Time
}

type rateBucket struct {
	windowStart time.Time
	count       int
}

func NewGlobalRateDetector(threshold int, window time.Duration, pressure PressureConfig) *GlobalRateDetector {
	if threshold < 1 {
		threshold = DefaultGlobalRequestsPerSecond
	}
	if window <= 0 {
		window = DefaultGlobalWindow
	}
	pressure = normalizePressureConfig(pressure)
	return &GlobalRateDetector{
		threshold: threshold,
		window:    window,
		pressure:  pressure,
		buckets:   make([]rateBucket, bucketCount(window)),
		now:       time.Now,
	}
}

func (d *GlobalRateDetector) Record() (int, PressureLevel) {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := d.now()
	slot := d.slot(now)
	windowStart := d.bucketStart(now)
	if !d.buckets[slot].windowStart.Equal(windowStart) {
		d.buckets[slot] = rateBucket{windowStart: windowStart}
	}
	d.buckets[slot].count++
	total := d.totalLocked(now)
	return total, d.pressureFor(total)
}

func (d *GlobalRateDetector) Pressure() PressureLevel {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.pressureFor(d.totalLocked(d.now()))
}

func (d *GlobalRateDetector) RecordAndPressure() PressureLevel {
	_, pressure := d.Record()
	return pressure
}

func (d *GlobalRateDetector) totalLocked(now time.Time) int {
	cutoff := now.Add(-d.window)
	total := 0
	for _, bucket := range d.buckets {
		if bucket.windowStart.IsZero() || bucket.windowStart.Before(cutoff) {
			continue
		}
		total += bucket.count
	}
	return total
}

func (d *GlobalRateDetector) pressureFor(total int) PressureLevel {
	rate := float64(total) / d.window.Seconds()
	threshold := float64(d.threshold)
	switch {
	case rate >= threshold*d.pressure.CriticalMultiplier:
		return PressureCritical
	case rate >= threshold*d.pressure.HighMultiplier:
		return PressureHigh
	case rate >= threshold*d.pressure.ElevatedMultiplier:
		return PressureElevated
	default:
		return PressureNormal
	}
}

func (d *GlobalRateDetector) slot(now time.Time) int {
	return int(now.UnixMilli()/bucketWidth.Milliseconds()) % len(d.buckets)
}

func (d *GlobalRateDetector) bucketStart(now time.Time) time.Time {
	unixMilli := now.UnixMilli()
	start := unixMilli - unixMilli%bucketWidth.Milliseconds()
	return time.UnixMilli(start)
}

const bucketWidth = 100 * time.Millisecond

func bucketCount(window time.Duration) int {
	count := int(window / bucketWidth)
	if window%bucketWidth != 0 {
		count++
	}
	if count < 1 {
		return 1
	}
	return count + 1
}

func normalizePressureConfig(cfg PressureConfig) PressureConfig {
	if cfg.ElevatedMultiplier < 1 {
		cfg.ElevatedMultiplier = 1
	}
	if cfg.HighMultiplier < cfg.ElevatedMultiplier {
		cfg.HighMultiplier = cfg.ElevatedMultiplier * 2
	}
	if cfg.CriticalMultiplier < cfg.HighMultiplier {
		cfg.CriticalMultiplier = cfg.HighMultiplier * 2
	}
	return cfg
}
