package antiddos

import (
	"testing"
	"time"
)

func TestGlobalRateDetectorCountsRequestsInSlidingWindow(t *testing.T) {
	now := time.Now()
	detector := NewGlobalRateDetector(2, time.Second, PressureConfig{})
	detector.now = func() time.Time { return now }

	if _, pressure := detector.Record(); pressure != PressureNormal {
		t.Fatalf("first pressure = %s, want normal", pressure)
	}
	if _, pressure := detector.Record(); pressure != PressureElevated {
		t.Fatalf("second pressure = %s, want elevated", pressure)
	}
	if _, pressure := detector.Record(); pressure != PressureElevated {
		t.Fatalf("third pressure = %s, want elevated", pressure)
	}

	now = now.Add(time.Second + time.Millisecond)
	if pressure := detector.Pressure(); pressure != PressureNormal {
		t.Fatalf("pressure = %s, want normal after window expires", pressure)
	}
}

func TestGlobalRateDetectorUsesDefaultsForInvalidConfig(t *testing.T) {
	detector := NewGlobalRateDetector(0, 0, PressureConfig{})
	if detector.threshold != DefaultGlobalRequestsPerSecond {
		t.Fatalf("threshold = %d, want %d", detector.threshold, DefaultGlobalRequestsPerSecond)
	}
	if detector.window != DefaultGlobalWindow {
		t.Fatalf("window = %s, want %s", detector.window, DefaultGlobalWindow)
	}
}

func TestGlobalRateDetectorClassifiesPressureLevels(t *testing.T) {
	now := time.Now()
	detector := NewGlobalRateDetector(10, time.Second, PressureConfig{
		ElevatedMultiplier: 1,
		HighMultiplier:     2,
		CriticalMultiplier: 4,
	})
	detector.now = func() time.Time { return now }

	for range 10 {
		detector.Record()
	}
	if pressure := detector.Pressure(); pressure != PressureElevated {
		t.Fatalf("pressure = %s, want elevated", pressure)
	}
	for range 10 {
		detector.Record()
	}
	if pressure := detector.Pressure(); pressure != PressureHigh {
		t.Fatalf("pressure = %s, want high", pressure)
	}
	for range 20 {
		detector.Record()
	}
	if pressure := detector.Pressure(); pressure != PressureCritical {
		t.Fatalf("pressure = %s, want critical", pressure)
	}
}
