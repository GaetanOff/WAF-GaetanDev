package antiddos

import (
	"testing"
	"time"
)

func TestGlobalRateDetectorCountsRequestsInSlidingWindow(t *testing.T) {
	now := time.Now()
	detector := NewGlobalRateDetector(2, time.Second)
	detector.now = func() time.Time { return now }

	if detector.RecordAndIsExceeded() {
		t.Fatal("first request should not exceed threshold")
	}
	if detector.RecordAndIsExceeded() {
		t.Fatal("second request should not exceed threshold")
	}
	if !detector.RecordAndIsExceeded() {
		t.Fatal("third request should exceed threshold")
	}

	now = now.Add(time.Second + time.Millisecond)
	if detector.IsExceeded() {
		t.Fatal("detector should recover after the sliding window expires")
	}
}

func TestGlobalRateDetectorUsesDefaultsForInvalidConfig(t *testing.T) {
	detector := NewGlobalRateDetector(0, 0)
	if detector.threshold != DefaultGlobalRequestsPerSecond {
		t.Fatalf("threshold = %d, want %d", detector.threshold, DefaultGlobalRequestsPerSecond)
	}
	if detector.window != DefaultGlobalWindow {
		t.Fatalf("window = %s, want %s", detector.window, DefaultGlobalWindow)
	}
}
