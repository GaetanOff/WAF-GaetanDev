package risk

import "sync"

const (
	defaultFeedbackStep    = 0.10
	defaultMinWeightFactor = 0.50
	defaultInitialWeight   = 1.00
)

type FeedbackManager struct {
	mu        sync.Mutex
	step      float64
	minFactor float64
	weights   map[string]map[SignalFamily]float64
}

func NewFeedbackManager() *FeedbackManager {
	return &FeedbackManager{
		step:      defaultFeedbackStep,
		minFactor: defaultMinWeightFactor,
		weights:   make(map[string]map[SignalFamily]float64),
	}
}

func (m *FeedbackManager) RecordChallengePassAfterFlag(visitorKey string, families []SignalFamily) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.weights[visitorKey]; !ok {
		m.weights[visitorKey] = make(map[SignalFamily]float64)
	}
	for _, family := range families {
		if family == FamilyHumanCredit {
			continue
		}
		current := m.weights[visitorKey][family]
		if current == 0 {
			current = defaultInitialWeight
		}
		current -= m.step
		if current < m.minFactor {
			current = m.minFactor
		}
		m.weights[visitorKey][family] = current
	}
}

func (m *FeedbackManager) WeightFactor(visitorKey string, family SignalFamily) float64 {
	m.mu.Lock()
	defer m.mu.Unlock()

	if byFamily, ok := m.weights[visitorKey]; ok {
		if factor := byFamily[family]; factor > 0 {
			return factor
		}
	}
	return defaultInitialWeight
}

func (m *FeedbackManager) Apply(visitorKey string, cfg FusionConfig) FusionConfig {
	adjusted := cfg
	adjusted.Weights = make(map[SignalFamily]float64, len(cfg.Weights))
	for family, weight := range cfg.Weights {
		adjusted.Weights[family] = weight * m.WeightFactor(visitorKey, family)
	}
	return adjusted
}
