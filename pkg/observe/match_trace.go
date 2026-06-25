package observe

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/lucheng0127/marmot/pkg/rule"
)

// MatchTrace records a single match event for debugging.
type MatchTrace struct {
	Time      time.Time         `json:"time"`
	Domain    string            `json:"domain,omitempty"`
	IP        string            `json:"ip,omitempty"`
	Result    rule.MatchResult  `json:"result"`
	Duration  time.Duration     `json:"duration_ns"`
}

// TraceStore holds recent match traces in a ring buffer.
type TraceStore struct {
	mu     sync.Mutex
	traces []MatchTrace
	cap    int
	pos    int
	count  int
}

func NewTraceStore(capacity int) *TraceStore {
	if capacity <= 0 {
		capacity = 128
	}
	return &TraceStore{traces: make([]MatchTrace, capacity), cap: capacity}
}

// Record adds a match trace to the store.
func (ts *TraceStore) Record(trace MatchTrace) {
	ts.mu.Lock()
	ts.traces[ts.pos] = trace
	ts.pos = (ts.pos + 1) % ts.cap
	if ts.count < ts.cap {
		ts.count++
	}
	ts.mu.Unlock()
}

// Recent returns the most recent traces in order (newest first).
func (ts *TraceStore) Recent(n int) []MatchTrace {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if n <= 0 || n > ts.count {
		n = ts.count
	}
	result := make([]MatchTrace, 0, n)
	for i := 0; i < n; i++ {
		idx := (ts.pos - 1 - i + ts.cap) % ts.cap
		if idx < 0 || idx >= ts.cap {
			break
		}
		if ts.traces[idx].Time.IsZero() {
			continue
		}
		result = append(result, ts.traces[idx])
		if len(result) >= n {
			break
		}
	}
	return result
}

// JSON returns recent traces as JSON.
func (ts *TraceStore) JSON(n int) string {
	data, _ := json.Marshal(ts.Recent(n))
	return string(data)
}

// Stats counts match results by type and action.
type Stats struct {
	mu       sync.Mutex
	byType   map[rule.MatchType]int
	byAction map[rule.Action]int
	total    int
}

func NewStats() *Stats {
	return &Stats{
		byType:   make(map[rule.MatchType]int),
		byAction: make(map[rule.Action]int),
	}
}

func (s *Stats) Record(result rule.MatchResult) {
	s.mu.Lock()
	s.byType[result.MatchType]++
	s.byAction[result.Action]++
	s.total++
	s.mu.Unlock()
}

func (s *Stats) Snapshot() (byType map[rule.MatchType]int, byAction map[rule.Action]int, total int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	byType = make(map[rule.MatchType]int)
	byAction = make(map[rule.Action]int)
	for k, v := range s.byType {
		byType[k] = v
	}
	for k, v := range s.byAction {
		byAction[k] = v
	}
	return byType, byAction, s.total
}
