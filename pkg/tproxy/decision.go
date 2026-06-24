package tproxy

// Decision represents the result of traffic classification.
// Phase 2 only supports Direct and Proxy — no rule engine yet.
type Decision uint8

const (
	// DecisionDirect — forward traffic directly without proxying.
	// Used when destination matches CIDR whitelist or explicit bypass rules.
	DecisionDirect Decision = iota

	// DecisionProxy — route traffic through the proxy engine.
	// The TProxy socket will receive and forward this traffic.
	DecisionProxy
)

// Decider is the interface for making traffic decisions.
// Phase 2 uses a simple static decider; Phase 5 will replace
// this with the full Rule Engine (GeoIP/GeoSite/Domain rules).
type Decider interface {
	// Decide returns a Decision for the given 5-tuple flow.
	// In Phase 2, this is a simplified stub.
	// In Phase 5, this will consult the full Rule Engine.
	Decide(key FlowKey) Decision
}

// FlowKey is the 5-tuple identifying a network flow.
// Mirrors the BPF-side flow_key struct in bpf/tc_ingress.c.
type FlowKey struct {
	SrcIP    uint32 // network byte order
	DstIP    uint32 // network byte order
	SrcPort  uint16 // network byte order
	DstPort  uint16 // network byte order
	Protocol uint8  // 6=TCP, 17=UDP
}

// StaticDecider returns DecisionProxy for all traffic.
// In Phase 2, this is a placeholder — all traffic that reaches
// TProxy is assumed to need proxying.
// Phase 5 will replace this with a Rule Engine that considers
// CIDR whitelist, GeoIP, GeoSite, and custom rules.
type StaticDecider struct{}

func NewStaticDecider() *StaticDecider {
	return &StaticDecider{}
}

func (d *StaticDecider) Decide(key FlowKey) Decision {
	return DecisionProxy
}
