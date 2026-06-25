package tproxy

import (
	"net"

	"github.com/lucheng0127/marmot/pkg/log"
	"github.com/lucheng0127/marmot/pkg/rule"
)

type Decision uint8

const (
	DecisionDirect Decision = iota
	DecisionProxy
	DecisionBlock
)

type Decider interface {
	Decide(key FlowKey) Decision
}

type FlowKey struct {
	SrcIP    uint32
	DstIP    uint32
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
}

func IPToNetAddr(ip uint32) net.IP {
	return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

// RuleEngineDecider wraps the Phase 5 Rule Engine as a Decider.
type RuleEngineDecider struct {
	engine *rule.Engine
}

func NewRuleEngineDecider(engine *rule.Engine) *RuleEngineDecider {
	return &RuleEngineDecider{engine: engine}
}

func (d *RuleEngineDecider) Decide(key FlowKey) Decision {
	addr := rule.Addr{
		IP:       IPToNetAddr(key.DstIP),
		Port:     key.DstPort,
		Protocol: key.Protocol,
	}
	result := d.engine.Match(addr)
	log.Debug("Rule Engine decision", map[string]interface{}{
		"action":    result.Action.String(),
		"match":     string(result.MatchType),
		"rule_tag":  result.RuleTag,
		"outbound":  result.Outbound,
	})
	return ruleActionToDecision(result.Action)
}

func ruleActionToDecision(a rule.Action) Decision {
	switch a {
	case rule.ActionDirect:
		return DecisionDirect
	case rule.ActionBlock:
		return DecisionBlock
	default:
		return DecisionProxy
	}
}

type StaticDecider struct{}

func NewStaticDecider() *StaticDecider {
	return &StaticDecider{}
}

func (d *StaticDecider) Decide(key FlowKey) Decision {
	return DecisionProxy
}
