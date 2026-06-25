package rule

import (
	"fmt"
	"net"
	"strings"

	"github.com/lucheng0127/marmot/pkg/geo"
	"github.com/lucheng0127/marmot/pkg/log"
)

// Action defines what to do with matching traffic.
type Action uint8

const (
	ActionProxy  Action = iota // send to proxy
	ActionDirect               // bypass proxy
	ActionBlock                // drop
)

func (a Action) String() string {
	switch a {
	case ActionProxy:
		return "proxy"
	case ActionDirect:
		return "direct"
	case ActionBlock:
		return "block"
	default:
		return "unknown"
	}
}

// MatchType indicates what kind of rule matched.
type MatchType string

const (
	MatchDomainExact  MatchType = "domain_exact"
	MatchDomainSuffix MatchType = "domain_suffix"
	MatchDomainKw     MatchType = "domain_keyword"
	MatchGeoSite      MatchType = "geosite"
	MatchGeoIP        MatchType = "geoip"
	MatchCIDR         MatchType = "cidr"
	MatchDefault      MatchType = "default"
)

// MatchResult contains the full result of a rule match.
type MatchResult struct {
	Action    Action    `json:"action"`
	MatchType MatchType `json:"match_type"`
	RuleTag   string    `json:"rule_tag,omitempty"`
	Outbound  string    `json:"outbound,omitempty"`
	Trace     []MatchStep `json:"trace,omitempty"`
}

// MatchStep captures each matching step for debugging.
type MatchStep struct {
	Matcher string `json:"matcher"`
	Input   string `json:"input"`
	Result  string `json:"result"`
}

// RuleConfig describes a single rule loaded from YAML.
type RuleConfig struct {
	Tag      string   `yaml:"tag"`
	Action   string   `yaml:"action"` // proxy, direct, block
	Outbound string   `yaml:"outbound,omitempty"`
	Domain   []string `yaml:"domain,omitempty"`
	DomSfx   []string `yaml:"domain_suffix,omitempty"`
	DomKw    []string `yaml:"domain_keyword,omitempty"`
	GeoSite  []string `yaml:"geosite,omitempty"`
	GeoIP    []string `yaml:"geoip,omitempty"`
	IPCIDR   []string `yaml:"ip_cidr,omitempty"`
}

// Engine is the rule matching engine with priority-based evaluation.
type Engine struct {
	geoReader *geo.Reader
	matchers  []Matcher
	// Sub-matchers
	exactMap   map[string]*Rule    // domain exact match
	suffixTrie *Trie               // domain suffix match
	keywordAC  *AhoCorasick        // domain keyword match
	cidrSet    *CIDRSet            // IP CIDR match
	geoIPRules []GeoRule           // GeoIP rules
	geoSite    map[string][]string // site -> domains (from data)
}

// Rule represents a single rule with its action and outbound tag.
type Rule struct {
	Tag      string
	Action   Action
	Outbound string
}

// Matcher is the interface for a single matching strategy.
type Matcher interface {
	Name() string
	Match(addr Addr) (*Rule, MatchType)
}

// Addr contains all address information for matching.
type Addr struct {
	Domain   string
	IP       net.IP
	Port     uint16
	Protocol uint8
}

func NewEngine(geoReader *geo.Reader) *Engine {
	return &Engine{
		geoReader:  geoReader,
		exactMap:   make(map[string]*Rule),
		suffixTrie: NewTrie(),
		keywordAC:  NewAhoCorasick(),
		cidrSet:    NewCIDRSet(),
		geoIPRules: nil,
		geoSite:    make(map[string][]string),
	}
}

// LoadRules processes a list of RuleConfig into the engine.
func (e *Engine) LoadRules(configs []RuleConfig) error {
	for i, rc := range configs {
		action, err := parseAction(rc.Action)
		if err != nil {
			return fmt.Errorf("rule #%d (%s): %w", i, rc.Tag, err)
		}
		rule := &Rule{Tag: rc.Tag, Action: action, Outbound: rc.Outbound}

		for _, d := range rc.Domain {
			e.exactMap[strings.ToLower(d)] = rule
		}
		for _, d := range rc.DomSfx {
			e.suffixTrie.Insert(strings.ToLower(d), rule)
		}
		for _, d := range rc.DomKw {
			e.keywordAC.Insert(strings.ToLower(d), rule)
		}
		for _, c := range rc.IPCIDR {
			e.cidrSet.Add(c, rule)
		}
		for _, g := range rc.GeoIP {
			e.geoIPRules = append(e.geoIPRules, GeoRule{Country: g, Rule: rule})
		}
		for _, s := range rc.GeoSite {
			e.geoSite[s] = []string{}
		}
	}
	return nil
}

// Match evaluates rules against an address in priority order.
// Returns the first matching result, or default (proxy).
func (e *Engine) Match(addr Addr) MatchResult {
	var trace []MatchStep

	addTrace := func(matcher, input, result string) {
		trace = append(trace, MatchStep{Matcher: matcher, Input: input, Result: result})
	}

	// 1. Domain exact match
	if addr.Domain != "" {
		d := strings.ToLower(addr.Domain)
		if rule, ok := e.exactMap[d]; ok {
			addTrace("domain_exact", d, rule.Action.String())
			return MatchResult{Action: rule.Action, MatchType: MatchDomainExact, RuleTag: rule.Tag, Outbound: rule.Outbound, Trace: trace}
		}

		// 2. Domain suffix match
		if rule, mtype := e.suffixTrie.Match(d); rule != nil {
			addTrace("domain_suffix", d, rule.Action.String())
			return MatchResult{Action: rule.Action, MatchType: mtype, RuleTag: rule.Tag, Outbound: rule.Outbound, Trace: trace}
		}

		// 3. Domain keyword match
		if rule := e.keywordAC.Match(d); rule != nil {
			addTrace("domain_keyword", d, rule.Action.String())
			return MatchResult{Action: rule.Action, MatchType: MatchDomainKw, RuleTag: rule.Tag, Outbound: rule.Outbound, Trace: trace}
		}
	}

	// 4. IP CIDR match
	if addr.IP != nil {
		if rule := e.cidrSet.Match(addr.IP); rule != nil {
			addTrace("cidr", addr.IP.String(), rule.Action.String())
			return MatchResult{Action: rule.Action, MatchType: MatchCIDR, RuleTag: rule.Tag, Outbound: rule.Outbound, Trace: trace}
		}
	}

	// 5. GeoIP match
	if addr.IP != nil && e.geoReader != nil {
		if country, err := e.geoReader.LookupGeoIP(addr.IP); err == nil {
			for _, gr := range e.geoIPRules {
				if gr.Country == country {
					addTrace("geoip", country, gr.Rule.Action.String())
					return MatchResult{Action: gr.Rule.Action, MatchType: MatchGeoIP, RuleTag: gr.Rule.Tag, Outbound: gr.Rule.Outbound, Trace: trace}
				}
			}
		}
	}

	// 6. Default: proxy all
	addTrace("default", "", "proxy")
	return MatchResult{Action: ActionProxy, MatchType: MatchDefault, Trace: trace}
}

// MatchDebug returns a full trace of all matching steps.
func (e *Engine) MatchDebug(addr Addr) MatchResult {
	return e.Match(addr)
}

func parseAction(s string) (Action, error) {
	switch s {
	case "proxy":
		return ActionProxy, nil
	case "direct":
		return ActionDirect, nil
	case "block":
		return ActionBlock, nil
	default:
		return 0, fmt.Errorf("unknown action: %s", s)
	}
}

// GeoRule links a GeoIP country code to a rule.
type GeoRule struct {
	Country string
	Rule    *Rule
}

func init() {
	log.Debug("rule engine initialized")
}

var _ = fmt.Sprintf
