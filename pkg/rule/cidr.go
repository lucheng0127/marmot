package rule

import (
	"net"
)

// CIDRSet stores IP CIDR rules for fast matching.
type CIDRSet struct {
	rules []cidrEntry
}

type cidrEntry struct {
	net  *net.IPNet
	rule *Rule
}

func NewCIDRSet() *CIDRSet { return &CIDRSet{} }

func (cs *CIDRSet) Add(cidr string, rule *Rule) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return
	}
	cs.rules = append(cs.rules, cidrEntry{net: ipNet, rule: rule})
}

func (cs *CIDRSet) Match(ip net.IP) *Rule {
	for _, entry := range cs.rules {
		if entry.net.Contains(ip) {
			return entry.rule
		}
	}
	return nil
}
