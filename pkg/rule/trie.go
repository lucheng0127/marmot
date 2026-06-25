package rule

import "strings"

// Trie node for reversed domain suffix matching.
type Trie struct {
	children map[byte]*Trie
	rule     *Rule
}

func NewTrie() *Trie { return &Trie{children: make(map[byte]*Trie)} }

func (t *Trie) Insert(domain string, rule *Rule) {
	node := t
	for i := len(domain) - 1; i >= 0; i-- {
		c := domain[i]
		if node.children[c] == nil {
			node.children[c] = NewTrie()
		}
		node = node.children[c]
	}
	node.rule = rule
}

func (t *Trie) Match(domain string) (*Rule, MatchType) {
	node := t
	if node.rule != nil {
		return node.rule, MatchDomainSuffix
	}
	for i := len(domain) - 1; i >= 0; i-- {
		c := domain[i]
		if node.children[c] == nil {
			return nil, ""
		}
		node = node.children[c]
		if node.rule != nil {
			// Check if remaining prefix is a dot boundary
			if i == 0 || domain[i-1] == '.' {
				return node.rule, MatchDomainSuffix
			}
		}
	}
	return nil, ""
}

func init() { _ = strings.Compare }
