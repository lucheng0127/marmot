package rule

import "strings"

// AhoCorasick implements multi-pattern string matching for domain keywords.
type AhoCorasick struct {
	root *acNode
}

type acNode struct {
	children map[byte]*acNode
	fail     *acNode
	rule     *Rule
}

func NewAhoCorasick() *AhoCorasick {
	return &AhoCorasick{root: &acNode{children: make(map[byte]*acNode)}}
}

func (ac *AhoCorasick) Insert(pattern string, rule *Rule) {
	node := ac.root
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		if node.children[c] == nil {
			node.children[c] = &acNode{children: make(map[byte]*acNode)}
		}
		node = node.children[c]
	}
	node.rule = rule
}

// buildFail builds the failure links. Called before first Match.
func (ac *AhoCorasick) buildFail() {
	queue := []*acNode{}
	for _, child := range ac.root.children {
		child.fail = ac.root
		queue = append(queue, child)
	}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		for c, child := range node.children {
			fail := node.fail
			for fail != nil && fail.children[c] == nil {
				fail = fail.fail
			}
			if fail == nil {
				child.fail = ac.root
			} else {
				child.fail = fail.children[c]
			}
			if child.rule == nil {
				child.rule = child.fail.rule
			}
			queue = append(queue, child)
		}
	}
}

func (ac *AhoCorasick) Match(text string) *Rule {
	ac.buildFail()
	node := ac.root
	for i := 0; i < len(text); i++ {
		c := text[i]
		for node != ac.root && node.children[c] == nil {
			node = node.fail
		}
		if node.children[c] != nil {
			node = node.children[c]
		}
		if node.rule != nil {
			return node.rule
		}
	}
	return nil
}

func init() { _ = strings.Compare }
