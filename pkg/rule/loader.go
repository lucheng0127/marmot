package rule

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadRulesFromFile reads and parses a rules YAML file.
func LoadRulesFromFile(path string) ([]RuleConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules file %s: %w", path, err)
	}
	return LoadRulesFromYAML(data)
}

// LoadRulesFromYAML parses YAML rule definitions.
func LoadRulesFromYAML(data []byte) ([]RuleConfig, error) {
	var cfg struct {
		Rules []RuleConfig `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}
	return cfg.Rules, nil
}
