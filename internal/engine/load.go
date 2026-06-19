package engine

import (
	"encoding/json"
	"fmt"
	"os"
)

// LoadRuleSet reads and parses a rule set from a JSON file.
func LoadRuleSet(path string) (*RuleSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules: %w", err)
	}
	var rs RuleSet
	if err := json.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("parse rules %s: %w", path, err)
	}
	if rs.Name == "" {
		rs.Name = path
	}
	return &rs, nil
}

// LoadCorpus reads and parses a labeled corpus from a JSON file.
func LoadCorpus(path string) (*Corpus, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read corpus: %w", err)
	}
	var c Corpus
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse corpus %s: %w", path, err)
	}
	if c.Name == "" {
		c.Name = path
	}
	return &c, nil
}
