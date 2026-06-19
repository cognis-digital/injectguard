// Package engine implements the detection-rule tuning lab for injectguard.
//
// injectguard is a DEFENSIVE tool: it evaluates a set of detection signatures
// (regular-expression rules) against a labeled corpus of inputs and reports the
// confusion-matrix metrics (TP/FP/FN, precision, recall, F1) overall and per
// category. It does not attack anything; it exists so a defender can TUNE their
// WAF/IDS detection rules and find evasions (false negatives) and noisy rules
// (false positives).
package engine

import (
	"fmt"
	"regexp"
)

// Rule is a single detection signature. Pattern is a Go regular expression that
// is matched (case-insensitively unless the rule embeds its own flags) against
// each corpus input. Category groups rules so metrics can be reported per
// category (e.g. "sqli", "auth-bypass", "xss").
type Rule struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Pattern  string `json:"pattern"`

	re *regexp.Regexp
}

// compiled returns the compiled regexp for the rule, compiling it on first use.
// Rules are compiled case-insensitively by default; authors can still pin case
// sensitivity inside the pattern with the standard (?-i:...) group.
func (r *Rule) compiled() (*regexp.Regexp, error) {
	if r.re != nil {
		return r.re, nil
	}
	re, err := regexp.Compile("(?i)" + r.Pattern)
	if err != nil {
		return nil, fmt.Errorf("rule %q: invalid pattern: %w", r.ID, err)
	}
	r.re = re
	return re, nil
}

// Matches reports whether the rule's pattern is found anywhere in the input.
func (r *Rule) Matches(input string) (bool, error) {
	re, err := r.compiled()
	if err != nil {
		return false, err
	}
	return re.MatchString(input), nil
}

// Sample is one labeled corpus input. Malicious is true when the input is a
// canary that SHOULD be detected by at least one rule; false for benign inputs
// that should NOT be flagged. Category lets per-category metrics line up with
// rule categories.
type Sample struct {
	ID        string `json:"id"`
	Category  string `json:"category"`
	Text      string `json:"text"`
	Malicious bool   `json:"malicious"`
	Note      string `json:"note,omitempty"`
}

// RuleSet is a named collection of rules, as loaded from JSON.
type RuleSet struct {
	Name  string `json:"name"`
	Rules []Rule `json:"rules"`
}

// Corpus is a named collection of labeled samples, as loaded from JSON.
type Corpus struct {
	Name    string   `json:"name"`
	Samples []Sample `json:"samples"`
}

// Validate checks a rule set for structural problems (empty IDs, duplicate IDs,
// uncompilable patterns) so misconfiguration surfaces before evaluation.
func (rs *RuleSet) Validate() error {
	if len(rs.Rules) == 0 {
		return fmt.Errorf("rule set %q contains no rules", rs.Name)
	}
	seen := map[string]bool{}
	for i := range rs.Rules {
		r := &rs.Rules[i]
		if r.ID == "" {
			return fmt.Errorf("rule at index %d has an empty id", i)
		}
		if seen[r.ID] {
			return fmt.Errorf("duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
		if r.Pattern == "" {
			return fmt.Errorf("rule %q has an empty pattern", r.ID)
		}
		if _, err := r.compiled(); err != nil {
			return err
		}
	}
	return nil
}

// Validate checks a corpus for structural problems (empty IDs, duplicates).
func (c *Corpus) Validate() error {
	if len(c.Samples) == 0 {
		return fmt.Errorf("corpus %q contains no samples", c.Name)
	}
	seen := map[string]bool{}
	for i := range c.Samples {
		s := &c.Samples[i]
		if s.ID == "" {
			return fmt.Errorf("sample at index %d has an empty id", i)
		}
		if seen[s.ID] {
			return fmt.Errorf("duplicate sample id %q", s.ID)
		}
		seen[s.ID] = true
	}
	return nil
}
