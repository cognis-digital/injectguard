package engine

import "sort"

// SampleResult records how a single sample was classified by the rule set.
type SampleResult struct {
	Sample    Sample
	Detected  bool     // at least one rule matched
	MatchedBy []string // ids of rules that matched (sorted)
}

// Metrics holds confusion-matrix counts and the derived scores. A "positive"
// prediction means the rule set flagged a sample as malicious (at least one
// rule matched).
//
//	TP: malicious sample that was detected
//	FP: benign sample that was flagged
//	FN: malicious sample that evaded all rules
//	TN: benign sample that was correctly left alone
type Metrics struct {
	TP int `json:"tp"`
	FP int `json:"fp"`
	FN int `json:"fn"`
	TN int `json:"tn"`

	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
}

// add accumulates one classification into the counts.
func (m *Metrics) add(malicious, detected bool) {
	switch {
	case malicious && detected:
		m.TP++
	case malicious && !detected:
		m.FN++
	case !malicious && detected:
		m.FP++
	default:
		m.TN++
	}
}

// finalize computes precision, recall and F1 from the counts. The conventional
// edge cases apply: precision is 1.0 when no positive predictions were made,
// recall is 1.0 when there are no actual positives, and F1 is 0 when precision
// and recall are both 0.
func (m *Metrics) finalize() {
	if m.TP+m.FP == 0 {
		m.Precision = 1.0
	} else {
		m.Precision = float64(m.TP) / float64(m.TP+m.FP)
	}
	if m.TP+m.FN == 0 {
		m.Recall = 1.0
	} else {
		m.Recall = float64(m.TP) / float64(m.TP+m.FN)
	}
	if m.Precision+m.Recall == 0 {
		m.F1 = 0
	} else {
		m.F1 = 2 * m.Precision * m.Recall / (m.Precision + m.Recall)
	}
}

// CategoryMetrics pairs a category name with its metrics.
type CategoryMetrics struct {
	Category string  `json:"category"`
	Metrics  Metrics `json:"metrics"`
}

// Report is the full outcome of evaluating a rule set against a corpus.
type Report struct {
	RuleSetName string            `json:"ruleset"`
	CorpusName  string            `json:"corpus"`
	RuleCount   int               `json:"rule_count"`
	SampleCount int               `json:"sample_count"`
	Overall     Metrics           `json:"overall"`
	ByCategory  []CategoryMetrics `json:"by_category"`

	Results        []SampleResult `json:"-"`
	FalseNegatives []SampleResult `json:"-"`
	FalsePositives []SampleResult `json:"-"`
}

// classify runs every rule against one sample and returns the result.
func classify(rules []Rule, s Sample) (SampleResult, error) {
	res := SampleResult{Sample: s}
	for i := range rules {
		ok, err := rules[i].Matches(s.Text)
		if err != nil {
			return res, err
		}
		if ok {
			res.Detected = true
			res.MatchedBy = append(res.MatchedBy, rules[i].ID)
		}
	}
	sort.Strings(res.MatchedBy)
	return res, nil
}

// Evaluate scores a rule set against a corpus and returns a full Report. It
// validates both inputs first so structural errors surface clearly.
func Evaluate(rs *RuleSet, c *Corpus) (*Report, error) {
	if err := rs.Validate(); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}

	rep := &Report{
		RuleSetName: rs.Name,
		CorpusName:  c.Name,
		RuleCount:   len(rs.Rules),
		SampleCount: len(c.Samples),
	}

	catMetrics := map[string]*Metrics{}

	for _, s := range c.Samples {
		res, err := classify(rs.Rules, s)
		if err != nil {
			return nil, err
		}
		rep.Results = append(rep.Results, res)
		rep.Overall.add(s.Malicious, res.Detected)

		cat := s.Category
		if cat == "" {
			cat = "(uncategorized)"
		}
		m := catMetrics[cat]
		if m == nil {
			m = &Metrics{}
			catMetrics[cat] = m
		}
		m.add(s.Malicious, res.Detected)

		if s.Malicious && !res.Detected {
			rep.FalseNegatives = append(rep.FalseNegatives, res)
		}
		if !s.Malicious && res.Detected {
			rep.FalsePositives = append(rep.FalsePositives, res)
		}
	}

	rep.Overall.finalize()

	cats := make([]string, 0, len(catMetrics))
	for cat := range catMetrics {
		cats = append(cats, cat)
	}
	sort.Strings(cats)
	for _, cat := range cats {
		m := catMetrics[cat]
		m.finalize()
		rep.ByCategory = append(rep.ByCategory, CategoryMetrics{Category: cat, Metrics: *m})
	}

	return rep, nil
}
