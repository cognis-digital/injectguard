package engine

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// RenderText writes a human-readable report to w. When showFN/showFP are set,
// the evading (false-negative) and wrongly-flagged (false-positive) samples are
// listed so a defender can see exactly what to tune.
func RenderText(w io.Writer, rep *Report, showFN, showFP bool) {
	fmt.Fprintf(w, "injectguard evaluation\n")
	fmt.Fprintf(w, "  rules:   %s (%d rules)\n", rep.RuleSetName, rep.RuleCount)
	fmt.Fprintf(w, "  corpus:  %s (%d samples)\n\n", rep.CorpusName, rep.SampleCount)

	o := rep.Overall
	fmt.Fprintf(w, "overall: TP=%d FP=%d FN=%d TN=%d\n", o.TP, o.FP, o.FN, o.TN)
	fmt.Fprintf(w, "         precision=%.3f recall=%.3f f1=%.3f\n\n", o.Precision, o.Recall, o.F1)

	fmt.Fprintf(w, "%-18s %4s %4s %4s %4s  %9s %7s %5s\n",
		"category", "TP", "FP", "FN", "TN", "precision", "recall", "f1")
	fmt.Fprintf(w, "%s\n", strings.Repeat("-", 64))
	for _, cm := range rep.ByCategory {
		m := cm.Metrics
		fmt.Fprintf(w, "%-18s %4d %4d %4d %4d  %9.3f %7.3f %5.3f\n",
			cm.Category, m.TP, m.FP, m.FN, m.TN, m.Precision, m.Recall, m.F1)
	}

	if showFN {
		fmt.Fprintf(w, "\nfalse negatives (malicious, evaded all rules): %d\n", len(rep.FalseNegatives))
		for _, r := range rep.FalseNegatives {
			fmt.Fprintf(w, "  - [%s/%s] %q\n", r.Sample.Category, r.Sample.ID, r.Sample.Text)
		}
	}
	if showFP {
		fmt.Fprintf(w, "\nfalse positives (benign, wrongly flagged): %d\n", len(rep.FalsePositives))
		for _, r := range rep.FalsePositives {
			fmt.Fprintf(w, "  - [%s/%s] %q  matched-by=%s\n",
				r.Sample.Category, r.Sample.ID, r.Sample.Text, strings.Join(r.MatchedBy, ","))
		}
	}
}

// jsonSample is the externally-stable shape for a listed sample in JSON output.
type jsonSample struct {
	ID        string   `json:"id"`
	Category  string   `json:"category"`
	Text      string   `json:"text"`
	MatchedBy []string `json:"matched_by,omitempty"`
}

// jsonReport mirrors Report for stable JSON output, including the FN/FP lists.
type jsonReport struct {
	RuleSet        string            `json:"ruleset"`
	Corpus         string            `json:"corpus"`
	RuleCount      int               `json:"rule_count"`
	SampleCount    int               `json:"sample_count"`
	Overall        Metrics           `json:"overall"`
	ByCategory     []CategoryMetrics `json:"by_category"`
	FalseNegatives []jsonSample      `json:"false_negatives"`
	FalsePositives []jsonSample      `json:"false_positives"`
}

// RenderJSON writes the report as indented JSON to w.
func RenderJSON(w io.Writer, rep *Report) error {
	jr := jsonReport{
		RuleSet:     rep.RuleSetName,
		Corpus:      rep.CorpusName,
		RuleCount:   rep.RuleCount,
		SampleCount: rep.SampleCount,
		Overall:     rep.Overall,
		ByCategory:  rep.ByCategory,
	}
	for _, r := range rep.FalseNegatives {
		jr.FalseNegatives = append(jr.FalseNegatives, jsonSample{
			ID: r.Sample.ID, Category: r.Sample.Category, Text: r.Sample.Text,
		})
	}
	for _, r := range rep.FalsePositives {
		jr.FalsePositives = append(jr.FalsePositives, jsonSample{
			ID: r.Sample.ID, Category: r.Sample.Category, Text: r.Sample.Text, MatchedBy: r.MatchedBy,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(jr)
}
