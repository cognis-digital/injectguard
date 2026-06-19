package engine

import (
	"math"
	"strings"
	"testing"
)

func approx(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// A tiny hand-built fixture with known confusion-matrix outcomes so the metric
// math can be checked independently of the built-in data.
func fixtureRuleSet() *RuleSet {
	return &RuleSet{
		Name: "fixture",
		Rules: []Rule{
			{ID: "r-tauto", Category: "sqli", Severity: "high", Pattern: `or\s+1\s*=\s*1`},
			{ID: "r-script", Category: "xss", Severity: "high", Pattern: `<script`},
		},
	}
}

func fixtureCorpus() *Corpus {
	return &Corpus{
		Name: "fixture",
		Samples: []Sample{
			// sqli: 1 TP, 1 FN, 1 TN
			{ID: "s1", Category: "sqli", Malicious: true, Text: "x' or 1=1"},          // TP
			{ID: "s2", Category: "sqli", Malicious: true, Text: "x' union select pw"}, // FN (no rule covers union)
			{ID: "s3", Category: "sqli", Malicious: false, Text: "hello world"},       // TN
			// xss: 1 TP, 1 FP
			{ID: "s4", Category: "xss", Malicious: true, Text: "<script>x</script>"},  // TP
			{ID: "s5", Category: "xss", Malicious: false, Text: "<script>safe note"}, // FP (benign but matches)
		},
	}
}

func TestEvaluateConfusionCounts(t *testing.T) {
	rep, err := Evaluate(fixtureRuleSet(), fixtureCorpus())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	o := rep.Overall
	if o.TP != 2 || o.FP != 1 || o.FN != 1 || o.TN != 1 {
		t.Fatalf("counts TP=%d FP=%d FN=%d TN=%d, want 2/1/1/1", o.TP, o.FP, o.FN, o.TN)
	}
}

func TestEvaluatePrecisionRecallF1(t *testing.T) {
	rep, _ := Evaluate(fixtureRuleSet(), fixtureCorpus())
	o := rep.Overall
	// precision = TP/(TP+FP) = 2/3
	if !approx(o.Precision, 2.0/3.0) {
		t.Errorf("precision = %v, want 0.6667", o.Precision)
	}
	// recall = TP/(TP+FN) = 2/3
	if !approx(o.Recall, 2.0/3.0) {
		t.Errorf("recall = %v, want 0.6667", o.Recall)
	}
	// f1 = 2pr/(p+r) = 2/3
	if !approx(o.F1, 2.0/3.0) {
		t.Errorf("f1 = %v, want 0.6667", o.F1)
	}
}

func TestPerCategoryMetrics(t *testing.T) {
	rep, _ := Evaluate(fixtureRuleSet(), fixtureCorpus())
	byCat := map[string]Metrics{}
	for _, cm := range rep.ByCategory {
		byCat[cm.Category] = cm.Metrics
	}

	sqli, ok := byCat["sqli"]
	if !ok {
		t.Fatal("missing sqli category")
	}
	if sqli.TP != 1 || sqli.FN != 1 || sqli.TN != 1 || sqli.FP != 0 {
		t.Errorf("sqli counts TP=%d FP=%d FN=%d TN=%d, want 1/0/1/1", sqli.TP, sqli.FP, sqli.FN, sqli.TN)
	}
	if !approx(sqli.Recall, 0.5) {
		t.Errorf("sqli recall = %v, want 0.5", sqli.Recall)
	}

	xss := byCat["xss"]
	if xss.TP != 1 || xss.FP != 1 {
		t.Errorf("xss counts TP=%d FP=%d, want 1/1", xss.TP, xss.FP)
	}
	if !approx(xss.Recall, 1.0) {
		t.Errorf("xss recall = %v, want 1.0", xss.Recall)
	}
	if !approx(xss.Precision, 0.5) {
		t.Errorf("xss precision = %v, want 0.5", xss.Precision)
	}
}

func TestFalseNegativesAndPositivesListed(t *testing.T) {
	rep, _ := Evaluate(fixtureRuleSet(), fixtureCorpus())
	if len(rep.FalseNegatives) != 1 || rep.FalseNegatives[0].Sample.ID != "s2" {
		t.Errorf("false negatives = %+v, want [s2]", rep.FalseNegatives)
	}
	if len(rep.FalsePositives) != 1 || rep.FalsePositives[0].Sample.ID != "s5" {
		t.Errorf("false positives = %+v, want [s5]", rep.FalsePositives)
	}
	if len(rep.FalsePositives[0].MatchedBy) == 0 {
		t.Error("false positive should record which rule matched")
	}
}

func TestRuleMatchingCaseInsensitive(t *testing.T) {
	r := Rule{ID: "x", Pattern: `<script`}
	ok, err := r.Matches("<SCRIPT>alert(1)</SCRIPT>")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("expected case-insensitive match")
	}
	no, _ := r.Matches("nothing here")
	if no {
		t.Error("unexpected match")
	}
}

func TestEdgeCaseEmptyPredictions(t *testing.T) {
	// rule that matches nothing in the corpus => no positive predictions.
	rs := &RuleSet{Name: "none", Rules: []Rule{{ID: "never", Category: "x", Pattern: `zzzzznevermatch`}}}
	c := &Corpus{Name: "c", Samples: []Sample{
		{ID: "a", Category: "x", Malicious: false, Text: "clean"},
	}}
	rep, err := Evaluate(rs, c)
	if err != nil {
		t.Fatal(err)
	}
	// no positives predicted -> precision defined as 1.0; no actual positives -> recall 1.0
	if !approx(rep.Overall.Precision, 1.0) {
		t.Errorf("precision = %v, want 1.0", rep.Overall.Precision)
	}
	if !approx(rep.Overall.Recall, 1.0) {
		t.Errorf("recall = %v, want 1.0", rep.Overall.Recall)
	}
}

func TestValidateRejectsBadPattern(t *testing.T) {
	rs := &RuleSet{Name: "bad", Rules: []Rule{{ID: "r1", Category: "x", Pattern: `([`}}}
	if err := rs.Validate(); err == nil {
		t.Error("expected error for invalid regex pattern")
	}
}

func TestValidateRejectsDuplicateRuleID(t *testing.T) {
	rs := &RuleSet{Name: "dup", Rules: []Rule{
		{ID: "r1", Pattern: "a"},
		{ID: "r1", Pattern: "b"},
	}}
	if err := rs.Validate(); err == nil {
		t.Error("expected duplicate id error")
	}
}

func TestValidateRejectsDuplicateSampleID(t *testing.T) {
	c := &Corpus{Name: "dup", Samples: []Sample{
		{ID: "s1", Text: "a"},
		{ID: "s1", Text: "b"},
	}}
	if err := c.Validate(); err == nil {
		t.Error("expected duplicate sample id error")
	}
}

func TestBuiltinDataIsCoherent(t *testing.T) {
	rs := BuiltinRules()
	c := BuiltinCorpus()
	if err := rs.Validate(); err != nil {
		t.Fatalf("builtin rules invalid: %v", err)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("builtin corpus invalid: %v", err)
	}
	rep, err := Evaluate(rs, c)
	if err != nil {
		t.Fatalf("evaluate builtins: %v", err)
	}
	// The starter set should detect a strong majority of canaries and keep
	// precision high; pin loose floors so the data and rules stay coherent.
	if rep.Overall.Recall < 0.8 {
		t.Errorf("builtin recall = %.3f, want >= 0.8", rep.Overall.Recall)
	}
	if rep.Overall.Precision < 0.8 {
		t.Errorf("builtin precision = %.3f, want >= 0.8", rep.Overall.Precision)
	}
}

func TestRenderTextIncludesMetricsAndLists(t *testing.T) {
	rep, _ := Evaluate(fixtureRuleSet(), fixtureCorpus())
	var b strings.Builder
	RenderText(&b, rep, true, true)
	out := b.String()
	for _, want := range []string{"overall:", "precision", "false negatives", "false positives", "s2", "s5"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q\n%s", want, out)
		}
	}
}

func TestRenderJSONValid(t *testing.T) {
	rep, _ := Evaluate(fixtureRuleSet(), fixtureCorpus())
	var b strings.Builder
	if err := RenderJSON(&b, rep); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `"recall"`) {
		t.Error("json output missing recall field")
	}
}
