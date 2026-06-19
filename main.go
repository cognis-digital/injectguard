// Command injectguard is a DEFENSIVE detection-rule tuning lab.
//
// It evaluates detection signatures (regex rules) against a labeled corpus of
// benign and malicious test strings and reports TP/FP/FN, precision, recall and
// F1 — overall and per category — so a defender can tune WAF/IDS rules, find
// evasions (false negatives) and silence noisy rules (false positives).
//
// It never attacks anything; it only scores rules against canaries you supply
// (or the built-in starter set).
//
//	injectguard eval [--rules f.json] [--corpus f.json] [--json] [--show-fn] [--show-fp] [--fail-under-recall X]
//	injectguard rules    list the built-in rule set
//	injectguard corpus   list the built-in corpus
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/cognis-digital/injectguard/internal/engine"
)

const usage = `injectguard - defensive detection-rule tuning lab

usage:
  injectguard eval [flags]     evaluate rules against a labeled corpus
  injectguard rules            list the built-in starter rules
  injectguard corpus           list the built-in labeled corpus
  injectguard help             show this help

eval flags:
  --rules PATH            JSON rule set (default: built-in starter rules)
  --corpus PATH           JSON labeled corpus (default: built-in starter corpus)
  --json                  emit the report as JSON
  --show-fn               list false negatives (malicious inputs that evaded)
  --show-fp               list false positives (benign inputs wrongly flagged)
  --fail-under-recall X   exit non-zero if overall recall < X (0..1), for CI

injectguard is DEFENSIVE: it scores detection rules so you can tune them.
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	switch args[0] {
	case "eval":
		return runEval(args[1:])
	case "rules":
		return runRules(args[1:])
	case "corpus":
		return runCorpus(args[1:])
	case "help", "-h", "--help":
		fmt.Print(usage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

func runEval(args []string) int {
	fs := flag.NewFlagSet("eval", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	rulesPath := fs.String("rules", "", "JSON rule set (default: built-in)")
	corpusPath := fs.String("corpus", "", "JSON labeled corpus (default: built-in)")
	asJSON := fs.Bool("json", false, "emit JSON report")
	showFN := fs.Bool("show-fn", false, "list false negatives")
	showFP := fs.Bool("show-fp", false, "list false positives")
	failRecall := fs.Float64("fail-under-recall", -1, "exit non-zero if overall recall < X")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	var (
		rs  *engine.RuleSet
		c   *engine.Corpus
		err error
	)

	if *rulesPath != "" {
		rs, err = engine.LoadRuleSet(*rulesPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
	} else {
		rs = engine.BuiltinRules()
	}

	if *corpusPath != "" {
		c, err = engine.LoadCorpus(*corpusPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
	} else {
		c = engine.BuiltinCorpus()
	}

	rep, err := engine.Evaluate(rs, c)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	if *asJSON {
		if err := engine.RenderJSON(os.Stdout, rep); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
	} else {
		engine.RenderText(os.Stdout, rep, *showFN, *showFP)
	}

	if *failRecall >= 0 && rep.Overall.Recall < *failRecall {
		fmt.Fprintf(os.Stderr, "\nFAIL: overall recall %.3f < threshold %.3f\n",
			rep.Overall.Recall, *failRecall)
		return 3
	}
	return 0
}

func runRules(args []string) int {
	fs := flag.NewFlagSet("rules", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rs := engine.BuiltinRules()
	fmt.Printf("%s (%d rules)\n\n", rs.Name, len(rs.Rules))
	fmt.Printf("%-28s %-12s %-8s %s\n", "id", "category", "severity", "pattern")
	for _, r := range rs.Rules {
		fmt.Printf("%-28s %-12s %-8s %s\n", r.ID, r.Category, r.Severity, r.Pattern)
	}
	return 0
}

func runCorpus(args []string) int {
	fs := flag.NewFlagSet("corpus", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c := engine.BuiltinCorpus()
	mal, ben := 0, 0
	for _, s := range c.Samples {
		if s.Malicious {
			mal++
		} else {
			ben++
		}
	}
	fmt.Printf("%s (%d samples: %d malicious, %d benign)\n\n", c.Name, len(c.Samples), mal, ben)
	fmt.Printf("%-12s %-12s %-9s %s\n", "id", "category", "label", "text")
	for _, s := range c.Samples {
		label := "benign"
		if s.Malicious {
			label = "malicious"
		}
		fmt.Printf("%-12s %-12s %-9s %q\n", s.ID, s.Category, label, s.Text)
	}
	return 0
}
