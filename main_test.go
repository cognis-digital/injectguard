package main

import (
	"os"
	"path/filepath"
	"testing"
)

// run() returns process exit codes; verify the command dispatch and the CI gate.

func TestRunNoArgs(t *testing.T) {
	if code := run(nil); code != 2 {
		t.Errorf("no args exit = %d, want 2", code)
	}
}

func TestRunUnknownCommand(t *testing.T) {
	if code := run([]string{"bogus"}); code != 2 {
		t.Errorf("unknown command exit = %d, want 2", code)
	}
}

func TestRunHelp(t *testing.T) {
	if code := run([]string{"help"}); code != 0 {
		t.Errorf("help exit = %d, want 0", code)
	}
}

func TestRunEvalBuiltins(t *testing.T) {
	if code := run([]string{"eval"}); code != 0 {
		t.Errorf("eval builtin exit = %d, want 0", code)
	}
}

func TestRunRulesAndCorpus(t *testing.T) {
	if code := run([]string{"rules"}); code != 0 {
		t.Errorf("rules exit = %d, want 0", code)
	}
	if code := run([]string{"corpus"}); code != 0 {
		t.Errorf("corpus exit = %d, want 0", code)
	}
}

func TestGatePassesWhenRecallAboveThreshold(t *testing.T) {
	// built-in recall is comfortably above 0.5
	if code := run([]string{"eval", "--fail-under-recall", "0.5"}); code != 0 {
		t.Errorf("gate exit = %d, want 0 (recall above threshold)", code)
	}
}

func TestGateFailsWhenRecallBelowThreshold(t *testing.T) {
	// impossible threshold => gate must trip with exit 3
	if code := run([]string{"eval", "--fail-under-recall", "1.01"}); code != 3 {
		t.Errorf("gate exit = %d, want 3 (recall below threshold)", code)
	}
}

func TestEvalWithFileInputs(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.json")
	corpusPath := filepath.Join(dir, "corpus.json")

	rules := `{"name":"t","rules":[{"id":"r1","category":"sqli","severity":"high","pattern":"or 1=1"}]}`
	corpus := `{"name":"t","samples":[
		{"id":"a","category":"sqli","malicious":true,"text":"x or 1=1"},
		{"id":"b","category":"sqli","malicious":false,"text":"clean text"}
	]}`
	if err := os.WriteFile(rulesPath, []byte(rules), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(corpusPath, []byte(corpus), 0o644); err != nil {
		t.Fatal(err)
	}

	code := run([]string{"eval", "--rules", rulesPath, "--corpus", corpusPath, "--json"})
	if code != 0 {
		t.Errorf("eval with files exit = %d, want 0", code)
	}
}

func TestEvalMissingFile(t *testing.T) {
	if code := run([]string{"eval", "--rules", "does-not-exist.json"}); code != 1 {
		t.Errorf("missing file exit = %d, want 1", code)
	}
}
