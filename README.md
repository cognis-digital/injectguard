# injectguard

**A defensive detection-rule tuning lab.**

`injectguard` is a small CLI that evaluates your **detection signatures**
(regular-expression rules) against a **labeled corpus** of benign and malicious
test strings, then reports the confusion-matrix metrics — TP / FP / FN,
precision, recall and F1 — **overall and per category**. It tells you which
malicious inputs *evaded* your rules (false negatives) and which benign inputs
were *wrongly flagged* (false positives), so you can **tune your WAF/IDS
detection rules** with measured feedback instead of guesswork.

> **Defensive scope only.** injectguard does not attack, scan, or send anything.
> It is a measurement harness: you give it rules and a labeled corpus, it scores
> the rules. Its only purpose is to help defenders improve detection coverage
> and cut alert noise. The bundled malicious samples are short, generic,
> authored canaries (illustrative attack *shapes*, not exploit payloads) used to
> exercise the matching logic.

---

## Install / build

Requires Go 1.22+.

```sh
git clone https://github.com/cognis-digital/injectguard
cd injectguard
go build -o injectguard .
```

Or run without installing:

```sh
go run . eval
```

## Usage

```
injectguard eval [flags]     evaluate rules against a labeled corpus
injectguard rules            list the built-in starter rules
injectguard corpus           list the built-in labeled corpus
injectguard help             show help
```

### `eval` flags

| flag | meaning |
|------|---------|
| `--rules PATH` | JSON rule set (defaults to the built-in starter rules) |
| `--corpus PATH` | JSON labeled corpus (defaults to the built-in corpus) |
| `--json` | emit the report as JSON |
| `--show-fn` | list false negatives (malicious inputs that evaded all rules) |
| `--show-fp` | list false positives (benign inputs that were wrongly flagged) |
| `--fail-under-recall X` | exit non-zero if overall recall < X (0..1) — for CI gates |

If you omit `--rules`/`--corpus`, the built-in starter data is used, so you can
try it immediately:

```sh
injectguard eval
injectguard eval --show-fn --show-fp
injectguard eval --json
```

### Example output

```
injectguard evaluation
  rules:   injectguard-starter-rules (10 rules)
  corpus:  injectguard-starter-corpus (23 samples)

overall: TP=12 FP=0 FN=1 TN=10
         precision=1.000 recall=0.923 f1=0.960

category             TP   FP   FN   TN  precision  recall    f1
----------------------------------------------------------------
auth-bypass           4    0    0    3      1.000   1.000 1.000
sqli                  4    0    1    4      1.000   0.800 0.889
xss                   4    0    0    3      1.000   1.000 1.000
```

The starter `sqli` category intentionally ships with **one evasion** — the
quoted tautology `") or ("1"="1` slips past `sqli-tautology`. Run
`injectguard eval --show-fn` to surface it; closing that gap (broadening the
rule to allow quoted operands) is the canonical first tuning exercise.

## File formats

**Rule set** — a regex `pattern` per rule, grouped by `category`. Patterns are
matched case-insensitively.

```json
{
  "name": "my-rules",
  "rules": [
    { "id": "sqli-union-select", "category": "sqli", "severity": "high",
      "pattern": "\\bunion\\b[\\s\\S]{0,40}?\\bselect\\b" }
  ]
}
```

**Corpus** — labeled inputs. `malicious: true` means the input *should* be
detected by at least one rule; `false` means it should be left alone.

```json
{
  "name": "my-corpus",
  "samples": [
    { "id": "m1", "category": "sqli", "malicious": true,  "text": "1' UNION SELECT pw FROM users" },
    { "id": "b1", "category": "sqli", "malicious": false, "text": "union representatives met today" }
  ]
}
```

Ready-to-edit examples live in [`examples/`](examples/).

## How the metrics are defined

A *positive* prediction means the rule set flagged a sample (≥1 rule matched).

| | predicted positive | predicted negative |
|---|---|---|
| **actually malicious** | TP | FN (evasion) |
| **actually benign** | FP (noise) | TN |

- `precision = TP / (TP + FP)` — when no positives are predicted, precision is reported as `1.0`.
- `recall = TP / (TP + FN)` — when there are no actual positives, recall is reported as `1.0`.
- `f1 = 2·precision·recall / (precision + recall)` — `0` when both are `0`.

## Tuning workflow

1. Start from your current rules and a corpus of real benign + malicious shapes.
2. Run `injectguard eval --show-fn --show-fp`.
3. **False negatives** show evasions → add or broaden a rule for that category.
4. **False positives** show noisy rules (with `matched-by`) → tighten them.
5. Re-run; watch per-category recall climb and precision hold.
6. Wire `--fail-under-recall 0.8` into CI so a regression in coverage fails the build.

## CI

`injectguard eval --fail-under-recall X` exits non-zero (code `3`) when overall
recall drops below `X`, so you can gate rule changes:

```yaml
- run: go run . eval --rules rules.json --corpus corpus.json --fail-under-recall 0.8
```

See [`.github/workflows/ci.yml`](.github/workflows/ci.yml) for the project's own
build + test + self-check gate.

## Exit codes

| code | meaning |
|------|---------|
| `0` | success |
| `1` | runtime error (bad/missing file, invalid rule set or corpus) |
| `2` | usage error (unknown command / bad flags) |
| `3` | recall gate tripped (`--fail-under-recall`) |

## Development

```sh
go build ./...
go test ./...
go vet ./...
```

Standard library only (uses `regexp`, `encoding/json`, `flag`).

## License

License: COCL 1.0

## Maintainer

Cognis Digital
