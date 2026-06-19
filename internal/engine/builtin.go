package engine

// This file contains injectguard's built-in starter rule set and labeled
// corpus. Everything here is ORIGINAL, authored by Cognis Digital as generic
// illustrative canaries for DEFENSIVE detection-rule tuning. The malicious
// samples are short, well-known-shape probes (not lifted from any wordlist or
// third-party project) whose only purpose is to exercise the matching logic so
// a defender can measure and tune recall/precision before deploying their own
// rules and corpus.

// BuiltinRules returns the starter detection rule set. Patterns are compiled
// case-insensitively, so they are written in lower case for readability.
func BuiltinRules() *RuleSet {
	return &RuleSet{
		Name: "injectguard-starter-rules",
		Rules: []Rule{
			// --- SQL injection shapes ---
			{
				ID:       "sqli-tautology",
				Category: "sqli",
				Severity: "high",
				// classic always-true comparison: ' or 1=1 / " or '1'='1
				Pattern: `(['"]?\s*or\s+['"]?\d+['"]?\s*=\s*['"]?\d+)`,
			},
			{
				ID:       "sqli-comment-terminator",
				Category: "sqli",
				Severity: "medium",
				// trailing sql comment used to truncate a query: --, #, /*
				Pattern: `(--\s|#\s*$|/\*)`,
			},
			{
				ID:       "sqli-union-select",
				Category: "sqli",
				Severity: "high",
				Pattern:  `\bunion\b[\s\S]{0,40}?\bselect\b`,
			},
			{
				ID:       "sqli-stacked-query",
				Category: "sqli",
				Severity: "high",
				// stacked statement: ; drop / ; delete / ; update
				Pattern: `;\s*(drop|delete|update|insert|truncate)\b`,
			},

			// --- Authentication / authorization bypass shapes ---
			{
				ID:       "auth-bypass-or-true",
				Category: "auth-bypass",
				Severity: "high",
				// boolean bypass injected into a login field
				Pattern: `\bor\b\s+true\b|\bor\b\s+1\s*=\s*1`,
			},
			{
				ID:       "auth-bypass-admin-comment",
				Category: "auth-bypass",
				Severity: "high",
				// admin'-- style username that comments out the password check
				Pattern: `\badmin['"]?\s*(--|#|/\*)`,
			},
			{
				ID:       "auth-bypass-null-cred",
				Category: "auth-bypass",
				Severity: "medium",
				// attempts to coerce a null/empty credential check
				Pattern: `\bpassword\b\s*(is\s+null|=\s*['"]?\s*['"]?\s*or)`,
			},

			// --- Cross-site scripting shapes ---
			{
				ID:       "xss-script-tag",
				Category: "xss",
				Severity: "high",
				Pattern:  `<\s*script\b`,
			},
			{
				ID:       "xss-event-handler",
				Category: "xss",
				Severity: "medium",
				// inline event handler such as onerror= / onload=
				Pattern: `\bon(error|load|click|mouseover)\s*=`,
			},
			{
				ID:       "xss-js-uri",
				Category: "xss",
				Severity: "medium",
				Pattern:  `javascript\s*:`,
			},
		},
	}
}

// BuiltinCorpus returns the starter labeled corpus. Malicious samples are
// generic canaries; benign samples deliberately include "tricky" text that
// looks adjacent to an attack (e.g. prose mentioning a script, a SELECT in a
// sentence) so that false positives in noisy rules are exposed.
func BuiltinCorpus() *Corpus {
	return &Corpus{
		Name: "injectguard-starter-corpus",
		Samples: []Sample{
			// --- sqli: malicious ---
			{ID: "sqli-m1", Category: "sqli", Malicious: true, Text: `' OR 1=1 -- `, Note: "tautology + comment"},
			{ID: "sqli-m2", Category: "sqli", Malicious: true, Text: `1' UNION SELECT username, password FROM users`, Note: "union extract"},
			{ID: "sqli-m3", Category: "sqli", Malicious: true, Text: `42; DROP TABLE sessions`, Note: "stacked query"},
			{ID: "sqli-m4", Category: "sqli", Malicious: true, Text: `") or ("1"="1`, Note: "tautology variant"},
			{ID: "sqli-m5", Category: "sqli", Malicious: true, Text: `id=5 /* peek */ UNION  SELECT 1`, Note: "comment + union"},

			// --- sqli: benign ---
			{ID: "sqli-b1", Category: "sqli", Malicious: false, Text: `Florida or Georgia for vacation?`, Note: "natural 'or'"},
			{ID: "sqli-b2", Category: "sqli", Malicious: false, Text: `We will select the best candidate next week.`, Note: "prose select"},
			{ID: "sqli-b3", Category: "sqli", Malicious: false, Text: `order number 10012`, Note: "ordinary order id"},
			{ID: "sqli-b4", Category: "sqli", Malicious: false, Text: `union representatives met today`, Note: "prose union, no select"},

			// --- auth-bypass: malicious ---
			{ID: "auth-m1", Category: "auth-bypass", Malicious: true, Text: `admin'--`, Note: "comment-out password"},
			{ID: "auth-m2", Category: "auth-bypass", Malicious: true, Text: `username=x' OR 1=1`, Note: "boolean bypass"},
			{ID: "auth-m3", Category: "auth-bypass", Malicious: true, Text: `' or true; --`, Note: "or true bypass"},
			{ID: "auth-m4", Category: "auth-bypass", Malicious: true, Text: `password is null or 1=1`, Note: "null credential"},

			// --- auth-bypass: benign ---
			{ID: "auth-b1", Category: "auth-bypass", Malicious: false, Text: `My username is administrator`, Note: "legit admin-ish"},
			{ID: "auth-b2", Category: "auth-bypass", Malicious: false, Text: `please reset my password`, Note: "support request"},
			{ID: "auth-b3", Category: "auth-bypass", Malicious: false, Text: `true or false quiz answers`, Note: "prose or true"},

			// --- xss: malicious ---
			{ID: "xss-m1", Category: "xss", Malicious: true, Text: `<script>steal()</script>`, Note: "script tag"},
			{ID: "xss-m2", Category: "xss", Malicious: true, Text: `<img src=x onerror=alert(1)>`, Note: "event handler"},
			{ID: "xss-m3", Category: "xss", Malicious: true, Text: `<a href="javascript:run()">x</a>`, Note: "js uri"},
			{ID: "xss-m4", Category: "xss", Malicious: true, Text: `< script >hide()< /script >`, Note: "spaced tag"},

			// --- xss: benign ---
			{ID: "xss-b1", Category: "xss", Malicious: false, Text: `I wrote a shell script yesterday.`, Note: "prose script"},
			{ID: "xss-b2", Category: "xss", Malicious: false, Text: `The onload festival starts at noon.`, Note: "word onload, no ="},
			{ID: "xss-b3", Category: "xss", Malicious: false, Text: `Use JavaScript for the front end.`, Note: "language name, no colon"},
		},
	}
}
