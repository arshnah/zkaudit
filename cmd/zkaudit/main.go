package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/arshnah/zkaudit"
)

func main() {
	harPaths := flag.String("har", "", "comma-separated paths to HAR files, one per flow you captured (upload, view, share, etc.)")
	secretsFlag := flag.String("secrets", "", "comma-separated plaintext values that should never appear in any request (e.g. the message you typed, the encryption key)")
	target := flag.String("target", "", "name of the thing being audited, used in the report (optional)")
	date := flag.String("date", "", "date to record in the report (optional)")
	reportPath := flag.String("report", "", "write a markdown report to this path (optional)")
	badgePath := flag.String("badge", "", "write a pass/fail SVG badge to this path (optional)")
	redactOut := flag.String("redact-out", "", "instead of auditing, strip cookies/auth headers from the -har file(s) and write the sanitized result here (single output file, merges multi-flow input)")
	flag.Parse()

	if *harPaths == "" {
		usage()
	}

	var paths []string
	var flowNames []string
	for _, p := range strings.Split(*harPaths, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		paths = append(paths, p)
		flowNames = append(flowNames, flowName(p))
	}
	if len(paths) == 0 {
		usage()
	}

	var hars []*zkaudit.HAR
	for _, p := range paths {
		h, err := zkaudit.LoadHAR(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to load HAR %s: %v\n", p, err)
			os.Exit(1)
		}
		hars = append(hars, h)
	}
	merged := zkaudit.MergeHARs(hars...)

	if *redactOut != "" {
		sanitized := zkaudit.Redact(merged)
		if err := zkaudit.SaveHAR(sanitized, *redactOut); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write redacted HAR: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("wrote sanitized HAR (cookies and auth headers redacted) to %s\n", *redactOut)
		return
	}

	if *secretsFlag == "" {
		usage()
	}

	var secrets []zkaudit.Secret
	for i, s := range strings.Split(*secretsFlag, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if len(s) < zkaudit.MinReliableSecretLength {
			fmt.Fprintf(os.Stderr, "warning: secret %q is only %d characters, substrings this short match constantly by coincidence (inside ordinary words, binary noise) and will produce false positives, results below may not be meaningful, use something longer and distinctive instead\n", s, len(s))
		}
		secrets = append(secrets, zkaudit.Secret{Label: fmt.Sprintf("secret-%d", i+1), Value: s})
	}

	report := zkaudit.Scan(merged, secrets)

	fmt.Printf("scanned %d network entries across %d flow(s) for %d secret(s)\n", report.EntriesScanned, len(paths), len(secrets))
	if report.CiphertextLikely {
		fmt.Println("at least one request body has the statistical signature of ciphertext (high entropy or high base64 density), consistent with client-side encryption actually happening")
	}

	pass := len(report.Findings) == 0
	if pass {
		fmt.Println("PASS: no plaintext secret was ever found in any request or response, this HAR is consistent with a zero-knowledge claim")
	} else {
		fmt.Printf("FAIL: found %d plaintext leak(s)\n", len(report.Findings))
		for _, f := range report.Findings {
			fmt.Printf("  entry %d, %s %s\n    leaked in: %s\n    matched: %s\n    context: %q\n", f.EntryIndex, f.Method, f.URL, f.Location, f.Secret, f.Snippet)
		}
	}

	if *reportPath != "" {
		meta := zkaudit.AuditMeta{Target: *target, Flows: flowNames, Date: *date}
		if err := zkaudit.WriteMarkdownReport(report, meta, *reportPath); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write report: %v\n", err)
		} else {
			fmt.Printf("wrote report to %s\n", *reportPath)
		}
	}
	if *badgePath != "" {
		if err := zkaudit.WriteBadgeSVG(pass, *badgePath); err != nil {
			fmt.Fprintf(os.Stderr, "failed to write badge: %v\n", err)
		} else {
			fmt.Printf("wrote badge to %s\n", *badgePath)
		}
	}

	if !pass {
		os.Exit(1)
	}
}

func flowName(path string) string {
	base := path
	if i := strings.LastIndexByte(base, '/'); i != -1 {
		base = base[i+1:]
	}
	return strings.TrimSuffix(base, ".har")
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: zkaudit -har capture.har[,flow2.har,...] -secrets \"the exact plaintext I typed,my-encryption-passphrase\" [-target name] [-report out.md] [-badge out.svg]")
	fmt.Fprintln(os.Stderr, "   or: zkaudit -har capture.har -redact-out sanitized.har   (strip cookies/auth headers before sharing a capture)")
	os.Exit(1)
}
