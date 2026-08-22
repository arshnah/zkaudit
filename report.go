package zkaudit

import (
	"fmt"
	"os"
	"strings"
)

type AuditMeta struct {
	Target string
	Flows  []string
	Date   string
}

func WriteMarkdownReport(report Report, meta AuditMeta, path string) error {
	var b strings.Builder

	verdict := "PASS"
	if len(report.Findings) > 0 {
		verdict = "FAIL"
	}

	fmt.Fprintf(&b, "# zero-knowledge audit: %s\n\n", meta.Target)
	fmt.Fprintf(&b, "**verdict: %s**\n\n", verdict)
	fmt.Fprintf(&b, "date: %s\n\n", meta.Date)
	if len(meta.Flows) > 0 {
		fmt.Fprintf(&b, "flows captured: %s\n\n", strings.Join(meta.Flows, ", "))
	}
	fmt.Fprintf(&b, "network entries scanned: %d\n\n", report.EntriesScanned)

	if report.CiphertextLikely {
		fmt.Fprintf(&b, "at least one captured request body has the statistical signature of ciphertext (high entropy or high base64 density), consistent with client-side encryption actually happening.\n\n")
	} else {
		fmt.Fprintf(&b, "no captured request body showed a strong ciphertext signature, this doesn't mean encryption isn't happening, only that this specific heuristic didn't fire on this capture.\n\n")
	}

	if len(report.Findings) == 0 {
		fmt.Fprintf(&b, "no plaintext secret was ever found in any captured request or response. across the flows captured, this target's zero-knowledge claim held up.\n\n")
	} else {
		fmt.Fprintf(&b, "## leaks found\n\n")
		for _, f := range report.Findings {
			fmt.Fprintf(&b, "- entry %d, `%s %s`, leaked in %s, matched %s: `%s`\n", f.EntryIndex, f.Method, f.URL, f.Location, f.Secret, f.Snippet)
		}
		fmt.Fprintf(&b, "\n")
	}

	fmt.Fprintf(&b, "## what this does and doesn't prove\n\n")
	fmt.Fprintf(&b, "this checks whether the exact plaintext provided to the audit ever appeared, in any form, in any request or response captured during these specific flows. ")
	fmt.Fprintf(&b, "it does not audit the cryptographic implementation itself, does not cover flows that weren't captured, and a PASS is only as good as the flows actually exercised.\n")

	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func WriteBadgeSVG(pass bool, path string) error {
	label := "zero-knowledge audit"
	status := "pass"
	color := "#2ea44f"
	if !pass {
		status = "fail"
		color = "#d1242f"
	}

	svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="190" height="20" role="img" aria-label="%s: %s">
<linearGradient id="s" x2="0" y2="100%%">
<stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
<stop offset="1" stop-opacity=".1"/>
</linearGradient>
<mask id="m"><rect width="190" height="20" rx="3" fill="#fff"/></mask>
<g mask="url(#m)">
<rect width="130" height="20" fill="#555"/>
<rect x="130" width="60" height="20" fill="%s"/>
<rect width="190" height="20" fill="url(#s)"/>
</g>
<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,sans-serif" font-size="11">
<text x="65" y="14">%s</text>
<text x="160" y="14">%s</text>
</g>
</svg>`, label, status, color, label, strings.ToUpper(status))

	return os.WriteFile(path, []byte(svg), 0o644)
}
