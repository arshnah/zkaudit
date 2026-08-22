package zkaudit

import (
	"encoding/base64"
	"net/url"
	"strings"
)

const MinReliableSecretLength = 8

type Secret struct {
	Label string
	Value string
}

type Finding struct {
	Secret     string
	EntryIndex int
	Method     string
	URL        string
	Location   string
	Snippet    string
}

type Report struct {
	Findings         []Finding
	EntriesScanned   int
	CiphertextLikely bool
}

func variants(secret string) []string {
	candidates := []string{
		secret,
		url.QueryEscape(secret),
		base64.StdEncoding.EncodeToString([]byte(secret)),
		strings.ToUpper(secret),
		strings.ToLower(secret),
	}
	seen := make(map[string]bool, len(candidates))
	var out []string
	for _, c := range candidates {
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	return out
}

func Scan(h *HAR, secrets []Secret) Report {
	var report Report
	report.EntriesScanned = len(h.Log.Entries)

	for i, e := range h.Log.Entries {
		locations := map[string]string{
			"request URL":      e.Request.URL,
			"request headers":  headerBlob(e.Request.Headers),
			"response headers": headerBlob(e.Response.Headers),
		}
		if e.Request.PostData != nil {
			locations["request body"] = e.Request.PostData.Text
		}
		if e.Response.Content.Text != "" {
			body := e.Response.Content.Text
			if e.Response.Content.Encoding == "base64" {
				if decoded, err := base64.StdEncoding.DecodeString(body); err == nil {
					body = string(decoded)
				}
			}
			locations["response body"] = body
		}

		for loc, text := range locations {
			if text == "" {
				continue
			}
			for _, s := range secrets {
				for _, v := range variants(s.Value) {
					if v == "" {
						continue
					}
					if idx := strings.Index(text, v); idx != -1 {
						start := idx - 20
						if start < 0 {
							start = 0
						}
						end := idx + len(v) + 20
						if end > len(text) {
							end = len(text)
						}
						report.Findings = append(report.Findings, Finding{
							Secret:     s.Label,
							EntryIndex: i,
							Method:     e.Request.Method,
							URL:        e.Request.URL,
							Location:   loc,
							Snippet:    text[start:end],
						})
					}
				}
			}
		}

		if looksLikeCiphertext(e) || (e.Request.PostData != nil && looksHighEntropy(e.Request.PostData.Text)) {
			report.CiphertextLikely = true
		}
	}

	return report
}

func headerBlob(hs []Header) string {
	var b strings.Builder
	for _, h := range hs {
		b.WriteString(h.Name)
		b.WriteString(": ")
		b.WriteString(h.Value)
		b.WriteString("\n")
	}
	return b.String()
}

func looksLikeCiphertext(e Entry) bool {
	if e.Request.PostData == nil {
		return false
	}
	text := e.Request.PostData.Text
	if len(text) < 32 {
		return false
	}
	base64ish := 0
	for _, r := range text {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '+' || r == '/' || r == '=' {
			base64ish++
		}
	}
	return float64(base64ish)/float64(len(text)) > 0.9
}
