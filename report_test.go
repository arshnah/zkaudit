package zkaudit

import (
	"os"
	"strings"
	"testing"
)

func TestWriteMarkdownReportPass(t *testing.T) {
	report := Report{EntriesScanned: 3, CiphertextLikely: true}
	meta := AuditMeta{Target: "cipherdrop upload flow", Flows: []string{"upload"}, Date: "2026-08-22"}

	path := t.TempDir() + "/report.md"
	if err := WriteMarkdownReport(report, meta, path); err != nil {
		t.Fatalf("failed to write report: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read report back: %v", err)
	}
	content := string(data)

	if !strings.Contains(content, "PASS") {
		t.Error("expected report to say PASS when there are no findings")
	}
	if !strings.Contains(content, "cipherdrop upload flow") {
		t.Error("expected report to include the target name")
	}
	if !strings.Contains(content, "ciphertext") {
		t.Error("expected report to mention the ciphertext-likely signal")
	}
}

func TestWriteMarkdownReportFailListsFindings(t *testing.T) {
	report := Report{
		EntriesScanned: 1,
		Findings: []Finding{
			{Secret: "message", EntryIndex: 0, Method: "POST", URL: "https://example.com/api", Location: "request body", Snippet: "leaked here"},
		},
	}
	meta := AuditMeta{Target: "test target"}

	path := t.TempDir() + "/report.md"
	if err := WriteMarkdownReport(report, meta, path); err != nil {
		t.Fatalf("failed to write report: %v", err)
	}

	data, _ := os.ReadFile(path)
	content := string(data)

	if !strings.Contains(content, "FAIL") {
		t.Error("expected report to say FAIL when findings exist")
	}
	if !strings.Contains(content, "leaked here") {
		t.Error("expected report to include the actual leak evidence, not just the verdict")
	}
}

func TestWriteBadgeSVGReflectsVerdict(t *testing.T) {
	passPath := t.TempDir() + "/pass.svg"
	if err := WriteBadgeSVG(true, passPath); err != nil {
		t.Fatalf("failed to write pass badge: %v", err)
	}
	passData, _ := os.ReadFile(passPath)
	if !strings.Contains(string(passData), "PASS") {
		t.Error("expected pass badge SVG to contain PASS text")
	}
	if !strings.HasPrefix(strings.TrimSpace(string(passData)), "<svg") {
		t.Error("expected badge output to actually be an SVG")
	}

	failPath := t.TempDir() + "/fail.svg"
	if err := WriteBadgeSVG(false, failPath); err != nil {
		t.Fatalf("failed to write fail badge: %v", err)
	}
	failData, _ := os.ReadFile(failPath)
	if !strings.Contains(string(failData), "FAIL") {
		t.Error("expected fail badge SVG to contain FAIL text")
	}
}
