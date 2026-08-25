package zkaudit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/arshnah/detsim"
)

const testSecret = "the exact message I typed into the app"

func sampleHARBytes(t *testing.T) []byte {
	t.Helper()
	h := &HAR{}
	h.Log.Entries = []Entry{
		{
			StartedDateTime: "2026-01-01T00:00:00.000Z",
			Request: Request{
				Method: "POST",
				URL:    "https://example.com/api/upload",
				Headers: []Header{
					{Name: "Content-Type", Value: "application/json"},
					{Name: "Cookie", Value: "session=abc123"},
				},
				Cookies: []Cookie{{Name: "session", Value: "abc123"}},
				PostData: &struct {
					MimeType string `json:"mimeType"`
					Text     string `json:"text"`
				}{MimeType: "application/json", Text: `{"ciphertext":"U2FsdGVkX1+3vN9ZqK8mF2xJpL4wR7tY9cB1nH5gV0aE3sQ6uI8oP2dW4rT7yA1c"}`},
			},
			Response: Response{
				Status:  200,
				Headers: []Header{{Name: "Set-Cookie", Value: "session=abc123"}},
				Content: struct {
					MimeType string `json:"mimeType"`
					Text     string `json:"text"`
					Encoding string `json:"encoding"`
				}{MimeType: "application/json", Text: `{"ok":true}`},
			},
		},
	}

	path := filepath.Join(t.TempDir(), "clean.har")
	if err := SaveHAR(h, path); err != nil {
		t.Fatalf("SaveHAR: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	return data
}

func scenario(t *testing.T, seed int64, profile detsim.FaultProfile, clean []byte) {
	t.Helper()

	fs := detsim.NewFaultyStorage(seed, profile)
	fs.WriteAt(clean, 0)
	fs.Sync()

	buf := make([]byte, len(clean)+256)
	n, _ := fs.ReadAt(buf, 0)
	corrupted := buf[:n]

	path := filepath.Join(t.TempDir(), "corrupted.har")
	if err := os.WriteFile(path, corrupted, 0o644); err != nil {
		t.Fatalf("seed %d: WriteFile: %v", seed, err)
	}

	h, err := LoadHAR(path)
	if err != nil {
		return
	}

	report := Scan(h, []Secret{{Label: "message", Value: testSecret}})
	redacted := Redact(h)

	reportPath := filepath.Join(t.TempDir(), "audit.md")
	if err := WriteMarkdownReport(report, AuditMeta{Target: "test", Date: "2026-01-01"}, reportPath); err != nil {
		t.Fatalf("seed %d: WriteMarkdownReport: %v", seed, err)
	}
	badgePath := filepath.Join(t.TempDir(), "badge.svg")
	if err := WriteBadgeSVG(len(report.Findings) == 0, badgePath); err != nil {
		t.Fatalf("seed %d: WriteBadgeSVG: %v", seed, err)
	}
	_ = MergeHARs(h, redacted)
}

func TestManySeedsNeverPanicOnCorruptedHAR(t *testing.T) {
	clean := sampleHARBytes(t)
	profile := detsim.FaultProfile{TornWriteRate: 0.1, CorruptByteRate: 0.08, SkipSyncRate: 0.05}
	for seed := int64(1); seed <= 3000; seed++ {
		scenario(t, seed, profile, clean)
	}
}

func TestScanIsDeterministicOnIdenticalCorruptedInput(t *testing.T) {
	clean := sampleHARBytes(t)
	profile := detsim.FaultProfile{TornWriteRate: 0.15, CorruptByteRate: 0.1, SkipSyncRate: 0.1}

	fs := detsim.NewFaultyStorage(42, profile)
	fs.WriteAt(clean, 0)
	fs.Sync()
	buf := make([]byte, len(clean)+256)
	n, _ := fs.ReadAt(buf, 0)
	corrupted := buf[:n]

	run := func() *Report {
		path := filepath.Join(t.TempDir(), "corrupted.har")
		if err := os.WriteFile(path, corrupted, 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		h, err := LoadHAR(path)
		if err != nil {
			return nil
		}
		r := Scan(h, []Secret{{Label: "message", Value: testSecret}})
		return &r
	}

	a, b := run(), run()
	if (a == nil) != (b == nil) {
		t.Fatalf("determinism broke on parse success: a=%v b=%v", a, b)
	}
	if a == nil {
		return
	}
	if len(a.Findings) != len(b.Findings) || a.EntriesScanned != b.EntriesScanned || a.CiphertextLikely != b.CiphertextLikely {
		t.Fatalf("replaying the same corrupted bytes produced different reports: %+v vs %+v", a, b)
	}
}
