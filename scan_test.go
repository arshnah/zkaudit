package zkaudit

import (
	"testing"
)

func harWithPostData(text string) *HAR {
	var h HAR
	h.Log.Entries = []Entry{
		{
			Request: Request{
				Method: "POST",
				URL:    "https://example.com/api/drop",
				PostData: &struct {
					MimeType string `json:"mimeType"`
					Text     string `json:"text"`
				}{MimeType: "application/json", Text: text},
			},
		},
	}
	return &h
}

func TestNoDuplicateFindingsForLowercaseSecret(t *testing.T) {
	secret := "hello this is my real secret message"
	h := harWithPostData(`{"body":"` + secret + `"}`)

	report := Scan(h, []Secret{{Label: "message", Value: secret}})
	if len(report.Findings) != 1 {
		t.Fatalf("expected exactly 1 finding for a single leak, got %d (an all-lowercase secret with no special chars produces duplicate variants unless deduplicated): %+v", len(report.Findings), report.Findings)
	}
}

func TestFindsPlaintextInRequestBody(t *testing.T) {
	secret := "the actual secret message"
	h := harWithPostData(`{"content":"` + secret + `"}`)

	report := Scan(h, []Secret{{Label: "message", Value: secret}})
	if len(report.Findings) == 0 {
		t.Fatal("expected a finding, plaintext secret was sent verbatim in the request body")
	}
	if report.Findings[0].Location != "request body" {
		t.Fatalf("expected leak located in request body, got %q", report.Findings[0].Location)
	}
}

func TestNoFalsePositiveOnCiphertext(t *testing.T) {
	secret := "the actual secret message"
	ciphertextLooking := "U2FsdGVkX1+3vN9ZqK8mF2xJpL4wR7tY9cB1nH5gV0aE3sQ6uI8oP2dW4rT7yA1c"
	h := harWithPostData(`{"ciphertext":"` + ciphertextLooking + `"}`)

	report := Scan(h, []Secret{{Label: "message", Value: secret}})
	if len(report.Findings) != 0 {
		t.Fatalf("expected no findings against ciphertext-only payload, got %d: %+v", len(report.Findings), report.Findings)
	}
	if !report.CiphertextLikely {
		t.Error("expected the high-base64-density payload to be flagged as ciphertext-likely")
	}
}

func TestFindsKeyLeakedInURL(t *testing.T) {
	key := "my-super-secret-passphrase"
	var h HAR
	h.Log.Entries = []Entry{
		{Request: Request{Method: "GET", URL: "https://example.com/api/verify?key=" + key}},
	}

	report := Scan(&h, []Secret{{Label: "encryption key", Value: key}})
	if len(report.Findings) == 0 {
		t.Fatal("expected a finding, encryption key was leaked in the URL")
	}
	if report.Findings[0].Location != "request URL" {
		t.Fatalf("expected leak located in request URL, got %q", report.Findings[0].Location)
	}
}

func TestFindsSecretLeakedInResponseBody(t *testing.T) {
	secret := "leaked in the server response"
	var h HAR
	e := Entry{Request: Request{Method: "GET", URL: "https://example.com/api/echo"}}
	e.Response.Content.MimeType = "application/json"
	e.Response.Content.Text = `{"debug":"` + secret + `"}`
	h.Log.Entries = []Entry{e}

	report := Scan(&h, []Secret{{Label: "message", Value: secret}})
	if len(report.Findings) == 0 {
		t.Fatal("expected a finding, secret was echoed back in the response body")
	}
}

func TestCleanMultiEntryHARPassesEntirely(t *testing.T) {
	secret := "never sent anywhere"
	key := "never-sent-either"
	var h HAR
	h.Log.Entries = []Entry{
		harWithPostData("just some unrelated ciphertext blob AAAABBBBCCCCDDDDEEEEFFFF1234567890").Log.Entries[0],
		{Request: Request{Method: "GET", URL: "https://example.com/api/health"}},
	}

	report := Scan(&h, []Secret{{Label: "message", Value: secret}, {Label: "key", Value: key}})
	if len(report.Findings) != 0 {
		t.Fatalf("expected zero findings on a genuinely clean HAR, got %d: %+v", len(report.Findings), report.Findings)
	}
	if report.EntriesScanned != 2 {
		t.Fatalf("expected 2 entries scanned, got %d", report.EntriesScanned)
	}
}

func TestShortSecretsProduceCoincidentalFalsePositives(t *testing.T) {
	h := harWithPostData(`{"cache-control":"stale-while-revalidate"}`)

	report := Scan(h, []Secret{{Label: "message", Value: "hi"}})
	if len(report.Findings) == 0 {
		t.Fatal("expected 'hi' to coincidentally match inside 'while', this documents exactly why MinReliableSecretLength exists, a real audit run hit this against live traffic and got 6 false positives from a 2-character secret")
	}
}
