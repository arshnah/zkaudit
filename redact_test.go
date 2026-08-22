package zkaudit

import "testing"

func TestRedactStripsCookieAndAuthHeaders(t *testing.T) {
	h := &HAR{}
	h.Log.Entries = []Entry{
		{
			Request: Request{
				Method: "GET",
				URL:    "https://example.com/api",
				Headers: []Header{
					{Name: "Cookie", Value: "session=super-secret-token"},
					{Name: "Authorization", Value: "Bearer abc123"},
					{Name: "Content-Type", Value: "application/json"},
				},
				Cookies: []Cookie{{Name: "session", Value: "super-secret-token"}},
			},
		},
	}

	out := Redact(h)
	req := out.Log.Entries[0].Request

	for _, header := range req.Headers {
		switch header.Name {
		case "Cookie", "Authorization":
			if header.Value != RedactedValue {
				t.Errorf("expected %s header to be redacted, got %q", header.Name, header.Value)
			}
		case "Content-Type":
			if header.Value != "application/json" {
				t.Errorf("expected non-sensitive header to survive untouched, got %q", header.Value)
			}
		}
	}
	if req.Cookies[0].Value != RedactedValue {
		t.Errorf("expected cookie value to be redacted, got %q", req.Cookies[0].Value)
	}
	if req.Cookies[0].Name != "session" {
		t.Error("expected cookie name to survive, only the value should be redacted")
	}
}

func TestRedactDoesNotMutateOriginal(t *testing.T) {
	h := &HAR{}
	h.Log.Entries = []Entry{
		{Request: Request{Headers: []Header{{Name: "Cookie", Value: "do-not-touch-me"}}}},
	}

	Redact(h)

	if h.Log.Entries[0].Request.Headers[0].Value != "do-not-touch-me" {
		t.Fatal("Redact must not mutate the original HAR, callers may still need the raw version for scanning")
	}
}
