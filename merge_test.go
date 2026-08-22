package zkaudit

import "testing"

func TestMergeHARsCombinesEntries(t *testing.T) {
	a := &HAR{}
	a.Log.Entries = []Entry{{Request: Request{URL: "https://example.com/upload"}}}

	b := &HAR{}
	b.Log.Entries = []Entry{
		{Request: Request{URL: "https://example.com/view"}},
		{Request: Request{URL: "https://example.com/share"}},
	}

	merged := MergeHARs(a, b)
	if len(merged.Log.Entries) != 3 {
		t.Fatalf("expected 3 combined entries, got %d", len(merged.Log.Entries))
	}
	if merged.Log.Entries[0].Request.URL != "https://example.com/upload" {
		t.Error("expected entries from the first HAR to come first")
	}
	if merged.Log.Entries[2].Request.URL != "https://example.com/share" {
		t.Error("expected entries from the second HAR to follow, in order")
	}
}

func TestMergeHARsHandlesNil(t *testing.T) {
	a := &HAR{}
	a.Log.Entries = []Entry{{Request: Request{URL: "https://example.com/only"}}}

	merged := MergeHARs(a, nil)
	if len(merged.Log.Entries) != 1 {
		t.Fatalf("expected a nil HAR in the list to be skipped safely, got %d entries", len(merged.Log.Entries))
	}
}
