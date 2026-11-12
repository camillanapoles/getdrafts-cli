package drafto

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// wireDraft mirrors the JSON shape the boundary crosses to Kotlin. The tests
// decode into this instead of core.Draft on purpose: it pins the *wire*
// contract, so a renamed Go field that is not reflected in the boundary output
// fails here rather than in the app at runtime.
type wireDraft struct {
	UUID    string   `json:"uuid"`
	Content string   `json:"content"`
	Tags    []string `json:"tags"`
}

func decodeDraft(t *testing.T, payload string) wireDraft {
	t.Helper()
	var d wireDraft
	if err := json.Unmarshal([]byte(payload), &d); err != nil {
		t.Fatalf("boundary returned non-JSON: %v (%q)", err, payload)
	}
	return d
}

// NewAt must persist drafts across engine instances: closing the engine and
// reopening the same database path has to return the draft. This is the
// core of the Android persistence gap (G1 in docs/drafto/06-HANDOFF.md §2.1).
func TestNewAtPersistsAcrossInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "drafto.db")

	first, err := NewAt(path)
	if err != nil {
		t.Fatalf("NewAt: %v", err)
	}
	createdJSON, err := first.CreateDraftJSON("persisted from android", `["mobile"]`, false)
	if err != nil {
		t.Fatalf("CreateDraftJSON: %v", err)
	}
	created := decodeDraft(t, createdJSON)
	if created.UUID == "" {
		t.Fatalf("CreateDraftJSON returned no uuid: %q", createdJSON)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second, err := NewAt(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer second.Close()

	gotJSON, err := second.GetDraftJSON(created.UUID)
	if err != nil {
		t.Fatalf("GetDraftJSON after reopen: %v", err)
	}
	got := decodeDraft(t, gotJSON)
	if got.Content != "persisted from android" {
		t.Fatalf("content = %q", got.Content)
	}
	if len(got.Tags) != 1 || got.Tags[0] != "mobile" {
		t.Fatalf("tags = %v", got.Tags)
	}

	// The "not found" convention is "" with no error — Kotlin reads that as
	// "no draft", and the app relies on it to close the editor.
	if missing, err := second.GetDraftJSON("00000000-0000-0000-0000-000000000000"); err != nil || missing != "" {
		t.Fatalf("GetDraftJSON(unknown) = %q, %v; want \"\", nil", missing, err)
	}
}

// New (in-memory) must stay isolated per engine and Close must be a no-op.
// An empty result set crosses the boundary as "" as well.
func TestNewInMemoryAndClose(t *testing.T) {
	a := New()
	b := New()

	if _, err := a.CreateDraftJSON("only in a", "", false); err != nil {
		t.Fatalf("create: %v", err)
	}
	drafts, err := b.QueryDraftsJSON("all", "", "", 0)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if strings.TrimSpace(drafts) != "" {
		t.Fatalf("engine b sees drafts: %q", drafts)
	}

	// The other engine keeps its own data, and the JSON list is a real array.
	mine, err := a.QueryDraftsJSON("all", "", "", 0)
	if err != nil {
		t.Fatalf("query a: %v", err)
	}
	var decoded []wireDraft
	if err := json.Unmarshal([]byte(mine), &decoded); err != nil {
		t.Fatalf("QueryDraftsJSON returned non-JSON array: %v (%q)", err, mine)
	}
	if len(decoded) != 1 || decoded[0].Content != "only in a" {
		t.Fatalf("engine a sees %s", mine)
	}

	if err := a.Close(); err != nil {
		t.Fatalf("Close on in-memory engine: %v", err)
	}
}

// NewAt with an unusable path must fail instead of silently degrading to
// memory (same rule the CLI follows).
func TestNewAtRejectsBadPath(t *testing.T) {
	if _, err := NewAt(filepath.Join(t.TempDir(), "missing-dir", "x.db")); err == nil {
		t.Fatal("expected error for unusable database path")
	}
}

// tagsJSON is validated at the boundary: malformed JSON is INVALID_INPUT, not
// a silently ignored tag list.
func TestCreateDraftRejectsMalformedTags(t *testing.T) {
	c := New()
	defer c.Close()

	if _, err := c.CreateDraftJSON("x", `{"not":"an array"}`, false); err == nil {
		t.Fatal("expected error for malformed tagsJSON")
	}
}
