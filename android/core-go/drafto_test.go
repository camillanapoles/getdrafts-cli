package drafto

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/nerveband/drafts-applescript-cli/core"
)

// decodeDraft is the test-side counterpart of the JSON boundary: the Android
// side does exactly this (org.json) after receiving the string.
func decodeDraft(t *testing.T, s string) core.Draft {
	t.Helper()
	if s == "" {
		t.Fatal("expected draft JSON, got empty string")
	}
	var d core.Draft
	if err := json.Unmarshal([]byte(s), &d); err != nil {
		t.Fatalf("unmarshal draft %q: %v", s, err)
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
	raw, err := first.CreateDraftJSON("persisted from android", `["mobile"]`, false)
	if err != nil {
		t.Fatalf("CreateDraftJSON: %v", err)
	}
	created := decodeDraft(t, raw)
	if created.UUID == "" {
		t.Fatal("created draft has no UUID")
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second, err := NewAt(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer second.Close()

	gotRaw, err := second.GetDraftJSON(created.UUID)
	if err != nil {
		t.Fatalf("GetDraftJSON after reopen: %v", err)
	}
	got := decodeDraft(t, gotRaw)
	if got.Content != "persisted from android" {
		t.Fatalf("content = %q", got.Content)
	}
	if len(got.Tags) != 1 || got.Tags[0] != "mobile" {
		t.Fatalf("tags = %v", got.Tags)
	}
}

// A missing draft crosses the boundary as an empty string, not an error, so
// Kotlin can map it to null without parsing Go error text.
func TestGetDraftJSONMissingReturnsEmpty(t *testing.T) {
	engine := New()
	defer engine.Close()

	raw, err := engine.GetDraftJSON("00000000-0000-0000-0000-000000000000")
	if err != nil {
		t.Fatalf("GetDraftJSON(missing): %v", err)
	}
	if raw != "" {
		t.Fatalf("expected empty string for missing draft, got %q", raw)
	}
}

// New (in-memory) must stay isolated per engine and Close must be a no-op.
func TestNewInMemoryAndClose(t *testing.T) {
	a := New()
	b := New()

	if _, err := a.CreateDraftJSON("only in a", "", false); err != nil {
		t.Fatalf("create: %v", err)
	}
	raw, err := b.QueryDraftsJSON("all", "", "", 0)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if raw != "" {
		var drafts []core.Draft
		if err := json.Unmarshal([]byte(raw), &drafts); err != nil {
			t.Fatalf("unmarshal drafts: %v", err)
		}
		if len(drafts) != 0 {
			t.Fatalf("engine b sees %d drafts", len(drafts))
		}
	}
	if err := a.Close(); err != nil {
		t.Fatalf("Close on in-memory engine: %v", err)
	}
}

// Every method the Kotlin adapter calls must exist as a string/error-only
// signature. Methods mentioning other packages' types are dropped by gomobile
// WITHOUT any warning — that regression is exactly what this test prevents.
func TestBoundMethodsAreGomobileSafe(t *testing.T) {
	engine := New()
	defer engine.Close()

	created, err := engine.CreateDraftJSON("boundary survey", `["a","b"]`, true)
	if err != nil {
		t.Fatalf("CreateDraftJSON: %v", err)
	}
	d := decodeDraft(t, created)

	if _, err := engine.SetFlaggedJSON(d.UUID, false); err != nil {
		t.Fatalf("SetFlaggedJSON: %v", err)
	}
	if _, err := engine.AddTagsJSON(d.UUID, `["c"]`); err != nil {
		t.Fatalf("AddTagsJSON: %v", err)
	}
	if _, err := engine.ReplaceDraftJSON(d.UUID, "edited"); err != nil {
		t.Fatalf("ReplaceDraftJSON: %v", err)
	}
	if _, err := engine.QueryDraftsJSON("all", "", `["c"]`, 10); err != nil {
		t.Fatalf("QueryDraftsJSON: %v", err)
	}
	tags, err := engine.ListTagsJSON()
	if err != nil {
		t.Fatalf("ListTagsJSON: %v", err)
	}
	var tagList []string
	if err := json.Unmarshal([]byte(tags), &tagList); err != nil {
		t.Fatalf("unmarshal tags %q: %v", tags, err)
	}
	if len(tagList) == 0 {
		t.Fatal("expected tags after AddTagsJSON")
	}
	counts, err := engine.CountsJSON()
	if err != nil {
		t.Fatalf("CountsJSON: %v", err)
	}
	var c core.Counts
	if err := json.Unmarshal([]byte(counts), &c); err != nil {
		t.Fatalf("unmarshal counts %q: %v", counts, err)
	}
	if c.All == 0 {
		t.Fatalf("expected non-zero draft count, got %+v", c)
	}
	stepsJSON := `{"group":"Quick","steps":[{"type":"copy"}]}`
	if err := engine.RegisterAction("quickcopy", stepsJSON); err != nil {
		t.Fatalf("RegisterAction: %v", err)
	}
	res, err := engine.RunActionJSON("quickcopy", d.UUID)
	if err != nil {
		t.Fatalf("RunActionJSON: %v", err)
	}
	var run core.ActionRunResult
	if err := json.Unmarshal([]byte(res), &run); err != nil {
		t.Fatalf("unmarshal action result %q: %v", res, err)
	}
	if err := engine.ArchiveDraft(d.UUID); err != nil {
		t.Fatalf("ArchiveDraft: %v", err)
	}
	if err := engine.TrashDraft(d.UUID); err != nil {
		t.Fatalf("TrashDraft: %v", err)
	}
}

// NewAt with an unusable path must fail instead of silently degrading to
// memory (same rule the CLI follows).
func TestNewAtRejectsBadPath(t *testing.T) {
	if _, err := NewAt(filepath.Join(t.TempDir(), "missing-dir", "x.db")); err == nil {
		t.Fatal("expected error for unusable database path")
	}
}
