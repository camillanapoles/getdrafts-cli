package drafto

import (
	"path/filepath"
	"testing"
)

// NewAt must persist drafts across engine instances: closing the engine and
// reopening the same database path has to return the draft. This is the
// core of the Android persistence gap (G1 in docs/drafto/06-HANDOFF.md §2.1).
func TestNewAtPersistsAcrossInstances(t *testing.T) {
	path := filepath.Join(t.TempDir(), "drafto.db")

	first, err := NewAt(path)
	if err != nil {
		t.Fatalf("NewAt: %v", err)
	}
	created, err := first.CreateDraft("persisted from android", []string{"mobile"}, false)
	if err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second, err := NewAt(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer second.Close()

	got, err := second.GetDraft(created.UUID)
	if err != nil {
		t.Fatalf("GetDraft after reopen: %v", err)
	}
	if got.Content != "persisted from android" {
		t.Fatalf("content = %q", got.Content)
	}
	if len(got.Tags) != 1 || got.Tags[0] != "mobile" {
		t.Fatalf("tags = %v", got.Tags)
	}
}

// New (in-memory) must stay isolated per engine and Close must be a no-op.
func TestNewInMemoryAndClose(t *testing.T) {
	a := New()
	b := New()

	if _, err := a.CreateDraft("only in a", nil, false); err != nil {
		t.Fatalf("create: %v", err)
	}
	drafts, err := b.QueryDrafts("all", "", nil, 0)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(drafts) != 0 {
		t.Fatalf("engine b sees %d drafts", len(drafts))
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
