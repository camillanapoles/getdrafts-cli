package core

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// newTestSQLiteStore returns a SQLiteStore backed by a temp file.
func newTestSQLiteStore(t *testing.T) *SQLiteStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSQLiteCreateAndGet(t *testing.T) {
	s := newTestSQLiteStore(t)
	ctx := context.Background()

	d, err := s.Create(ctx, "Hello world", CreateOptions{Tags: []string{"work"}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if d.UUID == "" {
		t.Fatal("empty uuid")
	}
	if d.Title != "Hello world" {
		t.Fatalf("title = %q", d.Title)
	}
	if d.Folder != "inbox" {
		t.Fatalf("folder = %q", d.Folder)
	}
	if len(d.Tags) != 1 || d.Tags[0] != "work" {
		t.Fatalf("tags = %v", d.Tags)
	}

	got, err := s.Get(ctx, d.UUID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Content != "Hello world" {
		t.Fatalf("content = %q", got.Content)
	}
	if got.AccessedAt == "" {
		t.Fatal("accessed_at not set on Get")
	}
}

func TestSQLiteTitleFromFirstLine(t *testing.T) {
	s := newTestSQLiteStore(t)
	ctx := context.Background()

	d, _ := s.Create(ctx, "First line\nsecond line", CreateOptions{})
	if d.Title != "First line" {
		t.Fatalf("title = %q", d.Title)
	}
}

func TestSQLiteArchiveTrash(t *testing.T) {
	s := newTestSQLiteStore(t)
	ctx := context.Background()

	d, _ := s.Create(ctx, "note", CreateOptions{})
	if err := s.Archive(ctx, d.UUID); err != nil {
		t.Fatalf("archive: %v", err)
	}
	got, _ := s.Get(ctx, d.UUID)
	if !got.IsArchived || got.Folder != "archive" {
		t.Fatalf("not archived: %+v", got)
	}

	if err := s.Trash(ctx, d.UUID); err != nil {
		t.Fatalf("trash: %v", err)
	}
	got, _ = s.Get(ctx, d.UUID)
	if !got.IsTrashed || got.Folder != "trash" {
		t.Fatalf("not trashed: %+v", got)
	}
	if got.TrashedAt == "" {
		t.Fatal("trashed_at not set")
	}
}

func TestSQLiteFlagAndTags(t *testing.T) {
	s := newTestSQLiteStore(t)
	ctx := context.Background()

	d, _ := s.Create(ctx, "flag me", CreateOptions{})
	if _, err := s.SetFlagged(ctx, d.UUID, true); err != nil {
		t.Fatalf("flag: %v", err)
	}
	got, _ := s.Get(ctx, d.UUID)
	if !got.IsFlagged {
		t.Fatal("not flagged")
	}

	if _, err := s.AddTags(ctx, d.UUID, []string{"a", "b"}); err != nil {
		t.Fatalf("tags: %v", err)
	}
	got, _ = s.Get(ctx, d.UUID)
	if len(got.Tags) != 2 {
		t.Fatalf("tags = %v", got.Tags)
	}

	tags, _ := s.ListTags(ctx)
	if len(tags) != 2 {
		t.Fatalf("listtags = %v", tags)
	}

	// SetTags replaces.
	if _, err := s.SetTags(ctx, d.UUID, []string{"x"}); err != nil {
		t.Fatalf("settags: %v", err)
	}
	got, _ = s.Get(ctx, d.UUID)
	if len(got.Tags) != 1 || got.Tags[0] != "x" {
		t.Fatalf("tags after set = %v", got.Tags)
	}
}

func TestSQLiteQueryFilters(t *testing.T) {
	s := newTestSQLiteStore(t)
	ctx := context.Background()

	s.Create(ctx, "alpha", CreateOptions{Tags: []string{"work"}})
	s.Create(ctx, "beta", CreateOptions{Flagged: true})
	s.Create(ctx, "gamma", CreateOptions{Folder: FolderArchive})

	inbox, _ := s.Query(ctx, Query{Filter: FilterInbox})
	if len(inbox) != 2 {
		t.Fatalf("inbox count = %d", len(inbox))
	}

	flagged, _ := s.Query(ctx, Query{Filter: FilterFlagged})
	if len(flagged) != 1 || !flagged[0].IsFlagged {
		t.Fatalf("flagged = %d", len(flagged))
	}

	archive, _ := s.Query(ctx, Query{Filter: FilterArchive})
	if len(archive) != 1 {
		t.Fatalf("archive = %d", len(archive))
	}

	tagged, _ := s.Query(ctx, Query{Filter: FilterInbox, Tags: []string{"work"}})
	if len(tagged) != 1 || tagged[0].Content != "alpha" {
		t.Fatalf("tagged = %v", contents(tagged))
	}

	search, _ := s.Query(ctx, Query{Filter: FilterAll, Search: "beta"})
	if len(search) != 1 {
		t.Fatalf("search = %d", len(search))
	}
}

func TestSQLiteSearchFTS(t *testing.T) {
	s := newTestSQLiteStore(t)
	ctx := context.Background()

	s.Create(ctx, "the quick brown fox", CreateOptions{})
	s.Create(ctx, "lazy dog sleeping", CreateOptions{})
	s.Create(ctx, "fox and hound", CreateOptions{})

	// Full-text search via FTS5.
	r1, _ := s.Query(ctx, Query{Filter: FilterAll, Search: "fox"})
	if len(r1) != 2 {
		t.Fatalf("search fox = %d, want 2", len(r1))
	}

	// Phrase search.
	r2, _ := s.Query(ctx, Query{Filter: FilterAll, Search: "quick brown"})
	if len(r2) != 1 {
		t.Fatalf("search 'quick brown' = %d, want 1", len(r2))
	}
}

func TestSQLiteAppendPrependReplace(t *testing.T) {
	s := newTestSQLiteStore(t)
	ctx := context.Background()

	d, _ := s.Create(ctx, "middle", CreateOptions{})
	s.Prepend(ctx, d.UUID, "head")
	s.Append(ctx, d.UUID, "tail")

	got, _ := s.Get(ctx, d.UUID)
	if got.Content != "head\nmiddle\ntail" {
		t.Fatalf("content = %q", got.Content)
	}

	s.Replace(ctx, d.UUID, "replaced")
	got, _ = s.Get(ctx, d.UUID)
	if got.Content != "replaced" || got.Title != "replaced" {
		t.Fatalf("after replace = %+v", got)
	}
}

func TestSQLiteSorting(t *testing.T) {
	s := newTestSQLiteStore(t)
	ctx := context.Background()

	base := time.Unix(1700000000, 0)
	counter := 0
	orig := NowFunc
	NowFunc = func() time.Time {
		counter++
		return base.Add(time.Duration(counter) * time.Second)
	}
	defer func() { NowFunc = orig }()

	s.Create(ctx, "c1", CreateOptions{})
	s.Create(ctx, "c2", CreateOptions{})
	s.Create(ctx, "c3", CreateOptions{})

	asc, _ := s.Query(ctx, Query{Filter: FilterAll, Sort: SortCreated})
	if len(asc) != 3 || asc[0].Content != "c1" || asc[2].Content != "c3" {
		t.Fatalf("asc = %v", contents(asc))
	}

	desc, _ := s.Query(ctx, Query{Filter: FilterAll, Sort: SortCreated, SortDescending: true})
	if len(desc) != 3 || desc[0].Content != "c3" || desc[2].Content != "c1" {
		t.Fatalf("desc = %v", contents(desc))
	}
}

func TestSQLiteWorkspaces(t *testing.T) {
	s := newTestSQLiteStore(t)
	ctx := context.Background()

	if err := s.SaveWorkspace(ctx, Workspace{Name: "Work", Folder: "inbox", Tags: []string{"work"}}); err != nil {
		t.Fatalf("save workspace: %v", err)
	}
	if err := s.SetActiveWorkspace(ctx, "Work"); err != nil {
		t.Fatalf("set active: %v", err)
	}

	d, _ := s.Create(ctx, "task", CreateOptions{Tags: []string{"work"}})
	if d.Workspace != "Work" {
		t.Fatalf("workspace = %q", d.Workspace)
	}

	res, _ := s.Query(ctx, Query{Workspace: "Work"})
	if len(res) != 1 || res[0].UUID != d.UUID {
		t.Fatalf("workspace query = %v", contents(res))
	}

	if _, err := s.Query(ctx, Query{Workspace: "missing"}); err == nil {
		t.Fatal("expected workspace not found")
	}
}

func TestSQLiteCounts(t *testing.T) {
	s := newTestSQLiteStore(t)
	ctx := context.Background()

	s.Create(ctx, "a", CreateOptions{})
	s.Create(ctx, "b", CreateOptions{Flagged: true})
	s.Create(ctx, "c", CreateOptions{Folder: FolderArchive})
	s.Create(ctx, "d", CreateOptions{})
	s.Trash(ctx, mustCreateSQL(t, s, ctx, "e"))

	c, _ := s.Counts(ctx)
	if c.Inbox != 3 || c.Flagged != 1 || c.Archive != 1 || c.Trash != 1 || c.All != 4 {
		t.Fatalf("counts = %+v", c)
	}
}

func TestSQLiteEmptyTrash(t *testing.T) {
	s := newTestSQLiteStore(t)
	ctx := context.Background()

	s.Create(ctx, "keep", CreateOptions{})
	s.Trash(ctx, mustCreateSQL(t, s, ctx, "delete me"))

	if err := s.EmptyTrash(ctx); err != nil {
		t.Fatalf("empty trash: %v", err)
	}

	all, _ := s.Query(ctx, Query{Filter: FilterAll})
	if len(all) != 1 {
		t.Fatalf("after empty trash = %d, want 1", len(all))
	}
}

func TestSQLitePurgeTrash(t *testing.T) {
	s := newTestSQLiteStore(t)
	ctx := context.Background()

	// Disable auto-retention for explicit purge testing.
	s.SetTrashRetention(0)

	s.Create(ctx, "old", CreateOptions{})
	oldUUID := mustCreateSQL(t, s, ctx, "old2")
	s.Trash(ctx, oldUUID)
	// Simulate old TrashedAt by updating directly.
	oldTS := time.Now().Add(-40 * 24 * time.Hour).Format(timeLayout)
	if _, err := s.db.Exec(`UPDATE drafts SET trashed_at = ? WHERE uuid = ?`, oldTS, oldUUID); err != nil {
		t.Fatalf("update trashed_at: %v", err)
	}

	s.Create(ctx, "recent", CreateOptions{})
	recentUUID := mustCreateSQL(t, s, ctx, "recent2")
	s.Trash(ctx, recentUUID)

	n, err := s.PurgeTrash(ctx, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if n != 1 {
		t.Fatalf("purged = %d, want 1", n)
	}

	// The old draft is gone; the recent one remains.
	_, err = s.Get(ctx, oldUUID)
	if err == nil {
		t.Fatal("old draft should be purged")
	}
	if _, err := s.Get(ctx, recentUUID); err != nil {
		t.Fatalf("recent draft should survive: %v", err)
	}
}

func TestSQLiteDelete(t *testing.T) {
	s := newTestSQLiteStore(t)
	ctx := context.Background()

	d, _ := s.Create(ctx, "to delete", CreateOptions{Tags: []string{"temp"}})
	if err := s.Delete(ctx, d.UUID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.Get(ctx, d.UUID); err == nil {
		t.Fatal("draft should be deleted")
	}
	// Tags should be cleaned up.
	tags, _ := s.ListTags(ctx)
	if len(tags) != 0 {
		t.Fatalf("tags after delete = %v", tags)
	}
}

func TestSQLiteTrashAutoPurgeOnQuery(t *testing.T) {
	s := newTestSQLiteStore(t)
	ctx := context.Background()

	// Default retention is 30 days.
	oldUUID := mustCreateSQL(t, s, ctx, "ancient")
	s.Trash(ctx, oldUUID)
	oldTS := time.Now().Add(-40 * 24 * time.Hour).Format(timeLayout)
	if _, err := s.db.Exec(`UPDATE drafts SET trashed_at = ? WHERE uuid = ?`, oldTS, oldUUID); err != nil {
		t.Fatalf("update: %v", err)
	}

	// A Query call should auto-purge expired trash.
	all, _ := s.Query(ctx, Query{Filter: FilterAll})
	if len(all) != 0 {
		t.Fatalf("expected auto-purge, got %d drafts", len(all))
	}
}

func mustCreateSQL(t *testing.T, s *SQLiteStore, ctx context.Context, content string) string {
	t.Helper()
	d, err := s.Create(ctx, content, CreateOptions{})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return d.UUID
}
