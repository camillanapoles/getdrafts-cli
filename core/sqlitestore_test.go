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

// ---- Regression tests for the review findings on PR #11 --------------------

// Search parity: MemoryStore matches case-insensitive substrings over
// content, title and tags. FTS5 alone would only match whole tokens.
func TestSQLiteSearchParityWithMemorySubstring(t *testing.T) {
	s := newTestSQLiteStore(t)
	ctx := context.Background()

	s.Create(ctx, "the quick brown foxes", CreateOptions{Tags: []string{"wildlife"}})
	s.Create(ctx, "lazy dog", CreateOptions{})

	// Substring inside a word (FTS5 token match would miss it).
	sub, err := s.Query(ctx, Query{Filter: FilterAll, Search: "fox"})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(sub) != 1 {
		t.Fatalf("substring search 'fox' = %d, want 1", len(sub))
	}

	// Case-insensitive.
	upper, _ := s.Query(ctx, Query{Filter: FilterAll, Search: "QUICK"})
	if len(upper) != 1 {
		t.Fatalf("case-insensitive search = %d, want 1", len(upper))
	}

	// Tag matches (parity with MemoryStore.matchesSearch).
	byTag, _ := s.Query(ctx, Query{Filter: FilterAll, Search: "wildlife"})
	if len(byTag) != 1 {
		t.Fatalf("tag search = %d, want 1", len(byTag))
	}

	// No match.
	none, _ := s.Query(ctx, Query{Filter: FilterAll, Search: "zebra"})
	if len(none) != 0 {
		t.Fatalf("search 'zebra' = %d, want 0", len(none))
	}
}

// Two independent :memory: stores must not see each other's data.
func TestSQLiteMemoryStoresAreIsolated(t *testing.T) {
	ctx := context.Background()
	a, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("open a: %v", err)
	}
	defer a.Close()
	b, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("open b: %v", err)
	}
	defer b.Close()

	if _, err := a.Create(ctx, "only in a", CreateOptions{}); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := b.Query(ctx, Query{Filter: FilterAll})
	if err != nil {
		t.Fatalf("query b: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("store b sees %d drafts from store a", len(got))
	}
}

// In-memory SQLite must keep a single database across operations.
func TestSQLiteMemoryPathPersistsAcrossCalls(t *testing.T) {
	s, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteStore(:memory:): %v", err)
	}
	defer s.Close()
	ctx := context.Background()

	d, err := s.Create(ctx, "kept", CreateOptions{})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.Get(ctx, d.UUID)
	if err != nil {
		t.Fatalf("get after create: %v", err)
	}
	if got.Content != "kept" {
		t.Fatalf("content = %q", got.Content)
	}
	list, _ := s.Query(ctx, Query{Filter: FilterAll})
	if len(list) != 1 {
		t.Fatalf("query = %d, want 1", len(list))
	}
}

// Update must persist every field it returns (created_at, permalink and geo
// data included) so a subsequent Get agrees with the Update result.
func TestSQLiteUpdateRoundTrip(t *testing.T) {
	s := newTestSQLiteStore(t)
	ctx := context.Background()

	d, _ := s.Create(ctx, "original", CreateOptions{})
	updated, err := s.Update(ctx, d.UUID, func(x *Draft) error {
		x.CreatedLatitude = -8.05
		x.CreatedLongitude = -34.88
		x.ModifiedLatitude = -8.06
		x.ModifiedLongitude = -34.89
		return nil
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}

	got, err := s.Get(ctx, d.UUID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.CreatedAt != updated.CreatedAt {
		t.Fatalf("created_at get=%q update=%q", got.CreatedAt, updated.CreatedAt)
	}
	if got.Permalink != updated.Permalink || got.Permalink == "" {
		t.Fatalf("permalink get=%q update=%q", got.Permalink, updated.Permalink)
	}
	if got.CreatedLatitude != -8.05 || got.CreatedLongitude != -34.88 {
		t.Fatalf("created geo = %v,%v", got.CreatedLatitude, got.CreatedLongitude)
	}
	if got.ModifiedLatitude != -8.06 || got.ModifiedLongitude != -34.89 {
		t.Fatalf("modified geo = %v,%v", got.ModifiedLatitude, got.ModifiedLongitude)
	}
}

// Workspace tags round-trip even when a tag contains a comma.
func TestSQLiteWorkspaceTagsWithCommas(t *testing.T) {
	s := newTestSQLiteStore(t)
	ctx := context.Background()

	want := []string{"a,b", "plain", "c"}
	if err := s.SaveWorkspace(ctx, Workspace{Name: "WS", Folder: "inbox", Tags: want, OmitTags: []string{"x,y"}}); err != nil {
		t.Fatalf("save: %v", err)
	}

	list, err := s.Workspaces(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("workspaces = %d", len(list))
	}
	got := list[0]
	if len(got.Tags) != len(want) {
		t.Fatalf("tags = %v, want %v", got.Tags, want)
	}
	for i := range want {
		if got.Tags[i] != want[i] {
			t.Fatalf("tags = %v, want %v", got.Tags, want)
		}
	}
	if len(got.OmitTags) != 1 || got.OmitTags[0] != "x,y" {
		t.Fatalf("omit_tags = %v", got.OmitTags)
	}
}

// A legacy comma-joined workspace row (written before the CSV encoding) must
// still decode correctly.
func TestSQLiteWorkspaceLegacyTagsDecode(t *testing.T) {
	s := newTestSQLiteStore(t)
	ctx := context.Background()

	if _, err := s.db.Exec(`INSERT INTO workspaces(name, folder, tags) VALUES ('legacy','inbox','one,two')`); err != nil {
		t.Fatalf("insert legacy: %v", err)
	}
	list, err := s.Workspaces(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || len(list[0].Tags) != 2 || list[0].Tags[0] != "one" || list[0].Tags[1] != "two" {
		t.Fatalf("legacy tags = %+v", list)
	}
}

// Tag loading must stay within SQLite's host-parameter limit for wide result
// sets (batching in loadTagsQuery).
func TestSQLiteQueryManyDraftsTags(t *testing.T) {
	s := newTestSQLiteStore(t)
	ctx := context.Background()

	const n = 520 // > tagBatchSize
	for i := 0; i < n; i++ {
		if _, err := s.Create(ctx, "bulk", CreateOptions{Tags: []string{"bulk"}}); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	all, err := s.Query(ctx, Query{Filter: FilterAll})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(all) != n {
		t.Fatalf("query = %d, want %d", len(all), n)
	}
	for _, d := range all {
		if len(d.Tags) != 1 || d.Tags[0] != "bulk" {
			t.Fatalf("draft %s tags = %v", d.UUID, d.Tags)
		}
	}
}

// Purge must actually delete the expired row (FilterAll would hide it even
// without the purge, so assert on Get).
func TestSQLiteTrashAutoPurgeDeletesRow(t *testing.T) {
	s := newTestSQLiteStore(t)
	ctx := context.Background()

	oldUUID := mustCreateSQL(t, s, ctx, "ancient")
	s.Trash(ctx, oldUUID)
	oldTS := time.Now().Add(-40 * 24 * time.Hour).Format(timeLayout)
	if _, err := s.db.Exec(`UPDATE drafts SET trashed_at = ? WHERE uuid = ?`, oldTS, oldUUID); err != nil {
		t.Fatalf("update: %v", err)
	}

	if _, err := s.Query(ctx, Query{Filter: FilterAll}); err != nil {
		t.Fatalf("query: %v", err)
	}
	if _, err := s.Get(ctx, oldUUID); err == nil {
		t.Fatal("expired trash draft should have been deleted")
	}
	trash, _ := s.Query(ctx, Query{Filter: FilterTrash})
	if len(trash) != 0 {
		t.Fatalf("trash = %d, want 0", len(trash))
	}
}

// SQLiteStore must satisfy TrashPruner and the TrashRetention knobs.
func TestSQLiteRetentionConfig(t *testing.T) {
	s := newTestSQLiteStore(t)
	if s.TrashRetention() != defaultTrashRetention {
		t.Fatalf("default retention = %v", s.TrashRetention())
	}
	s.SetTrashRetention(0)
	if s.TrashRetention() != 0 {
		t.Fatalf("retention after Set(0) = %v", s.TrashRetention())
	}
	s.SetTrashRetention(-1)
	if s.TrashRetention() != 0 {
		t.Fatalf("negative retention should clamp to 0, got %v", s.TrashRetention())
	}
}
