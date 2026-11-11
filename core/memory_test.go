package core

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMemoryCreateAndGet(t *testing.T) {
	s := NewMemoryStore()
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
}

func TestMemoryTitleFromFirstLine(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	d, _ := s.Create(ctx, "First line\nsecond line", CreateOptions{})
	if d.Title != "First line" {
		t.Fatalf("title = %q", d.Title)
	}
}

func TestMemoryArchiveTrash(t *testing.T) {
	s := NewMemoryStore()
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
}

func TestMemoryFlagAndTags(t *testing.T) {
	s := NewMemoryStore()
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
}

func TestMemoryQueryFilters(t *testing.T) {
	s := NewMemoryStore()
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

func TestMemoryAppendPrependReplace(t *testing.T) {
	s := NewMemoryStore()
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

func TestMemorySorting(t *testing.T) {
	s := NewMemoryStore()
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

func TestMemoryWorkspaces(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	s.SaveWorkspace(Workspace{Name: "Work", Folder: "inbox", Tags: []string{"work"}})
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

func TestMemoryCounts(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	s.Create(ctx, "a", CreateOptions{})
	s.Create(ctx, "b", CreateOptions{Flagged: true})
	s.Create(ctx, "c", CreateOptions{Folder: FolderArchive})
	s.Create(ctx, "d", CreateOptions{})
	s.Trash(ctx, mustCreate(t, s, ctx, "e"))

	c, _ := s.Counts(ctx)
	if c.Inbox != 3 || c.Flagged != 1 || c.Archive != 1 || c.Trash != 1 || c.All != 4 {
		t.Fatalf("counts = %+v", c)
	}
}

func TestMemorySearchMatchesTitleTagsAndContent(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	s.Create(ctx, "plain body", CreateOptions{Tags: []string{"project-x"}})
	s.Create(ctx, "Reunião do time", CreateOptions{})
	s.Create(ctx, "nothing here", CreateOptions{})

	byTag, _ := s.Query(ctx, Query{Filter: FilterAll, Search: "project-x"})
	if len(byTag) != 1 || byTag[0].Content != "plain body" {
		t.Fatalf("tag search = %v", contents(byTag))
	}

	byTitle, _ := s.Query(ctx, Query{Filter: FilterAll, Search: "reunião"})
	if len(byTitle) != 1 || byTitle[0].Title != "Reunião do time" {
		t.Fatalf("title search = %v", contents(byTitle))
	}

	byContent, _ := s.Query(ctx, Query{Filter: FilterAll, Search: "BODY"})
	if len(byContent) != 1 {
		t.Fatalf("content search = %v", contents(byContent))
	}
}

func TestMemorySortAccessedAndName(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	base := time.Unix(1700000000, 0)
	counter := 0
	orig := NowFunc
	NowFunc = func() time.Time {
		counter++
		return base.Add(time.Duration(counter) * time.Minute)
	}
	defer func() { NowFunc = orig }()

	s.Create(ctx, "zeta", CreateOptions{})
	s.Create(ctx, "alpha", CreateOptions{})
	s.Create(ctx, "mid", CreateOptions{})

	nameAsc, _ := s.Query(ctx, Query{Filter: FilterAll, Sort: SortName})
	if len(nameAsc) != 3 || nameAsc[0].Content != "alpha" || nameAsc[2].Content != "zeta" {
		t.Fatalf("name asc = %v", contents(nameAsc))
	}

	// Opening a draft refreshes AccessedAt without touching ModifiedAt.
	first, _ := s.Create(ctx, "opened first", CreateOptions{})
	got, err := s.Get(ctx, first.UUID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.AccessedAt == "" {
		t.Fatal("AccessedAt not refreshed on Get")
	}

	// The accessed draft surfaces first under SortAccessed descending.
	acc, _ := s.Query(ctx, Query{Filter: FilterAll, Sort: SortAccessed, SortDescending: true})
	if len(acc) != 4 || acc[0].Content != "opened first" {
		t.Fatalf("accessed desc = %v", contents(acc))
	}
}

func TestMemoryTrashAutoDelete(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	orig := NowFunc
	defer func() { NowFunc = orig }()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	NowFunc = func() time.Time { return now }

	old, _ := s.Create(ctx, "old trash", CreateOptions{})
	recent, _ := s.Create(ctx, "recent trash", CreateOptions{})
	keep, _ := s.Create(ctx, "keep me", CreateOptions{})

	// Trash `old` 31 days ago and `recent` 29 days ago.
	NowFunc = func() time.Time { return now.Add(-31 * 24 * time.Hour) }
	if err := s.Trash(ctx, old.UUID); err != nil {
		t.Fatalf("trash old: %v", err)
	}
	NowFunc = func() time.Time { return now.Add(-29 * 24 * time.Hour) }
	if err := s.Trash(ctx, recent.UUID); err != nil {
		t.Fatalf("trash recent: %v", err)
	}
	NowFunc = func() time.Time { return now }

	// Default retention is 30 days: `old` expires, `recent` survives.
	trashList, _ := s.Query(ctx, Query{Filter: FilterTrash})
	if len(trashList) != 1 || trashList[0].UUID != recent.UUID {
		t.Fatalf("trash after auto-purge = %v", contents(trashList))
	}
	if _, err := s.Get(ctx, old.UUID); !errors.Is(err, ErrDraftNotFound) {
		t.Fatalf("expected old draft purged, got %v", err)
	}
	if got, _ := s.Get(ctx, keep.UUID); got.Content != "keep me" {
		t.Fatalf("non-trashed draft affected: %+v", got)
	}

	// Disabling retention stops auto-purge entirely.
	s.SetTrashRetention(0)
	if s.TrashRetention() != 0 {
		t.Fatal("retention not disabled")
	}
	fresh, _ := s.Create(ctx, "fresh trash", CreateOptions{})
	if err := s.Trash(ctx, fresh.UUID); err != nil {
		t.Fatalf("trash fresh: %v", err)
	}
	list, _ := s.Query(ctx, Query{Filter: FilterTrash})
	if len(list) != 2 {
		t.Fatalf("disabled retention purged trash: %v", contents(list))
	}
}

func TestMemoryPurgeTrashManual(t *testing.T) {
	s := NewMemoryStore()
	s.SetTrashRetention(0) // disable auto-purge; purge manually
	ctx := context.Background()

	a, _ := s.Create(ctx, "a", CreateOptions{})
	b, _ := s.Create(ctx, "b", CreateOptions{})
	s.Create(ctx, "c", CreateOptions{})
	if err := s.Trash(ctx, a.UUID); err != nil {
		t.Fatalf("trash a: %v", err)
	}
	if err := s.Trash(ctx, b.UUID); err != nil {
		t.Fatalf("trash b: %v", err)
	}

	n, err := s.PurgeTrash(ctx, 0) // 0 = entire trash
	if err != nil || n != 2 {
		t.Fatalf("purge = %d, %v", n, err)
	}
	c, _ := s.Counts(ctx)
	if c.Trash != 0 || c.All != 1 {
		t.Fatalf("counts after purge = %+v", c)
	}
}

func contents(ds []Draft) []string {
	out := make([]string, len(ds))
	for i, d := range ds {
		out[i] = d.Content
	}
	return out
}

func mustCreate(t *testing.T, s *MemoryStore, ctx context.Context, content string) string {
	t.Helper()
	d, err := s.Create(ctx, content, CreateOptions{})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return d.UUID
}
