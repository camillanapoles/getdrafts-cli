package core

import (
	"context"
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
