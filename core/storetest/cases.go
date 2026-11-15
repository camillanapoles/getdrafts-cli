package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nerveband/drafts-applescript-cli/core"
)

// cases is the shared behavioural contract every core.Store backend must
// satisfy. Order is the CI output order; names are stable — they are quoted in
// issues and docs (DoD rule: a ✅ in docs needs a named test).
//
// Divergence/… entries are documented skips for differences the suite has
// found but this PR must not "fix" (no production changes allowed here). Each
// names the spec that owns the flip-back.
var cases = []conformanceCase{
	{name: "CreatePopulatesCanonicalFields", fn: caseCreateCanonical},
	{name: "CreateHonorsOptions", fn: caseCreateOptions},
	{name: "CreateDerivesTitleFromFirstNonEmptyLine", fn: caseCreateTitle},
	{name: "CreateEmptyContent", fn: caseCreateEmpty},
	{name: "GetRoundTrip", fn: caseGetRoundTrip},
	{name: "GetRefreshesAccessedAt", fn: caseGetAccessedAt},
	{name: "GetSeesTrashedDraft", fn: caseGetTrashed},
	{name: "QueryEmptyStore", fn: caseQueryEmpty},
	{name: "QueryFolderFilters", fn: caseQueryFolders},
	{name: "QueryInsertionOrderOnCreatedTies", fn: caseQueryStableTies},
	{name: "QueryLimit", fn: caseQueryLimit},
	{name: "SearchMatchesContentTitleTags", fn: caseSearch},
	{name: "SearchNoMatchIsEmpty", fn: caseSearchMiss},
	{name: "TagInclusionAndOmission", fn: caseTagFilters},
	{name: "ReplacePersistsAndKeepsIdentity", fn: caseReplace},
	{name: "PrependAndAppendContentSemantics", fn: casePrependAppend},
	{name: "UpdateStampsModifiedAt", fn: caseUpdateModifiedAt},
	{name: "UpdateMutatorErrorAbortsAtomically", fn: caseUpdateError},
	{name: "SentinelErrorsForUnknownUUID", fn: caseSentinels},
	{name: "SetFlaggedRoundTrip", fn: caseFlagged},
	{name: "SetTagsReplaceAndAddTagsUnion", fn: caseTags},
	{name: "AddTagsIsIdempotentUnion", fn: caseAddTagsDedupe},
	{name: "SetTagsEmptyClearsTagsAndIndex", fn: caseClearTags},
	{name: "ListTagsSortedAndDeduplicated", fn: caseListTags},
	{name: "ListTagsDropsSoleTagAfterDelete", fn: caseDeleteDropsTag},
	{name: "ArchiveMovesAndFlags", fn: caseArchive},
	{name: "TrashStampsTrashedAt", fn: caseTrash},
	{name: "ArchiveFromTrashClearsTrashedAt", fn: caseTrashToArchive},
	{name: "EmptyTrashRemovesOnlyTrash", fn: caseEmptyTrash},
	{name: "DeleteRemovesAndMissingIsSentinel", fn: caseDelete},
	{name: "CountsEmptyStore", fn: caseCountsEmpty},
	{name: "CountsFoldersAndInboxFlags", fn: caseCounts},
	{name: "SortCreatedModifiedAccessedPinnedClock", fn: caseSortPinnedClock},
	{name: "SortNameCaseInsensitive", fn: caseSortName},
	{name: "SortDescending", fn: caseSortDesc},
	{name: "SortFlaggedToTop", fn: caseFlaggedTop},
	{name: "TrashPrunerPurgeWindowAndCount", fn: casePurgeWindow},
	{name: "TrashPrunerNonPositivePurgesAll", fn: casePurgeAll},
	{name: "ExpiredTrashAutoPurgeOnQuery", fn: caseAutoPurge},
	{name: "WorkspacesRoundTripFields", fn: caseWorkspacesRoundTrip},
	{name: "WorkspacesUnknownNameSentinels", fn: caseWorkspacesUnknown},
	{name: "WorkspaceQueryOverrideFolderAndSearch", fn: caseWorkspaceQueryOverride},
	{name: "WorkspaceQueryOverrideTags", fn: caseWorkspaceTagsOverride},
	{name: "ActiveWorkspaceRoundTripAndCreateStamp", fn: caseActiveWorkspace},
}

// ---- create / get ------------------------------------------------------------

func caseCreateCanonical(t *testing.T, s core.Store) {
	d := mustCreate(t, s, "hello world")
	if d.UUID == "" {
		t.Fatal("Create returned an empty UUID")
	}
	if d.Title != "hello world" {
		t.Errorf("Title = %q, want %q", d.Title, "hello world")
	}
	if d.Folder != "inbox" {
		t.Errorf("Folder = %q, want inbox", d.Folder)
	}
	if d.CreatedAt != d.ModifiedAt {
		t.Errorf("CreatedAt %q != ModifiedAt %q on a fresh draft", d.CreatedAt, d.ModifiedAt)
	}
	if d.Permalink != core.Permalink(d.UUID) {
		t.Errorf("Permalink = %q, want %q", d.Permalink, core.Permalink(d.UUID))
	}
	if len(d.Tags) != 0 {
		t.Errorf("Tags = %v, want empty", d.Tags)
	}
	if d.IsFlagged || d.IsArchived || d.IsTrashed {
		t.Errorf("fresh draft flags = %+v, want all false", d)
	}
	if d.Workspace != "" {
		t.Errorf("Workspace = %q, want empty on a fresh store", d.Workspace)
	}
	g := mustGet(t, s, d.UUID)
	if g.Content != "hello world" || g.CreatedAt != d.CreatedAt || g.ModifiedAt != d.ModifiedAt {
		t.Errorf("Get round-trip mismatch: %+v vs created %+v", g, d)
	}
}

func caseCreateOptions(t *testing.T, s core.Store) {
	d := mustCreateWith(t, s, "archived flagged", core.CreateOptions{
		Tags:    []string{"a", "b"},
		Folder:  core.FolderArchive,
		Flagged: true,
	})
	if d.Folder != "archive" {
		t.Errorf("Folder = %q, want archive", d.Folder)
	}
	if !d.IsFlagged {
		t.Error("IsFlagged = false, want true")
	}
	wantTags(t, "Create opts", d.Tags, "a", "b")
	g := mustGet(t, s, d.UUID)
	wantTags(t, "Get after Create opts", g.Tags, "a", "b")
	c, err := s.Counts(context.Background())
	act(t, "Counts", err)
	if c.Archive != 1 || c.Inbox != 0 {
		t.Errorf("Counts after FolderArchive create: %+v", c)
	}
}

func caseCreateTitle(t *testing.T, s core.Store) {
	d := mustCreate(t, s, "\n\n   Héllo 中文   \nsecond line")
	if d.Title != "Héllo 中文" {
		t.Errorf("Title = %q, want %q (first non-empty line, trimmed)", d.Title, "Héllo 中文")
	}
	g := mustGet(t, s, d.UUID)
	if g.Content != "\n\n   Héllo 中文   \nsecond line" {
		t.Errorf("content not preserved verbatim: %q", g.Content)
	}
}

func caseCreateEmpty(t *testing.T, s core.Store) {
	d := mustCreate(t, s, "")
	if d.Title != "" {
		t.Errorf("Title = %q, want empty", d.Title)
	}
	if mustGet(t, s, d.UUID).Content != "" {
		t.Error("empty content did not round-trip")
	}
}

func caseGetRoundTrip(t *testing.T, s core.Store) {
	d := mustCreateWith(t, s, "body one", core.CreateOptions{Tags: []string{"x"}})
	g := mustGet(t, s, d.UUID)
	if g.UUID != d.UUID || g.Permalink != d.Permalink {
		t.Errorf("identity mismatch: %+v vs %+v", g, d)
	}
	wantTags(t, "Get", g.Tags, "x")
}

func caseGetAccessedAt(t *testing.T, s core.Store) {
	base, at := setClock(t)
	d := mustCreate(t, s, "accessed")
	if g := mustGet(t, s, d.UUID); g.AccessedAt != ts(base) {
		t.Errorf("AccessedAt = %q, want %q (Get must stamp and return the same value)", g.AccessedAt, ts(base))
	}
	at(time.Hour)
	g := mustGet(t, s, d.UUID)
	if g.AccessedAt != ts(base.Add(time.Hour)) {
		t.Errorf("AccessedAt = %q, want %q after clock advance", g.AccessedAt, ts(base.Add(time.Hour)))
	}
	if g.ModifiedAt != ts(base) {
		t.Errorf("Get touched ModifiedAt: %q, want untouched %q", g.ModifiedAt, ts(base))
	}
	// Persisted, not just returned: a later read carries the stamp.
	if again := mustGet(t, s, d.UUID); again.AccessedAt == "" {
		t.Error("AccessedAt not persisted by Get")
	}
}

func caseGetTrashed(t *testing.T, s core.Store) {
	d := mustCreate(t, s, "to trash")
	act(t, "Trash", s.Trash(context.Background(), d.UUID))
	g := mustGet(t, s, d.UUID)
	if g.Folder != "trash" || !g.IsTrashed {
		t.Errorf("Get after Trash: %+v, want folder trash and IsTrashed", g)
	}
}

// ---- query -------------------------------------------------------------------

func caseQueryEmpty(t *testing.T, s core.Store) {
	ds := mustQuery(t, s, core.Query{Filter: core.FilterAll})
	if len(ds) != 0 {
		t.Errorf("empty store query returned %d drafts", len(ds))
	}
}

func caseQueryFolders(t *testing.T, s core.Store) {
	inbox := mustCreateWith(t, s, "flagged inbox item", core.CreateOptions{Flagged: true})
	archived := mustCreateWith(t, s, "archive item", core.CreateOptions{Folder: core.FolderArchive})
	trashed := mustCreate(t, s, "trashed item")
	act(t, "Trash", s.Trash(context.Background(), trashed.UUID))

	wantUUIDs(t, mustQuery(t, s, core.Query{Filter: core.FilterInbox}), inbox.UUID)
	wantUUIDs(t, mustQuery(t, s, core.Query{Filter: core.FilterFlagged}), inbox.UUID)
	wantUUIDs(t, mustQuery(t, s, core.Query{Filter: core.FilterArchive}), archived.UUID)
	wantUUIDs(t, mustQuery(t, s, core.Query{Filter: core.FilterTrash}), trashed.UUID)
	wantUUIDs(t, mustQuery(t, s, core.Query{Filter: core.FilterAll}), inbox.UUID, archived.UUID)
}

func caseQueryStableTies(t *testing.T, s core.Store) {
	// Same-second timestamps: ties must keep insertion order on both backends
	// (MemoryStore replays its insertion slice, SQLiteStore its rowid order).
	a := mustCreate(t, s, "aaa")
	b := mustCreate(t, s, "bbb")
	c := mustCreate(t, s, "ccc")
	wantUUIDs(t, mustQuery(t, s, core.Query{}), a.UUID, b.UUID, c.UUID)
}

func caseQueryLimit(t *testing.T, s core.Store) {
	a := mustCreate(t, s, "aaa")
	b := mustCreate(t, s, "bbb")
	c := mustCreate(t, s, "ccc")

	wantUUIDs(t, mustQuery(t, s, core.Query{Limit: 1}), a.UUID)
	wantUUIDs(t, mustQuery(t, s, core.Query{Limit: 2}), a.UUID, b.UUID)
	wantUUIDs(t, mustQuery(t, s, core.Query{Limit: 0}), a.UUID, b.UUID, c.UUID)
	wantUUIDs(t, mustQuery(t, s, core.Query{Limit: -1}), a.UUID, b.UUID, c.UUID)
	wantUUIDs(t, mustQuery(t, s, core.Query{Limit: 99}), a.UUID, b.UUID, c.UUID)
}

func caseSearch(t *testing.T, s core.Store) {
	byContent := mustCreate(t, s, "Zebra Crossing plans")
	byTag := mustCreateWith(t, s, "quiet note", core.CreateOptions{Tags: []string{"nimbo"}})
	byTitle := mustCreate(t, s, "Nimbo-like header\nirrelevant body")
	mustCreate(t, s, "nothing here")

	// Case-insensitivity + content/title/tags coverage.
	wantAsSet(t, mustQuery(t, s, core.Query{Search: "nimbo"}), byTag.UUID, byTitle.UUID)
	wantAsSet(t, mustQuery(t, s, core.Query{Search: "ZEBRA"}), byContent.UUID)
	wantAsSet(t, mustQuery(t, s, core.Query{Search: "plans"}), byContent.UUID)
	wantAsSet(t, mustQuery(t, s, core.Query{Search: "中文-none"}))
}

func caseSearchMiss(t *testing.T, s core.Store) {
	mustCreate(t, s, "alpha")
	if ds := mustQuery(t, s, core.Query{Search: "zzz-none"}); len(ds) != 0 {
		t.Errorf("no-match search returned %v", uuidsOf(ds))
	}
}

func caseTagFilters(t *testing.T, s core.Store) {
	both := mustCreateWith(t, s, "both", core.CreateOptions{Tags: []string{"keep", "drop"}})
	keepOnly := mustCreateWith(t, s, "keep only", core.CreateOptions{Tags: []string{"keep"}})
	none := mustCreate(t, s, "untagged")

	wantUUIDs(t, mustQuery(t, s, core.Query{Tags: []string{"keep"}}), both.UUID, keepOnly.UUID)
	wantUUIDs(t, mustQuery(t, s, core.Query{Tags: []string{"keep", "drop"}}), both.UUID)
	wantUUIDs(t, mustQuery(t, s, core.Query{OmitTags: []string{"drop"}}), keepOnly.UUID, none.UUID)
	wantUUIDs(t, mustQuery(t, s, core.Query{Tags: []string{"keep"}, OmitTags: []string{"drop"}}), keepOnly.UUID)
}

// ---- content mutations ---------------------------------------------------------

func caseReplace(t *testing.T, s core.Store) {
	base, at := setClock(t)
	d := mustCreateWith(t, s, "old content\nsecond", core.CreateOptions{Tags: []string{"keepme"}})
	at(time.Hour)
	r, err := s.Replace(context.Background(), d.UUID, "new header\nrest")
	act(t, "Replace", err)

	if r.Content != "new header\nrest" {
		t.Errorf("Replace result content = %q", r.Content)
	}
	if r.Title != "new header" {
		t.Errorf("Replace title = %q, want %q", r.Title, "new header")
	}
	if r.CreatedAt != ts(base) {
		t.Errorf("Replace rewrote CreatedAt: %q, want %q", r.CreatedAt, ts(base))
	}
	if r.ModifiedAt != ts(base.Add(time.Hour)) {
		t.Errorf("Replace ModifiedAt = %q, want %q", r.ModifiedAt, ts(base.Add(time.Hour)))
	}
	if r.Permalink != d.Permalink {
		t.Errorf("Replace rewrote Permalink: %q", r.Permalink)
	}
	wantTags(t, "Replace preserves tags", r.Tags, "keepme")

	g := mustGet(t, s, d.UUID)
	if g.Content != "new header\nrest" || g.Title != "new header" {
		t.Errorf("Replace not persisted: %+v", g)
	}
	if g.CreatedAt != ts(base) || g.Permalink != d.Permalink {
		t.Errorf("Replace persisted identity drift: %+v", g)
	}
}

func casePrependAppend(t *testing.T, s core.Store) {
	d := mustCreate(t, s, "first line\nsecond")

	a, err := s.Append(context.Background(), d.UUID, "appended")
	act(t, "Append", err)
	if a.Content != "first line\nsecond\nappended" {
		t.Errorf("Append content = %q", a.Content)
	}
	if a.Title != "first line" {
		t.Errorf("Append rewrote Title to %q, want it to stay %q", a.Title, "first line")
	}

	p, err := s.Prepend(context.Background(), d.UUID, "head")
	act(t, "Prepend", err)
	if p.Content != "head\nfirst line\nsecond\nappended" {
		t.Errorf("Prepend content = %q", p.Content)
	}
	if p.Title != "head" {
		t.Errorf("Prepend Title = %q, want %q", p.Title, "head")
	}
	g := mustGet(t, s, d.UUID)
	if g.Content != p.Content || g.Title != p.Title {
		t.Errorf("Prepend/Append not persisted: %+v", g)
	}
}

func caseUpdateModifiedAt(t *testing.T, s core.Store) {
	base, at := setClock(t)
	d := mustCreate(t, s, "clock test")
	if d.CreatedAt != ts(base) || d.ModifiedAt != ts(base) {
		t.Fatalf("Create timestamps = %q/%q, want %q", d.CreatedAt, d.ModifiedAt, ts(base))
	}
	at(90 * time.Minute)
	u, err := s.Update(context.Background(), d.UUID, func(g *core.Draft) error {
		g.Content = "changed"
		return nil
	})
	act(t, "Update", err)
	if u.Content != "changed" {
		t.Errorf("Update content = %q", u.Content)
	}
	if u.CreatedAt != ts(base) {
		t.Errorf("Update rewrote CreatedAt: %q", u.CreatedAt)
	}
	if u.ModifiedAt != ts(base.Add(90*time.Minute)) {
		t.Errorf("Update ModifiedAt = %q, want %q", u.ModifiedAt, ts(base.Add(90*time.Minute)))
	}
	g := mustGet(t, s, d.UUID)
	if g.Content != "changed" || g.ModifiedAt != u.ModifiedAt {
		t.Errorf("Update not persisted: %+v", g)
	}
}

func caseUpdateError(t *testing.T, s core.Store) {
	errBoom := errors.New("boom")
	d := mustCreate(t, s, "original")
	_, err := s.Update(context.Background(), d.UUID, func(g *core.Draft) error {
		g.Content = "mutated"
		return errBoom
	})
	wantErrIs(t, "Update with failing mutator", err, errBoom)
	if g := mustGet(t, s, d.UUID); g.Content != "original" {
		t.Errorf("aborted Update persisted changes: %q", g.Content)
	}
}

func caseSentinels(t *testing.T, s core.Store) {
	const ghost = "no-such-uuid"
	ctx := context.Background()
	_, err := s.Get(ctx, ghost)
	wantErrIs(t, "Get", err, core.ErrDraftNotFound)
	_, err = s.Update(ctx, ghost, func(*core.Draft) error { return nil })
	wantErrIs(t, "Update", err, core.ErrDraftNotFound)
	_, err = s.Replace(ctx, ghost, "x")
	wantErrIs(t, "Replace", err, core.ErrDraftNotFound)
	_, err = s.Prepend(ctx, ghost, "x")
	wantErrIs(t, "Prepend", err, core.ErrDraftNotFound)
	_, err = s.Append(ctx, ghost, "x")
	wantErrIs(t, "Append", err, core.ErrDraftNotFound)
	wantErrIs(t, "Trash", s.Trash(ctx, ghost), core.ErrDraftNotFound)
	wantErrIs(t, "Archive", s.Archive(ctx, ghost), core.ErrDraftNotFound)
	_, err = s.SetFlagged(ctx, ghost, true)
	wantErrIs(t, "SetFlagged", err, core.ErrDraftNotFound)
	_, err = s.SetTags(ctx, ghost, []string{"t"})
	wantErrIs(t, "SetTags", err, core.ErrDraftNotFound)
	_, err = s.AddTags(ctx, ghost, []string{"t"})
	wantErrIs(t, "AddTags", err, core.ErrDraftNotFound)
	wantErrIs(t, "Delete", s.Delete(ctx, ghost), core.ErrDraftNotFound)
}

// ---- flags & tags -------------------------------------------------------------

func caseFlagged(t *testing.T, s core.Store) {
	d := mustCreate(t, s, "flag me")
	f, err := s.SetFlagged(context.Background(), d.UUID, true)
	act(t, "SetFlagged", err)
	if !f.IsFlagged {
		t.Error("SetFlagged result has IsFlagged=false")
	}
	if !mustGet(t, s, d.UUID).IsFlagged {
		t.Error("SetFlagged not persisted")
	}
	u, err := s.SetFlagged(context.Background(), d.UUID, false)
	act(t, "SetFlagged(false)", err)
	if u.IsFlagged {
		t.Error("SetFlagged(false) result still flagged")
	}
	if mustGet(t, s, d.UUID).IsFlagged {
		t.Error("SetFlagged(false) not persisted")
	}
}

func caseTags(t *testing.T, s core.Store) {
	d := mustCreateWith(t, s, "tags", core.CreateOptions{Tags: []string{"orig"}})

	r, err := s.SetTags(context.Background(), d.UUID, []string{"y", "z"})
	act(t, "SetTags", err)
	wantTags(t, "SetTags result", r.Tags, "y", "z")
	wantTags(t, "SetTags persisted", mustGet(t, s, d.UUID).Tags, "y", "z")

	a, err := s.AddTags(context.Background(), d.UUID, []string{"z", "w"})
	act(t, "AddTags", err)
	wantTags(t, "AddTags union", a.Tags, "y", "z", "w")
	wantTags(t, "AddTags persisted", mustGet(t, s, d.UUID).Tags, "y", "z", "w")

	q := mustQuery(t, s, core.Query{Tags: []string{"z"}})
	wantUUIDs(t, q, d.UUID)
}

func caseAddTagsDedupe(t *testing.T, s core.Store) {
	d := mustCreateWith(t, s, "dup", core.CreateOptions{Tags: []string{"dup"}})
	a, err := s.AddTags(context.Background(), d.UUID, []string{"dup"})
	act(t, "AddTags", err)
	if len(a.Tags) != 1 || a.Tags[0] != "dup" {
		t.Errorf("AddTags with an existing tag: %v, want exactly [dup]", a.Tags)
	}
}

func caseClearTags(t *testing.T, s core.Store) {
	d := mustCreateWith(t, s, "sole", core.CreateOptions{Tags: []string{"sole"}})
	before, err := s.ListTags(context.Background())
	act(t, "ListTags", err)
	if len(before) != 1 {
		t.Fatalf("ListTags before clear: %v", before)
	}
	_, err = s.SetTags(context.Background(), d.UUID, nil)
	act(t, "SetTags(nil)", err)
	if g := mustGet(t, s, d.UUID); len(g.Tags) != 0 {
		t.Errorf("SetTags(nil) left tags: %v", g.Tags)
	}
	after, err := s.ListTags(context.Background())
	act(t, "ListTags after clear", err)
	if len(after) != 0 {
		t.Errorf("dropped sole tag still in ListTags: %v", after)
	}
}

func caseListTags(t *testing.T, s core.Store) {
	mustCreateWith(t, s, "d1", core.CreateOptions{Tags: []string{"y", "x"}})
	mustCreateWith(t, s, "d2", core.CreateOptions{Tags: []string{"x", "w"}})
	got, err := s.ListTags(context.Background())
	act(t, "ListTags", err)
	// ListTags contract is sorted+deduplicated on both backends.
	if len(got) != 3 || got[0] != "w" || got[1] != "x" || got[2] != "y" {
		t.Errorf("ListTags = %v, want [w x y] sorted and unique", got)
	}
}

func caseDeleteDropsTag(t *testing.T, s core.Store) {
	d := mustCreateWith(t, s, "tagged once", core.CreateOptions{Tags: []string{"onlytag"}})
	act(t, "Delete", s.Delete(context.Background(), d.UUID))
	got, err := s.ListTags(context.Background())
	act(t, "ListTags", err)
	if len(got) != 0 {
		t.Errorf("tag survived Delete of its only draft: %v", got)
	}
}

// ---- folders / trash -----------------------------------------------------------

func caseArchive(t *testing.T, s core.Store) {
	d := mustCreate(t, s, "archive me")
	act(t, "Archive", s.Archive(context.Background(), d.UUID))
	g := mustGet(t, s, d.UUID)
	if g.Folder != "archive" || !g.IsArchived || g.IsTrashed {
		t.Errorf("Get after Archive: %+v", g)
	}
	wantUUIDs(t, mustQuery(t, s, core.Query{Filter: core.FilterInbox}))
	wantUUIDs(t, mustQuery(t, s, core.Query{Filter: core.FilterArchive}), d.UUID)
}

func caseTrash(t *testing.T, s core.Store) {
	d := mustCreate(t, s, "trash me")
	act(t, "Trash", s.Trash(context.Background(), d.UUID))
	g := mustGet(t, s, d.UUID)
	if g.Folder != "trash" || !g.IsTrashed || g.IsArchived {
		t.Errorf("Get after Trash: %+v", g)
	}
	if g.TrashedAt == "" {
		t.Error("Trash did not stamp TrashedAt")
	}
	if g.ModifiedAt == "" {
		t.Error("Trash did not stamp ModifiedAt")
	}
	wantUUIDs(t, mustQuery(t, s, core.Query{Filter: core.FilterInbox}))
	wantUUIDs(t, mustQuery(t, s, core.Query{Filter: core.FilterTrash}), d.UUID)
}

func caseTrashToArchive(t *testing.T, s core.Store) {
	d := mustCreate(t, s, "revive")
	ctx := context.Background()
	act(t, "Trash", s.Trash(ctx, d.UUID))
	if mustGet(t, s, d.UUID).TrashedAt == "" {
		t.Fatal("precondition: Trash did not stamp TrashedAt")
	}
	act(t, "Archive", s.Archive(ctx, d.UUID))
	g := mustGet(t, s, d.UUID)
	if g.TrashedAt != "" {
		t.Errorf("move out of trash must clear TrashedAt, got %q", g.TrashedAt)
	}
	if g.Folder != "archive" || !g.IsArchived || g.IsTrashed {
		t.Errorf("Get after trash→archive: %+v", g)
	}
}

func caseEmptyTrash(t *testing.T, s core.Store) {
	gone := mustCreate(t, s, "gone")
	kept := mustCreate(t, s, "kept")
	ctx := context.Background()
	act(t, "Trash", s.Trash(ctx, gone.UUID))

	act(t, "EmptyTrash", s.EmptyTrash(ctx))
	wantErrIs(t, "Get after EmptyTrash", getErr(s, gone.UUID), core.ErrDraftNotFound)
	if g := mustGet(t, s, kept.UUID); g.Folder != "inbox" {
		t.Errorf("EmptyTrash touched non-trash drafts: %+v", g)
	}
	if ds := mustQuery(t, s, core.Query{Filter: core.FilterTrash}); len(ds) != 0 {
		t.Errorf("EmptyTrash left trash: %v", uuidsOf(ds))
	}
}

func caseDelete(t *testing.T, s core.Store) {
	d := mustCreate(t, s, "delete me")
	ctx := context.Background()
	act(t, "Delete", s.Delete(ctx, d.UUID))
	if _, err := s.Get(ctx, d.UUID); !errors.Is(err, core.ErrDraftNotFound) {
		t.Errorf("Get after Delete: err = %v, want ErrDraftNotFound", err)
	}
	wantErrIs(t, "Delete again", s.Delete(ctx, d.UUID), core.ErrDraftNotFound)
	c, err := s.Counts(ctx)
	act(t, "Counts", err)
	if c != (core.Counts{}) {
		t.Errorf("Counts after deleting the only draft: %+v", c)
	}
}

// ---- counts --------------------------------------------------------------------

func caseCountsEmpty(t *testing.T, s core.Store) {
	c, err := s.Counts(context.Background())
	act(t, "Counts", err)
	if c != (core.Counts{}) {
		t.Errorf("Counts on empty store = %+v", c)
	}
}

func caseCounts(t *testing.T, s core.Store) {
	ctx := context.Background()
	mustCreate(t, s, "inbox one")
	i2 := mustCreate(t, s, "inbox two flagged")
	if _, err := s.SetFlagged(ctx, i2.UUID, true); err != nil {
		t.Fatalf("SetFlagged: %v", err)
	}
	a1 := mustCreateWith(t, s, "archived flagged", core.CreateOptions{Folder: core.FolderArchive})
	if _, err := s.SetFlagged(ctx, a1.UUID, true); err != nil {
		t.Fatalf("SetFlagged(archive): %v", err)
	}
	t1 := mustCreate(t, s, "trashed")
	act(t, "Trash", s.Trash(ctx, t1.UUID))

	c, err := s.Counts(ctx)
	act(t, "Counts", err)
	want := core.Counts{Inbox: 2, Flagged: 1, Archive: 1, Trash: 1, All: 3}
	if c != want {
		t.Errorf("Counts = %+v, want %+v (Flagged counts inbox only; All = inbox+archive)", c, want)
	}
}

// ---- sorting ---------------------------------------------------------------------

func caseSortPinnedClock(t *testing.T, s core.Store) {
	_, at := setClock(t)
	a := mustCreate(t, s, "aaa")
	at(time.Hour)
	b := mustCreate(t, s, "bbb")

	// created
	wantUUIDs(t, mustQuery(t, s, core.Query{Sort: core.SortCreated}), a.UUID, b.UUID)
	wantUUIDs(t, mustQuery(t, s, core.Query{Sort: core.SortCreated, SortDescending: true}), b.UUID, a.UUID)

	// modified: touch a later than b
	at(2 * time.Hour)
	if _, err := s.Append(context.Background(), a.UUID, "later"); err != nil {
		t.Fatalf("Append: %v", err)
	}
	wantUUIDs(t, mustQuery(t, s, core.Query{Sort: core.SortModified}), b.UUID, a.UUID)
	wantUUIDs(t, mustQuery(t, s, core.Query{Sort: core.SortModified, SortDescending: true}), a.UUID, b.UUID)

	// accessed: b was never opened (falls back to modified); open a later
	at(3 * time.Hour)
	if _, err := s.Get(context.Background(), a.UUID); err != nil {
		t.Fatalf("Get: %v", err)
	}
	wantUUIDs(t, mustQuery(t, s, core.Query{Sort: core.SortAccessed}), b.UUID, a.UUID)
	wantUUIDs(t, mustQuery(t, s, core.Query{Sort: core.SortAccessed, SortDescending: true}), a.UUID, b.UUID)
}

func caseSortName(t *testing.T, s core.Store) {
	beta := mustCreate(t, s, "beta one")
	alpha := mustCreate(t, s, "ALPHA two")
	gamma := mustCreate(t, s, "gamma three")
	wantUUIDs(t, mustQuery(t, s, core.Query{Sort: core.SortName}), alpha.UUID, beta.UUID, gamma.UUID)
	wantUUIDs(t, mustQuery(t, s, core.Query{Sort: core.SortName, SortDescending: true}), gamma.UUID, beta.UUID, alpha.UUID)
}

func caseSortDesc(t *testing.T, s core.Store) {
	_, at := setClock(t)
	a := mustCreate(t, s, "a")
	at(time.Minute)
	b := mustCreate(t, s, "b")
	at(2 * time.Minute)
	c := mustCreate(t, s, "c")
	wantUUIDs(t, mustQuery(t, s, core.Query{SortDescending: true}), c.UUID, b.UUID, a.UUID)
}

func caseFlaggedTop(t *testing.T, s core.Store) {
	a := mustCreate(t, s, "a")
	b := mustCreate(t, s, "b")
	c := mustCreate(t, s, "c")
	if _, err := s.SetFlagged(context.Background(), b.UUID, true); err != nil {
		t.Fatalf("SetFlagged: %v", err)
	}
	// Flagged first; the rest keep the (stable) created order.
	wantUUIDs(t, mustQuery(t, s, core.Query{SortFlaggedToTop: true}), b.UUID, a.UUID, c.UUID)
	wantUUIDs(t, mustQuery(t, s, core.Query{}), a.UUID, b.UUID, c.UUID)
}

// ---- trash lifecycle: pruning -----------------------------------------------------

func casePurgeWindow(t *testing.T, s core.Store) {
	ctx := context.Background()
	a := mustCreate(t, s, "a")
	b := mustCreate(t, s, "b")
	act(t, "Trash", s.Trash(ctx, a.UUID))
	act(t, "Trash", s.Trash(ctx, b.UUID))

	pruner, ok := s.(core.TrashPruner)
	if !ok {
		t.Fatal("Store must implement the core.TrashPruner capability")
	}
	// Fresh trashed drafts are inside every sane window: nothing goes.
	if n, err := pruner.PurgeTrash(ctx, 24*time.Hour); err != nil || n != 0 {
		t.Errorf("PurgeTrash(24h) on fresh trash = (%d, %v), want (0, nil)", n, err)
	}
	// olderThan <= 0 purges the whole trash and reports the count.
	if n, err := pruner.PurgeTrash(ctx, 0); err != nil || n != 2 {
		t.Errorf("PurgeTrash(0) = (%d, %v), want (2, nil)", n, err)
	}
	if n, err := pruner.PurgeTrash(ctx, 0); err != nil || n != 0 {
		t.Errorf("second PurgeTrash(0) = (%d, %v), want (0, nil)", n, err)
	}
}

func casePurgeAll(t *testing.T, s core.Store) {
	ctx := context.Background()
	d := mustCreate(t, s, "purge me")
	act(t, "Trash", s.Trash(ctx, d.UUID))
	pruner, ok := s.(core.TrashPruner)
	if !ok {
		t.Fatal("Store must implement the core.TrashPruner capability")
	}
	if n, err := pruner.PurgeTrash(ctx, -time.Second); err != nil || n != 1 {
		t.Errorf("PurgeTrash(negative) = (%d, %v), want (1, nil)", n, err)
	}
	wantErrIs(t, "Get after negative purge", getErr(s, d.UUID), core.ErrDraftNotFound)
}

func caseAutoPurge(t *testing.T, s core.Store) {
	ctx := context.Background()
	fresh := mustCreate(t, s, "fresh trash")
	act(t, "Trash", s.Trash(ctx, fresh.UUID))
	expired := mustCreate(t, s, "expired trash")
	act(t, "Trash", s.Trash(ctx, expired.UUID))

	// Backdate the trashed_at past the default 30-day window through Update —
	// a public-API move both backends persist verbatim (an explicit non-empty
	// TrashedAt is kept; only empty ones get stamped).
	_, err := s.Update(ctx, expired.UUID, func(g *core.Draft) error {
		g.TrashedAt = "2020-06-01 00:00:00"
		return nil
	})
	act(t, "backdate TrashedAt", err)

	// Query triggers the retention sweep (Drafts parity auto-delete).
	wantUUIDs(t, mustQuery(t, s, core.Query{Filter: core.FilterTrash}), fresh.UUID)
	wantErrIs(t, "Get on expired trash", getErr(s, expired.UUID), core.ErrDraftNotFound)
	if g := mustGet(t, s, fresh.UUID); g.TrashedAt == "" {
		t.Error("Query sweep clobbered the fresh draft's TrashedAt")
	}
	c, err := s.Counts(ctx)
	act(t, "Counts", err)
	if c.Trash != 1 {
		t.Errorf("Counts.Trash = %d after auto-purge, want 1", c.Trash)
	}
}

// ---- workspaces (read semantics via the runner's WorkspaceSeeder) ---------------

func caseWorkspacesRoundTrip(t *testing.T, s core.Store) {
	seedWorkspace(t, s, core.Workspace{
		Name:           "focus",
		Folder:         "archive",
		Search:         "needle",
		Tags:           []string{"t1", "t2"},
		OmitTags:       []string{"skipme"},
		Sort:           core.SortModified,
		SortDescending: true,
		FlaggedTop:     true,
		ActionGroup:    "daily",
	})
	list, err := s.Workspaces(context.Background())
	act(t, "Workspaces", err)
	if len(list) != 1 {
		t.Fatalf("Workspaces returned %d rows, want 1", len(list))
	}
	w := list[0]
	if w.Name != "focus" || w.Folder != "archive" || w.Search != "needle" {
		t.Errorf("workspace scalar fields lost: %+v", w)
	}
	wantTags(t, "workspace Tags", w.Tags, "t1", "t2")
	wantTags(t, "workspace OmitTags", w.OmitTags, "skipme")
	if w.Sort != core.SortModified || !w.SortDescending || !w.FlaggedTop {
		t.Errorf("workspace sort fields lost: %+v", w)
	}
	if w.ActionGroup != "daily" {
		t.Errorf("workspace ActionGroup = %q, want daily", w.ActionGroup)
	}
}

func caseWorkspacesUnknown(t *testing.T, s core.Store) {
	ctx := context.Background()
	_, err := s.Query(ctx, core.Query{Workspace: "ghost"})
	wantErrIs(t, "Query on unknown workspace", err, core.ErrWorkspaceNotFound)
	wantErrIs(t, "SetActiveWorkspace on unknown", s.SetActiveWorkspace(ctx, "ghost"), core.ErrWorkspaceNotFound)
	name, err := s.ActiveWorkspace(ctx)
	act(t, "ActiveWorkspace", err)
	if name != "" {
		t.Errorf("fresh store ActiveWorkspace = %q, want empty", name)
	}
}

func caseWorkspaceQueryOverride(t *testing.T, s core.Store) {
	inbox := mustCreate(t, s, "needle inbox")           // right search, wrong folder
	hit := mustCreateWith(t, s, "needle archive here", core.CreateOptions{Folder: core.FolderArchive})
	mustCreateWith(t, s, "haystack archive", core.CreateOptions{Folder: core.FolderArchive}) // right folder, wrong search
	_ = inbox

	seedWorkspace(t, s, core.Workspace{Name: "focus", Folder: "archive", Search: "needle"})
	wantUUIDs(t, mustQuery(t, s, core.Query{Workspace: "focus"}), hit.UUID)
}

func caseWorkspaceTagsOverride(t *testing.T, s core.Store) {
	keep := mustCreateWith(t, s, "one", core.CreateOptions{Tags: []string{"keep"}})
	mustCreateWith(t, s, "two", core.CreateOptions{Tags: []string{"drop"}})
	// A query-level filter must NOT leak into the workspace path: the request
	// asks for "drop", but the workspace pins "keep" and overrides it.
	seedWorkspace(t, s, core.Workspace{Name: "kept", Folder: "inbox", Tags: []string{"keep"}})
	wantUUIDs(t, mustQuery(t, s, core.Query{Workspace: "kept", Tags: []string{"drop"}}), keep.UUID)
}

func caseActiveWorkspace(t *testing.T, s core.Store) {
	ctx := context.Background()
	seedWorkspace(t, s, core.Workspace{Name: "focus", Folder: "archive"})

	act(t, "SetActiveWorkspace", s.SetActiveWorkspace(ctx, "focus"))
	name, err := s.ActiveWorkspace(ctx)
	act(t, "ActiveWorkspace", err)
	if name != "focus" {
		t.Fatalf("ActiveWorkspace = %q, want focus", name)
	}
	// New drafts are stamped with the active workspace.
	d := mustCreate(t, s, "inside focus")
	if d.Workspace != "focus" {
		t.Errorf("Create.Workspace = %q, want focus", d.Workspace)
	}
	if g := mustGet(t, s, d.UUID); g.Workspace != "focus" {
		t.Errorf("Get.Workspace = %q, want focus", g.Workspace)
	}
	// Clearing back to no workspace is always allowed.
	act(t, "SetActiveWorkspace(empty)", s.SetActiveWorkspace(ctx, ""))
	if name, err := s.ActiveWorkspace(ctx); err != nil || name != "" {
		t.Errorf("after clearing: ActiveWorkspace = %q, %v, want empty", name, err)
	}
}

// ---- documented divergences ---------------------------------------------------
//
// These entries exist so the divergences are CI-visible instead of folklore.
// Each has a tracking issue; when the owning spec lands, delete the skip
// entry and move the real assertions in.

func init() {
	divergences := []conformanceCase{
		{name: "Divergence/SharedTagSurvivesOtherDrafts", fn: func(t *testing.T, _ core.Store) {
			skipDiverge(t, "SPEC-CORE-06", "MemoryStore.reconcileTags drops a tag from the global index when one draft loses it even if another draft still has it; SQLite rows survive (memory.go reconcileTags vs tags-table cascade)")
		}},
		{name: "Divergence/EmptyTrashReconcilesTagIndex", fn: func(t *testing.T, _ core.Store) {
			skipDiverge(t, "SPEC-CORE-06", "Memory.EmptyTrash deletes drafts without reconciling the global tag index, so orphans stay in ListTags; SQLite cascades the rows away")
		}},
		{name: "Divergence/UpdateIdentityFieldsImmutable", fn: func(t *testing.T, _ core.Store) {
			skipDiverge(t, "SPEC-CORE-06", "SQLite.Update pins created_at/permalink against a hostile mutator; Memory.Update persists whatever the mutator set (HANDOFF §3.1 documents the SQLite semantics as the contract)")
		}},
		{name: "Divergence/UpdateFolderFlagInvariant", fn: func(t *testing.T, _ core.Store) {
			skipDiverge(t, "SPEC-CORE-06", "SQLite.Update recomputes IsArchived/IsTrashed from Folder; Memory trusts the mutator, letting a draft carry flags its folder contradicts")
		}},
		{name: "Divergence/RetentionUsesInjectedClock", fn: func(t *testing.T, _ core.Store) {
			skipDiverge(t, "SPEC-CORE-06", "SQLiteStore.PurgeTrash computes the cutoff with time.Now() instead of core.NowFunc, so NowFunc-driven retention expiry fires on MemoryStore only (suite works around it by backdating through Update)")
		}},
		{name: "Divergence/TagOrderIsContractual", fn: func(t *testing.T, _ core.Store) {
			skipDiverge(t, "SPEC-AND-01", "Memory returns draft tags in insertion order, SQLite in ORDER BY tag — the suite compares as sets until the boundary pins the wire shape")
		}},
		{name: "Divergence/SaveWorkspaceOnStore", fn: func(t *testing.T, _ core.Store) {
			skipDiverge(t, "SPEC-CORE-02", "SaveWorkspace is not in core.Store and the two backends disagree on its signature (audit D3/F1); seeding goes through WorkspaceSeeder meanwhile")
		}},
		{name: "Divergence/RankedFTS5Search", fn: func(t *testing.T, _ core.Store) {
			skipDiverge(t, "SPEC-CORE-05", "the FTS5 index is maintained but never queried — search is a Go substring scan on both backends (audit F10); ranked-result ordering has no contract to assert")
		}},
		{name: "Divergence/SortComplexityOnLargeDatasets", fn: func(t *testing.T, _ core.Store) {
			skipDiverge(t, "SPEC-CORE-04", "applySorting still uses an insertion sort O(n²) (audit F8); the 10k-draft perf case lands with the switch to sort.SliceStable")
		}},
	}
	cases = append(cases, divergences...)
}
