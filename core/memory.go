package core

import (
	"context"
	"crypto/rand"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// timeLayout is the canonical timestamp layout used across the core
	// ("2006-01-02 15:04:05"). It sorts correctly as a plain string.
	timeLayout = "2006-01-02 15:04:05"

	// defaultTrashRetention is the trash auto-delete window (parity: Drafts
	// permanently removes drafts trashed more than 30 days ago).
	defaultTrashRetention = 30 * 24 * time.Hour
)

// MemoryStore is an in-memory, thread-safe Store implementation. It is the
// reference backend for tests/demos and documents the exact semantics the
// SQLite and AppleScript backends must reproduce.
type MemoryStore struct {
	mu              sync.RWMutex
	drafts          map[string]*Draft
	tags            map[string]struct{}
	workspaces      map[string]Workspace
	order           []string // insertion order, for stable ties
	activeWorkspace string

	// trashRetention is the trash auto-delete window; 0 disables expiry.
	trashRetention time.Duration
}

// NewMemoryStore returns an empty in-memory store. Trash retention defaults
// to 30 days (Drafts parity); use SetTrashRetention to change or disable it.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		drafts:         make(map[string]*Draft),
		tags:           make(map[string]struct{}),
		workspaces:     make(map[string]Workspace),
		trashRetention: defaultTrashRetention,
	}
}

// SetTrashRetention sets the trash auto-delete window. A duration <= 0
// disables automatic expiration (manual PurgeTrash still works).
func (s *MemoryStore) SetTrashRetention(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d < 0 {
		d = 0
	}
	s.trashRetention = d
}

// TrashRetention returns the configured trash auto-delete window (0 = off).
func (s *MemoryStore) TrashRetention() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.trashRetention
}

// Create adds a new draft and returns it.
func (s *MemoryStore) Create(ctx context.Context, content string, opts CreateOptions) (Draft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	folder := "inbox"
	if opts.Folder == FolderArchive {
		folder = "archive"
	}

	uuid := newUUID()
	ts := nowStr()
	d := &Draft{
		UUID:       uuid,
		Content:    content,
		Title:      titleOf(content),
		Tags:       append([]string{}, opts.Tags...),
		IsFlagged:  opts.Flagged,
		Folder:     folder,
		CreatedAt:  ts,
		ModifiedAt: ts,
		Permalink:  Permalink(uuid),
		Workspace:  s.activeWorkspace,
	}

	for _, t := range d.Tags {
		s.tags[t] = struct{}{}
	}

	s.drafts[uuid] = d
	s.order = append(s.order, uuid)

	return cloneDraft(d), nil
}

// Get returns a draft by UUID. Accessing a draft refreshes its AccessedAt
// (parity: Drafts "accessed" sort); the modification time is untouched.
func (s *MemoryStore) Get(ctx context.Context, uuid string) (Draft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	d, ok := s.drafts[uuid]
	if !ok {
		return Draft{}, fmt.Errorf("%w: %s", ErrDraftNotFound, uuid)
	}
	d.AccessedAt = nowStr()
	return cloneDraft(d), nil
}

// Query returns drafts matching the query, sorted and limited. Trashed
// drafts past the retention window are auto-purged (Drafts parity) before
// the filters run.
func (s *MemoryStore) Query(ctx context.Context, q Query) ([]Draft, error) {
	// Write (not read) lock: lazy trash expiration may mutate the store.
	s.mu.Lock()
	defer s.mu.Unlock()

	s.purgeExpiredTrashLocked()

	// Resolve effective filter (a workspace overrides folder/search/tags).
	filter := q.Filter
	search := q.Search
	incTags := q.Tags
	omitTags := q.OmitTags
	if q.Workspace != "" {
		ws, ok := s.workspaces[q.Workspace]
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrWorkspaceNotFound, q.Workspace)
		}
		if ws.Folder != "" {
			filter = filterFromFolder(ws.Folder)
		}
		if ws.Search != "" {
			search = ws.Search
		}
		if len(ws.Tags) > 0 {
			incTags = ws.Tags
		}
		if len(ws.OmitTags) > 0 {
			omitTags = ws.OmitTags
		}
	}

	out := make([]Draft, 0, len(s.order))
	for _, uuid := range s.order {
		d := s.drafts[uuid]
		if d == nil {
			continue
		}
		if !passesFolder(*d, filter) {
			continue
		}
		if search != "" && !matchesSearch(*d, search) {
			continue
		}
		if !hasAllTags(*d, incTags) || !hasNoTags(*d, omitTags) {
			continue
		}
		out = append(out, cloneDraft(d))
	}

	out = applySorting(out, q)

	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

// Update mutates a draft atomically.
func (s *MemoryStore) Update(ctx context.Context, uuid string, mutate func(*Draft) error) (Draft, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	d, ok := s.drafts[uuid]
	if !ok {
		return Draft{}, fmt.Errorf("%w: %s", ErrDraftNotFound, uuid)
	}
	cp := cloneDraft(d)
	if err := mutate(&cp); err != nil {
		return Draft{}, err
	}
	cp.ModifiedAt = nowStr()
	// Trash lifecycle invariant: entering the trash stamps TrashedAt; any
	// move out of the trash (archive, restore, action step) clears it.
	if cp.Folder == "trash" {
		if cp.TrashedAt == "" {
			cp.TrashedAt = cp.ModifiedAt
		}
	} else {
		cp.TrashedAt = ""
	}
	*d = cp
	return cloneDraft(d), nil
}

// Replace overwrites a draft's content.
func (s *MemoryStore) Replace(ctx context.Context, uuid, content string) (Draft, error) {
	return s.Update(ctx, uuid, func(d *Draft) error {
		d.Content = content
		d.Title = titleOf(content)
		return nil
	})
}

// Prepend inserts text before the existing content.
func (s *MemoryStore) Prepend(ctx context.Context, uuid, text string) (Draft, error) {
	return s.Update(ctx, uuid, func(d *Draft) error {
		d.Content = text + "\n" + d.Content
		d.Title = titleOf(d.Content)
		return nil
	})
}

// Append inserts text after the existing content.
func (s *MemoryStore) Append(ctx context.Context, uuid, text string) (Draft, error) {
	return s.Update(ctx, uuid, func(d *Draft) error {
		d.Content = d.Content + "\n" + text
		return nil
	})
}

// Trash moves a draft to trash.
func (s *MemoryStore) Trash(ctx context.Context, uuid string) error {
	_, err := s.Update(ctx, uuid, func(d *Draft) error {
		d.Folder = "trash"
		d.IsTrashed = true
		d.IsArchived = false
		return nil
	})
	return err
}

// EmptyTrash permanently removes all trashed drafts.
func (s *MemoryStore) EmptyTrash(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	kept := s.order[:0]
	for _, uuid := range s.order {
		if d := s.drafts[uuid]; d != nil && d.Folder == "trash" {
			delete(s.drafts, uuid)
			continue
		}
		kept = append(kept, uuid)
	}
	s.order = kept
	return nil
}

// PurgeTrash permanently removes trashed drafts older than olderThan
// (parity: Drafts trash expiry). olderThan <= 0 purges the entire trash.
// It implements the TrashPruner capability. Returns the number of drafts
// removed.
func (s *MemoryStore) PurgeTrash(ctx context.Context, olderThan time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.purgeTrashOlderLocked(olderThan), nil
}

// Archive moves a draft to archive.
func (s *MemoryStore) Archive(ctx context.Context, uuid string) error {
	_, err := s.Update(ctx, uuid, func(d *Draft) error {
		d.Folder = "archive"
		d.IsArchived = true
		d.IsTrashed = false
		return nil
	})
	return err
}

// SetFlagged sets the flagged flag.
func (s *MemoryStore) SetFlagged(ctx context.Context, uuid string, flagged bool) (Draft, error) {
	return s.Update(ctx, uuid, func(d *Draft) error {
		d.IsFlagged = flagged
		return nil
	})
}

// SetTags replaces the draft's tags.
func (s *MemoryStore) SetTags(ctx context.Context, uuid string, tags []string) (Draft, error) {
	return s.Update(ctx, uuid, func(d *Draft) error {
		old := d.Tags
		d.Tags = append([]string{}, tags...)
		s.reconcileTags(old, d.Tags)
		return nil
	})
}

// AddTags unions tags onto the draft.
func (s *MemoryStore) AddTags(ctx context.Context, uuid string, tags []string) (Draft, error) {
	return s.Update(ctx, uuid, func(d *Draft) error {
		d.Tags = unionTags(d.Tags, tags)
		for _, t := range tags {
			s.tags[t] = struct{}{}
		}
		return nil
	})
}

// Delete permanently removes a draft.
func (s *MemoryStore) Delete(ctx context.Context, uuid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	d, ok := s.drafts[uuid]
	if !ok {
		return fmt.Errorf("%w: %s", ErrDraftNotFound, uuid)
	}
	s.reconcileTags(d.Tags, nil)
	delete(s.drafts, uuid)
	for i, u := range s.order {
		if u == uuid {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
	return nil
}

// ListTags returns all tags in use, sorted.
func (s *MemoryStore) ListTags(ctx context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]string, 0, len(s.tags))
	for t := range s.tags {
		out = append(out, t)
	}
	sort.Strings(out)
	return out, nil
}

// Counts returns per-folder counts.
func (s *MemoryStore) Counts(ctx context.Context) (Counts, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	c := Counts{}
	for _, uuid := range s.order {
		d := s.drafts[uuid]
		if d == nil {
			continue
		}
		switch d.Folder {
		case "inbox":
			c.Inbox++
			if d.IsFlagged {
				c.Flagged++
			}
		case "archive":
			c.Archive++
		case "trash":
			c.Trash++
		}
	}
	c.All = c.Inbox + c.Archive
	return c, nil
}

// Workspaces lists saved workspaces.
func (s *MemoryStore) Workspaces(ctx context.Context) ([]Workspace, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Workspace, 0, len(s.workspaces))
	for _, w := range s.workspaces {
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ActiveWorkspace returns the current workspace name.
func (s *MemoryStore) ActiveWorkspace(ctx context.Context) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeWorkspace, nil
}

// SetActiveWorkspace sets the current workspace.
func (s *MemoryStore) SetActiveWorkspace(ctx context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if name != "" {
		if _, ok := s.workspaces[name]; !ok {
			return fmt.Errorf("%w: %s", ErrWorkspaceNotFound, name)
		}
	}
	s.activeWorkspace = name
	return nil
}

// SaveWorkspace persists a workspace definition.
func (s *MemoryStore) SaveWorkspace(ws Workspace) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.workspaces[ws.Name] = ws
}

// ---- helpers ---------------------------------------------------------------

// reconcileTags updates the tag index when a draft's tags change.
// Callers must hold the write lock.
func (s *MemoryStore) reconcileTags(old, new []string) {
	for _, t := range old {
		if !contains(new, t) {
			delete(s.tags, t)
		}
	}
	for _, t := range new {
		s.tags[t] = struct{}{}
	}
}

// purgeExpiredTrashLocked auto-purges trashed drafts past the retention
// window. Drafts without TrashedAt (legacy records) never expire
// automatically; EmptyTrash/PurgeTrash handle them explicitly.
// Callers must hold the write lock.
func (s *MemoryStore) purgeExpiredTrashLocked() {
	if s.trashRetention <= 0 {
		return
	}
	s.purgeTrashOlderLocked(s.trashRetention)
}

// purgeTrashOlderLocked removes trashed drafts older than olderThan
// (olderThan <= 0 removes every trashed draft). Returns the number of
// drafts removed. Callers must hold the write lock.
func (s *MemoryStore) purgeTrashOlderLocked(olderThan time.Duration) int {
	now := parseTS(nowStr())
	removed := 0
	kept := s.order[:0]
	for _, uuid := range s.order {
		expired := false
		if d := s.drafts[uuid]; d != nil && d.Folder == "trash" {
			if olderThan <= 0 {
				expired = true
			} else if d.TrashedAt != "" {
				if t := parseTS(d.TrashedAt); !t.IsZero() && now.Sub(t) >= olderThan {
					expired = true
				}
			}
		}
		if expired {
			delete(s.drafts, uuid)
			removed++
			continue
		}
		kept = append(kept, uuid)
	}
	s.order = kept
	return removed
}

func cloneDraft(d *Draft) Draft {
	c := *d
	c.Tags = append([]string{}, d.Tags...)
	return c
}

func newUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("d%d", timeNow().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func nowStr() string {
	return timeNow().Format(timeLayout)
}

func passesFolder(d Draft, f Filter) bool {
	switch f {
	case FilterInbox:
		return d.Folder == "inbox"
	case FilterFlagged:
		return d.Folder == "inbox" && d.IsFlagged
	case FilterArchive:
		return d.Folder == "archive"
	case FilterTrash:
		return d.Folder == "trash"
	case FilterAll:
		return d.Folder == "inbox" || d.Folder == "archive"
	}
	return true
}

func filterFromFolder(folder string) Filter {
	switch folder {
	case "archive":
		return FilterArchive
	case "trash":
		return FilterTrash
	case "flagged":
		return FilterFlagged
	case "all":
		return FilterAll
	default:
		return FilterInbox
	}
}

func hasAllTags(d Draft, tags []string) bool {
	for _, t := range tags {
		if !contains(d.Tags, t) {
			return false
		}
	}
	return true
}

func hasNoTags(d Draft, tags []string) bool {
	for _, t := range tags {
		if contains(d.Tags, t) {
			return false
		}
	}
	return true
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func containsFold(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// matchesSearch is the full-text matcher for Query.Search (parity: Drafts
// search). It matches case-insensitively against the content, the display
// title and the tags.
func matchesSearch(d Draft, q string) bool {
	if containsFold(d.Content, q) || containsFold(d.Title, q) {
		return true
	}
	for _, t := range d.Tags {
		if containsFold(t, q) {
			return true
		}
	}
	return false
}

// parseTS parses a canonical core timestamp; returns the zero time when
// malformed (expired checks then skip the draft conservatively).
func parseTS(ts string) time.Time {
	t, err := time.Parse(timeLayout, ts)
	if err != nil {
		return time.Time{}
	}
	return t
}

func unionTags(a, b []string) []string {
	out := append([]string{}, a...)
	for _, t := range b {
		if !contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}
