package core

import (
	"context"
	"errors"
	"strings"
	"time"
)

// Sentinel errors shared across backends.
var (
	ErrDraftNotFound     = errors.New("draft not found")
	ErrActionNotFound    = errors.New("action not found")
	ErrWorkspaceNotFound = errors.New("workspace not found")
	ErrTagNotFound       = errors.New("tag not found")
	ErrInvalidInput      = errors.New("invalid input")
)

// Store is the storage abstraction every Drafto client programs against.
// Backends: AppleScript (macOS bridge), SQLite (Android/Linux), Memory (tests).
type Store interface {
	// Create a new draft; returns the stored draft.
	Create(ctx context.Context, content string, opts CreateOptions) (Draft, error)
	// Get a draft by UUID.
	Get(ctx context.Context, uuid string) (Draft, error)
	// Query drafts by filter/search/tags/workspace/sort.
	Query(ctx context.Context, q Query) ([]Draft, error)
	// Update mutates a draft atomically.
	Update(ctx context.Context, uuid string, mutate func(*Draft) error) (Draft, error)
	// Replace entire content.
	Replace(ctx context.Context, uuid, content string) (Draft, error)
	// Prepend text to the beginning.
	Prepend(ctx context.Context, uuid, text string) (Draft, error)
	// Append text to the end.
	Append(ctx context.Context, uuid, text string) (Draft, error)
	// Trash a draft (move to trash).
	Trash(ctx context.Context, uuid string) error
	// EmptyTrash permanently removes all trashed drafts.
	EmptyTrash(ctx context.Context) error
	// Archive a draft.
	Archive(ctx context.Context, uuid string) error
	// SetFlagged sets the flagged flag.
	SetFlagged(ctx context.Context, uuid string, flagged bool) (Draft, error)
	// SetTags replaces the draft's tags.
	SetTags(ctx context.Context, uuid string, tags []string) (Draft, error)
	// AddTags unions tags onto the draft.
	AddTags(ctx context.Context, uuid string, tags []string) (Draft, error)
	// Delete permanently removes a draft.
	Delete(ctx context.Context, uuid string) error
	// ListTags returns all tags in use.
	ListTags(ctx context.Context) ([]string, error)
	// Counts returns per-folder counts.
	Counts(ctx context.Context) (Counts, error)
	// Workspaces lists saved workspaces.
	Workspaces(ctx context.Context) ([]Workspace, error)
	// ActiveWorkspace returns the current workspace name.
	ActiveWorkspace(ctx context.Context) (string, error)
	// SetActiveWorkspace sets the current workspace.
	SetActiveWorkspace(ctx context.Context, name string) error
}

// TrashPruner is an optional capability implemented by stores that support
// trash expiration (parity: Drafts auto-deletes trashed drafts after 30
// days). Clients type-assert Store to TrashPruner; the absence of the
// capability is not an error.
type TrashPruner interface {
	// PurgeTrash permanently removes trashed drafts older than olderThan.
	// olderThan <= 0 purges the entire trash. Returns the number of drafts
	// removed.
	PurgeTrash(ctx context.Context, olderThan time.Duration) (int, error)
}

// applySorting orders drafts per a Query. It is a package helper so every
// backend shares identical ordering semantics.
func applySorting(ds []Draft, q Query) []Draft {
	if len(ds) < 2 {
		return ds
	}

	// Stable ascending sort by the requested key (lexicographic; the
	// "2006-01-02 15:04:05" layout sorts correctly as strings).
	sortStable(ds, func(i, j int) bool {
		a, b := ds[i], ds[j]
		var ka, kb string
		switch q.Sort {
		case SortModified:
			ka, kb = a.ModifiedAt, b.ModifiedAt
		case SortAccessed:
			ka, kb = accessedKey(a), accessedKey(b)
		case SortName:
			ka, kb = strings.ToLower(a.Title), strings.ToLower(b.Title)
		default: // SortCreated
			ka, kb = a.CreatedAt, b.CreatedAt
		}
		if ka != kb {
			if q.SortDescending {
				return ka > kb
			}
			return ka < kb
		}
		return false // preserve input order (stable)
	})

	if q.SortFlaggedToTop {
		flagged := make([]Draft, 0, len(ds))
		others := make([]Draft, 0, len(ds))
		for _, d := range ds {
			if d.IsFlagged {
				flagged = append(flagged, d)
			} else {
				others = append(others, d)
			}
		}
		return append(flagged, others...)
	}

	return ds
}

// accessedKey returns the sort key for SortAccessed: the last access time,
// falling back to the modification time for drafts that were never opened.
func accessedKey(d Draft) string {
	if d.AccessedAt != "" {
		return d.AccessedAt
	}
	return d.ModifiedAt
}

// sortStable is a tiny stable sort (insertion sort) to avoid importing
// "sort" for a single call site while keeping determinism. For large lists
// a backend may replace this with sort.SliceStable.
func sortStable(ds []Draft, less func(i, j int) bool) {
	for i := 1; i < len(ds); i++ {
		for j := i; j > 0 && less(j, j-1); j-- {
			ds[j], ds[j-1] = ds[j-1], ds[j]
		}
	}
}
