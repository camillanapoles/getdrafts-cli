// Package drafto is the gomobile boundary API. The //export methods below are
// generated into Kotlin/Java classes by `gomobile bind` and consumed by the
// Android app. Normal `go build`/`go vet` treat //export as a plain comment,
// so this package also compiles as ordinary Go.
//
// # Why JSON
//
// gomobile only binds types declared in the *bound* package itself. Exported
// methods that mention a type from another package (here `core.Draft`,
// `core.Counts`, `core.ActionRunResult`) are silently dropped from the
// generated Java class — no warning, no error, the method just is not there.
// That is why the first binding exposed only archiveDraft/trashDraft/close:
// every method returning `core.Draft` was omitted.
//
// The boundary therefore crosses the language border as plain strings:
// JSON in, JSON out. String and error are the only types that always bind.
package drafto

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/nerveband/drafts-applescript-cli/core"
)

// Core is the process-wide Drafto engine instance bound into Android.
type Core struct {
	store   core.Store
	actions *core.ActionRunner
	closer  interface{ Close() error }
}

// New initializes the engine with an in-memory store. Use NewAt for
// persistence; this constructor stays for UI preview and tests.
func New() *Core {
	s := core.NewMemoryStore()
	return &Core{store: s, actions: core.NewActionRunner(s)}
}

// NewAt initializes the engine with a persistent SQLite store at path
// (typically the app's private database path). SQLite is pure Go via
// modernc.org/sqlite, so no CGO is required on Android.
//
// The caller must call Close when the engine is torn down.
func NewAt(path string) (*Core, error) {
	s, err := core.NewSQLiteStore(path)
	if err != nil {
		return nil, err
	}
	return &Core{store: s, actions: core.NewActionRunner(s), closer: s}, nil
}

// Close releases the underlying store if it owns resources (SQLite).
// It is safe to call on an in-memory engine.
func (c *Core) Close() error {
	if c.closer == nil {
		return nil
	}
	return c.closer.Close()
}

// RegisterAction registers a built-in action so it can be run from Kotlin.
func (c *Core) RegisterAction(name string, stepsJSON string) error {
	a, err := ParseAction(name, stepsJSON)
	if err != nil {
		return err
	}
	c.actions.Register(a)
	return nil
}

// CreateDraftJSON creates a draft and returns it as JSON.
//
// tagsJSON is a JSON array of strings ("" means no tags).
func (c *Core) CreateDraftJSON(content string, tagsJSON string, flagged bool) (string, error) {
	tags, err := decodeTags(tagsJSON)
	if err != nil {
		return "", err
	}
	d, err := c.store.Create(context.Background(), content, core.CreateOptions{
		Tags:    tags,
		Flagged: flagged,
	})
	if err != nil {
		return "", err
	}
	return encode(d)
}

// GetDraftJSON returns one draft as JSON ("" when it does not exist).
func (c *Core) GetDraftJSON(uuid string) (string, error) {
	d, err := c.store.Get(context.Background(), uuid)
	if err != nil {
		if isNotFound(err) {
			return "", nil
		}
		return "", err
	}
	return encode(d)
}

// QueryDraftsJSON returns a JSON array of drafts ("" when empty).
func (c *Core) QueryDraftsJSON(filter string, search string, tagsJSON string, limit int) (string, error) {
	f, err := parseFilter(filter)
	if err != nil {
		return "", err
	}
	tags, err := decodeTags(tagsJSON)
	if err != nil {
		return "", err
	}
	ds, err := c.store.Query(context.Background(), core.Query{
		Filter: f,
		Search: search,
		Tags:   tags,
		Limit:  limit,
	})
	if err != nil {
		return "", err
	}
	if len(ds) == 0 {
		return "", nil
	}
	return encode(ds)
}

// SetFlaggedJSON flags/unflags a draft and returns it as JSON.
func (c *Core) SetFlaggedJSON(uuid string, flagged bool) (string, error) {
	d, err := c.store.SetFlagged(context.Background(), uuid, flagged)
	if err != nil {
		return "", err
	}
	return encode(d)
}

// ReplaceDraftJSON replaces a draft's content and returns it as JSON.
func (c *Core) ReplaceDraftJSON(uuid string, content string) (string, error) {
	d, err := c.store.Replace(context.Background(), uuid, content)
	if err != nil {
		return "", err
	}
	return encode(d)
}

// AddTagsJSON adds tags to a draft and returns it as JSON.
func (c *Core) AddTagsJSON(uuid string, tagsJSON string) (string, error) {
	tags, err := decodeTags(tagsJSON)
	if err != nil {
		return "", err
	}
	d, err := c.store.AddTags(context.Background(), uuid, tags)
	if err != nil {
		return "", err
	}
	return encode(d)
}

// RunActionJSON runs a registered action and returns ActionRunResult as JSON.
func (c *Core) RunActionJSON(actionName string, uuid string) (string, error) {
	res, err := c.actions.Run(context.Background(), actionName, uuid)
	if err != nil {
		return "", err
	}
	return encode(res)
}

// ListTagsJSON returns all tags as a JSON array ("" when there are none).
func (c *Core) ListTagsJSON() (string, error) {
	tags, err := c.store.ListTags(context.Background())
	if err != nil {
		return "", err
	}
	if len(tags) == 0 {
		return "", nil
	}
	return encode(tags)
}

// CountsJSON returns the draft counts as JSON.
func (c *Core) CountsJSON() (string, error) {
	counts, err := c.store.Counts(context.Background())
	if err != nil {
		return "", err
	}
	return encode(counts)
}

// ArchiveDraft moves a draft to the archive.
func (c *Core) ArchiveDraft(uuid string) error {
	return c.store.Archive(context.Background(), uuid)
}

// TrashDraft moves a draft to the trash.
func (c *Core) TrashDraft(uuid string) error {
	return c.store.Trash(context.Background(), uuid)
}

// ---- helpers ---------------------------------------------------------------

func encode(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func decodeTags(tagsJSON string) ([]string, error) {
	if tagsJSON == "" {
		return nil, nil
	}
	var tags []string
	if err := json.Unmarshal([]byte(tagsJSON), &tags); err != nil {
		return nil, core.ErrInvalidInput
	}
	return tags, nil
}

func isNotFound(err error) bool {
	return errors.Is(err, core.ErrDraftNotFound)
}

func parseFilter(s string) (core.Filter, error) {
	switch s {
	case "inbox":
		return core.FilterInbox, nil
	case "flagged":
		return core.FilterFlagged, nil
	case "archive":
		return core.FilterArchive, nil
	case "trash":
		return core.FilterTrash, nil
	case "all":
		return core.FilterAll, nil
	}
	return core.FilterInbox, core.ErrInvalidInput
}
