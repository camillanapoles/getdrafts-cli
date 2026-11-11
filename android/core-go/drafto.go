// Package drafto is the gomobile boundary API. The //export methods below are
// generated into Kotlin/Java classes by `gomobile bind` and consumed by the
// Android app. Normal `go build`/`go vet` treat //export as a plain comment,
// so this package also compiles as ordinary Go.
package drafto

import (
	"context"

	"github.com/nerveband/drafts-applescript-cli/core"
)

// Core is the process-wide Drafto engine instance bound into Android.
type Core struct {
	store   core.Store
	actions *core.ActionRunner
}

// New initializes the engine with an in-memory store. Swap for a SQLite
// store (core.NewSQLiteStore) in production.
func New() *Core {
	s := core.NewMemoryStore()
	return &Core{store: s, actions: core.NewActionRunner(s)}
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

//export CreateDraft
func (c *Core) CreateDraft(content string, tags []string, flagged bool) (core.Draft, error) {
	return c.store.Create(context.Background(), content, core.CreateOptions{
		Tags:    tags,
		Flagged: flagged,
	})
}

//export GetDraft
func (c *Core) GetDraft(uuid string) (core.Draft, error) {
	return c.store.Get(context.Background(), uuid)
}

//export QueryDrafts
func (c *Core) QueryDrafts(filter string, search string, tags []string, limit int) ([]core.Draft, error) {
	f, err := parseFilter(filter)
	if err != nil {
		return nil, err
	}
	return c.store.Query(context.Background(), core.Query{
		Filter: f,
		Search: search,
		Tags:   tags,
		Limit:  limit,
	})
}

//export SetFlagged
func (c *Core) SetFlagged(uuid string, flagged bool) (core.Draft, error) {
	return c.store.SetFlagged(context.Background(), uuid, flagged)
}

//export ArchiveDraft
func (c *Core) ArchiveDraft(uuid string) error {
	return c.store.Archive(context.Background(), uuid)
}

//export TrashDraft
func (c *Core) TrashDraft(uuid string) error {
	return c.store.Trash(context.Background(), uuid)
}

//export ReplaceDraft
func (c *Core) ReplaceDraft(uuid string, content string) (core.Draft, error) {
	return c.store.Replace(context.Background(), uuid, content)
}

//export AddTags
func (c *Core) AddTags(uuid string, tags []string) (core.Draft, error) {
	return c.store.AddTags(context.Background(), uuid, tags)
}

//export RunAction
func (c *Core) RunAction(actionName string, uuid string) (core.ActionRunResult, error) {
	return c.actions.Run(context.Background(), actionName, uuid)
}

//export ListTags
func (c *Core) ListTags() ([]string, error) {
	return c.store.ListTags(context.Background())
}

//export Counts
func (c *Core) Counts() (core.Counts, error) {
	return c.store.Counts(context.Background())
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
