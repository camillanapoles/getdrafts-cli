// Command drafto is the native Drafto client for Linux (and any Go host).
//
// It programs against the platform-agnostic core.Store — the same engine the
// Android app binds via gomobile. This is the "CLI base" reused for Android:
// the commands map 1:1 to core.Store methods.
//
// Storage defaults to an in-memory store; swap for a SQLite store
// (core.NewSQLiteStore, Phase 1) for persistence.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	arg "github.com/alexflint/go-arg"

	"github.com/nerveband/drafts-applescript-cli/core"
)

// store is the storage backend. Defaults to in-memory; replace with SQLite.
var store core.Store = core.NewMemoryStore()

func main() {
	var args Args
	p := arg.MustParse(&args)

	ctx := context.Background()

	if p.Subcommand() == nil {
		p.WriteHelp(os.Stdout)
		fmt.Println()
		fmt.Println("Drafto CLI - native client for the Drafto engine.")
		fmt.Println("Storage: in-memory (swap for SQLite in Phase 1).")
		return
	}

	var data interface{}
	var err error

	switch {
	case args.Create != nil:
		data, err = runCreate(ctx, args.Create)
	case args.List != nil:
		data, err = runList(ctx, args.List)
	case args.Get != nil:
		data, err = runGet(ctx, args.Get)
	case args.Search != nil:
		data, err = runSearch(ctx, args.Search)
	case args.Flag != nil:
		data, err = runFlag(ctx, args.Flag)
	case args.Unflag != nil:
		data, err = runUnflag(ctx, args.Unflag)
	case args.Archive != nil:
		err = store.Archive(ctx, args.Archive.UUID)
	case args.Trash != nil:
		err = store.Trash(ctx, args.Trash.UUID)
	case args.Tags != nil:
		data, err = runTags(ctx)
	case args.Counts != nil:
		data, err = store.Counts(ctx)
	case args.Schema != nil:
		data = schema()
	default:
		p.WriteHelp(os.Stdout)
		return
	}

	emit(data, err)
}

// ---- Commands ---------------------------------------------------------------

type CreateCmd struct {
	Content string   `arg:"positional" help:"draft content"`
	Tag     []string `arg:"-t,separate" help:"tag (repeatable)"`
	Flagged bool     `arg:"-f" help:"create flagged"`
}

type ListCmd struct {
	Filter string   `arg:"-f" default:"inbox" help:"inbox|flagged|archive|trash|all"`
	Search string   `arg:"-s" help:"search draft content"`
	Tag    []string `arg:"-t,separate" help:"filter by tag"`
	Limit  int      `arg:"--limit" default:"20" help:"max results (0 for all)"`
}

type GetCmd struct {
	UUID string `arg:"positional" help:"draft uuid"`
}

type SearchCmd struct {
	Query string `arg:"positional" help:"search query"`
}

type FlagCmd struct {
	UUID string `arg:"positional" help:"draft uuid"`
}

type UnflagCmd struct {
	UUID string `arg:"positional" help:"draft uuid"`
}

type ArchCmd struct {
	UUID string `arg:"positional" help:"draft uuid"`
}

type TrashCmd struct {
	UUID string `arg:"positional" help:"draft uuid"`
}

type TagsCmd struct{}

type CountsCmd struct{}

type SchemaCmd struct{}

type Args struct {
	Create  *CreateCmd  `arg:"subcommand:create" help:"create a draft"`
	List    *ListCmd    `arg:"subcommand:list" help:"list drafts"`
	Get     *GetCmd     `arg:"subcommand:get" help:"get a draft"`
	Search  *SearchCmd  `arg:"subcommand:search" help:"search drafts"`
	Flag    *FlagCmd    `arg:"subcommand:flag" help:"flag a draft"`
	Unflag  *UnflagCmd  `arg:"subcommand:unflag" help:"unflag a draft"`
	Archive *ArchCmd    `arg:"subcommand:archive" help:"archive a draft"`
	Trash   *TrashCmd   `arg:"subcommand:trash" help:"trash a draft"`
	Tags    *TagsCmd    `arg:"subcommand:tags" help:"list tags"`
	Counts  *CountsCmd  `arg:"subcommand:counts" help:"show folder counts"`
	Schema  *SchemaCmd  `arg:"subcommand:schema" help:"output command schema"`
}

func (Args) Description() string {
	return "Drafto CLI - native client for the Drafto engine (Linux/Go hosts)"
}

// ---- Handlers ---------------------------------------------------------------

func runCreate(ctx context.Context, c *CreateCmd) (interface{}, error) {
	d, err := store.Create(ctx, c.Content, core.CreateOptions{Tags: c.Tag, Flagged: c.Flagged})
	if err != nil {
		return nil, err
	}
	return d, nil
}

func runList(ctx context.Context, c *ListCmd) (interface{}, error) {
	filter, err := parseFilter(c.Filter)
	if err != nil {
		return nil, err
	}
	ds, err := store.Query(ctx, core.Query{
		Filter: filter,
		Search: c.Search,
		Tags:   c.Tag,
		Limit:  c.Limit,
	})
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"drafts": ds, "count": len(ds), "filter": c.Filter}, nil
}

func runGet(ctx context.Context, c *GetCmd) (interface{}, error) {
	return store.Get(ctx, c.UUID)
}

func runSearch(ctx context.Context, c *SearchCmd) (interface{}, error) {
	ds, err := store.Query(ctx, core.Query{Filter: core.FilterAll, Search: c.Query})
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"drafts": ds, "count": len(ds), "query": c.Query}, nil
}

func runFlag(ctx context.Context, c *FlagCmd) (interface{}, error) {
	return store.SetFlagged(ctx, c.UUID, true)
}

func runUnflag(ctx context.Context, c *UnflagCmd) (interface{}, error) {
	return store.SetFlagged(ctx, c.UUID, false)
}

func runTags(ctx context.Context) (interface{}, error) {
	tags, err := store.ListTags(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"tags": tags, "count": len(tags)}, nil
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
	return core.FilterInbox, fmt.Errorf("invalid filter: %s", s)
}

func schema() interface{} {
	return map[string]interface{}{
		"name":    "drafto",
		"engine":  "core.Store",
		"commands": []string{
			"create", "list", "get", "search",
			"flag", "unflag", "archive", "trash",
			"tags", "counts", "schema",
		},
	}
}

// ---- Output ------------------------------------------------------------------

func emit(data interface{}, err error) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	if err != nil {
		code := "ERROR"
		switch {
		case errors.Is(err, core.ErrDraftNotFound):
			code = "DRAFT_NOT_FOUND"
		case errors.Is(err, core.ErrWorkspaceNotFound):
			code = "WORKSPACE_NOT_FOUND"
		case errors.Is(err, core.ErrInvalidInput):
			code = "INVALID_FILTER"
		}
		enc.Encode(map[string]interface{}{
			"success": false,
			"error":   map[string]string{"code": code, "message": err.Error()},
		})
		os.Exit(1)
	}

	enc.Encode(map[string]interface{}{"success": true, "data": data})
}
