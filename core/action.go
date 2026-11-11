package core

import (
	"context"
	"fmt"
)

// ActionStepType enumerates built-in action step kinds.
type ActionStepType string

const (
	StepCopy     ActionStepType = "copy"
	StepShare    ActionStepType = "share"
	StepMove     ActionStepType = "move"
	StepTag      ActionStepType = "tag"
	StepArchive  ActionStepType = "archive"
	StepTrash    ActionStepType = "trash"
	StepTemplate ActionStepType = "template"
	StepPrompt   ActionStepType = "prompt"
)

// ActionStep is a single step in an Action.
type ActionStep struct {
	Type   ActionStepType         `json:"type"`
	Config map[string]interface{} `json:"config,omitempty"`
}

// Action is a named, ordered set of steps.
type Action struct {
	UUID         string       `json:"uuid"`
	Name         string       `json:"name"`
	Group        string       `json:"group"`
	Steps        []ActionStep `json:"steps"`
	AfterSuccess string       `json:"after_success,omitempty"`
}

// ActionRunResult describes the outcome of running an action.
type ActionRunResult struct {
	UUID         string `json:"uuid"`
	CreatedDraft bool   `json:"createdDraft"`
	Output       string `json:"output,omitempty"`
	Copied       string `json:"copied,omitempty"` // text sent to the clipboard by a copy step
}

// Clipboard is an optional sink for the copy step (injected by the client).
type Clipboard interface {
	Set(text string) error
}

// Sharer is an optional sink for the share step (injected by the client).
type Sharer interface {
	Share(text string) error
}

// ActionRunner executes actions against a Store.
type ActionRunner struct {
	store     Store
	actions   map[string]*Action
	clipboard Clipboard
	sharer    Sharer
}

// NewActionRunner returns an ActionRunner bound to a store.
func NewActionRunner(store Store) *ActionRunner {
	return &ActionRunner{store: store, actions: make(map[string]*Action)}
}

// SetClipboard injects the clipboard sink used by the copy step.
func (r *ActionRunner) SetClipboard(c Clipboard) { r.clipboard = c }

// SetSharer injects the share sink used by the share step.
func (r *ActionRunner) SetSharer(s Sharer) { r.sharer = s }

// Register adds (or replaces) an action by name.
func (r *ActionRunner) Register(a Action) {
	cp := a
	cp.Steps = append([]ActionStep{}, a.Steps...)
	r.actions[a.Name] = &cp
}

// List returns all registered actions.
func (r *ActionRunner) List() []Action {
	out := make([]Action, 0, len(r.actions))
	for _, a := range r.actions {
		out = append(out, *a)
	}
	return out
}

// Get returns a registered action by name.
func (r *ActionRunner) Get(name string) (Action, bool) {
	a, ok := r.actions[name]
	if !ok {
		return Action{}, false
	}
	return *a, true
}

// Run executes an action against an existing draft.
func (r *ActionRunner) Run(ctx context.Context, actionName, uuid string) (ActionRunResult, error) {
	a, ok := r.actions[actionName]
	if !ok {
		return ActionRunResult{}, fmt.Errorf("%w: %s", ErrActionNotFound, actionName)
	}

	d, err := r.store.Get(ctx, uuid)
	if err != nil {
		return ActionRunResult{}, err
	}

	out, copied, err := r.runSteps(ctx, a, d)
	if err != nil {
		return ActionRunResult{}, err
	}

	if _, err := r.store.Update(ctx, uuid, func(d *Draft) error {
		*d = out
		return nil
	}); err != nil {
		return ActionRunResult{}, err
	}

	if a.AfterSuccess != "" {
		r.applyAfterSuccess(ctx, uuid, a.AfterSuccess, out.Tags)
	}

	return ActionRunResult{UUID: uuid, CreatedDraft: false, Output: out.Content, Copied: copied}, nil
}

// RunOnText creates a transient draft, runs the action, returns the result.
func (r *ActionRunner) RunOnText(ctx context.Context, actionName, text string) (ActionRunResult, error) {
	d, err := r.store.Create(ctx, text, CreateOptions{})
	if err != nil {
		return ActionRunResult{}, err
	}
	res, err := r.Run(ctx, actionName, d.UUID)
	if err != nil {
		return ActionRunResult{}, err
	}
	res.CreatedDraft = true
	return res, nil
}

func (r *ActionRunner) runSteps(ctx context.Context, a *Action, d Draft) (Draft, string, error) {
	out := d
	out.Tags = append([]string{}, d.Tags...)
	copied := ""

	for _, step := range a.Steps {
		switch step.Type {
		case StepCopy:
			if r.clipboard != nil {
				if err := r.clipboard.Set(out.Content); err != nil {
					return out, copied, err
				}
			}
			copied = out.Content
		case StepShare:
			if r.sharer != nil {
				if err := r.sharer.Share(out.Content); err != nil {
					return out, copied, err
				}
			}
		case StepMove:
			folder := configString(step.Config, "folder")
			out.Folder = folder
			out.IsArchived = folder == "archive"
			out.IsTrashed = folder == "trash"
		case StepTag:
			out.Tags = unionTags(out.Tags, configStrings(step.Config, "tags"))
		case StepArchive:
			out.Folder = "archive"
			out.IsArchived = true
			out.IsTrashed = false
		case StepTrash:
			out.Folder = "trash"
			out.IsTrashed = true
			out.IsArchived = false
		case StepTemplate:
			tmpl := configString(step.Config, "template")
			out.Content = RenderTemplate(out.Content, out, tmpl)
			out.Title = titleOf(out.Content)
		}
	}
	return out, copied, nil
}

func (r *ActionRunner) applyAfterSuccess(ctx context.Context, uuid, after string, tags []string) {
	switch after {
	case "archive":
		_ = r.store.Archive(ctx, uuid)
	case "trash":
		_ = r.store.Trash(ctx, uuid)
	case "tag":
		for _, t := range tags {
			_, _ = r.store.AddTags(ctx, uuid, []string{t})
		}
	}
}

func configString(c map[string]interface{}, key string) string {
	if c == nil {
		return ""
	}
	if v, ok := c[key].(string); ok {
		return v
	}
	return ""
}

func configStrings(c map[string]interface{}, key string) []string {
	if c == nil {
		return nil
	}
	switch v := c[key].(type) {
	case []string:
		return v
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
