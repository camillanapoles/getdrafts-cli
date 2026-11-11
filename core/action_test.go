package core

import (
	"context"
	"testing"
)

type testClipboard struct{ v string }

func (c *testClipboard) Set(s string) error { c.v = s; return nil }

func TestActionRunnerRun(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	d, _ := s.Create(ctx, "original", CreateOptions{})

	clip := &testClipboard{}
	runner := NewActionRunner(s)
	runner.SetClipboard(clip)
	runner.Register(Action{
		Name: "Archive & Copy",
		Steps: []ActionStep{
			{Type: StepCopy},
			{Type: StepArchive},
		},
	})

	if _, err := runner.Run(ctx, "Archive & Copy", d.UUID); err != nil {
		t.Fatalf("run: %v", err)
	}
	if clip.v != "original" {
		t.Fatalf("clipboard = %q", clip.v)
	}
	got, _ := s.Get(ctx, d.UUID)
	if !got.IsArchived {
		t.Fatalf("not archived: %+v", got)
	}
}

func TestActionRunnerTagAndTemplate(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()

	d, _ := s.Create(ctx, "hello", CreateOptions{})
	runner := NewActionRunner(s)
	runner.Register(Action{
		Name: "Tag & Upper",
		Steps: []ActionStep{
			{Type: StepTag, Config: map[string]interface{}{"tags": []string{"done"}}},
			{Type: StepTemplate, Config: map[string]interface{}{"template": "[[draft_content]]"}},
		},
		AfterSuccess: "tag",
	})

	if _, err := runner.Run(ctx, "Tag & Upper", d.UUID); err != nil {
		t.Fatalf("run: %v", err)
	}
	got, _ := s.Get(ctx, d.UUID)
	if !contains(got.Tags, "done") {
		t.Fatalf("tags = %v", got.Tags)
	}
}

func TestActionRunnerRunOnText(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	runner := NewActionRunner(s)
	runner.Register(Action{
		Name: "Passthrough",
		Steps: []ActionStep{
			{Type: StepTemplate, Config: map[string]interface{}{"template": "[[draft_content]]"}},
		},
	})

	res, err := runner.RunOnText(ctx, "Passthrough", "hello")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !res.CreatedDraft {
		t.Fatal("expected created draft")
	}
}

func TestActionRunnerNotFound(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	runner := NewActionRunner(s)
	if _, err := runner.Run(ctx, "nope", "x"); err == nil {
		t.Fatal("expected action not found")
	}
}
