package core

import (
	"testing"
	"time"
)

func TestRenderTemplateTags(t *testing.T) {
	orig := NowFunc
	NowFunc = func() time.Time { return time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC) }
	defer func() { NowFunc = orig }()

	d := Draft{
		UUID:       "u1",
		Title:      "Hello",
		Content:    "body",
		CreatedAt:  "2026-01-01 00:00:00",
		ModifiedAt: "2026-01-02 00:00:00",
	}

	out := RenderTemplate("body", d, "T:[[draft_title]] U:[[draft_uuid]] D:[[date]] C:[[draft_content]]")
	want := "T:Hello U:u1 D:2026-03-04 C:body"
	if out != want {
		t.Fatalf("out = %q, want %q", out, want)
	}
}

func TestRenderTemplateLeavesUnknownTags(t *testing.T) {
	d := Draft{UUID: "u", Title: "t", Content: "c"}
	out := RenderTemplate("c", d, "[[unknown]]")
	if out != "[[unknown]]" {
		t.Fatalf("out = %q", out)
	}
}
