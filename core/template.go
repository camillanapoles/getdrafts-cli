package core

import "strings"

// RenderTemplate applies [[tag]] substitutions to a template string.
//
// Supported tags:
//
//	[[draft_content]]  current draft content
//	[[draft_title]]    draft display title
//	[[draft_uuid]]     draft UUID
//	[[date]]           today (YYYY-MM-DD)
//	[[date_created]]   draft creation timestamp
//	[[date_modified]]  draft modification timestamp
//
// The clock is NowFunc (see clock.go), which tests override for determinism.
// Unknown tags are left intact.
func RenderTemplate(content string, d Draft, template string) string {
	return RenderTemplateEnv(content, d, template, nil)
}

// RenderTemplateEnv is RenderTemplate plus an environment of extra tags:
// each entry (key K, value V) renders [[K]] as V.
//
// The action engine injects the parity tags:
//
//	[[clipboard]]  clipboard text (via the ClipboardReader capability)
//	[[workspace]]  the draft's workspace
//
// Environment values never override the built-in tags above.
func RenderTemplateEnv(content string, d Draft, template string, env map[string]string) string {
	now := timeNow()

	pairs := make([]string, 0, 12+2*len(env))
	pairs = append(pairs,
		"[[draft_content]]", content,
		"[[draft_title]]", d.Title,
		"[[draft_uuid]]", d.UUID,
		"[[date]]", now.Format("2006-01-02"),
		"[[date_created]]", d.CreatedAt,
		"[[date_modified]]", d.ModifiedAt,
	)
	for k, v := range env {
		if k == "" || builtinTag(k) {
			continue
		}
		pairs = append(pairs, "[["+k+"]]", v)
	}
	return strings.NewReplacer(pairs...).Replace(template)
}

// builtinTag reports whether key collides with a built-in template tag.
func builtinTag(key string) bool {
	switch key {
	case "draft_content", "draft_title", "draft_uuid", "date", "date_created", "date_modified":
		return true
	}
	return false
}
