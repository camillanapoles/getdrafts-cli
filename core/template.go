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
	now := timeNow()

	replacer := strings.NewReplacer(
		"[[draft_content]]", content,
		"[[draft_title]]", d.Title,
		"[[draft_uuid]]", d.UUID,
		"[[date]]", now.Format("2006-01-02"),
		"[[date_created]]", d.CreatedAt,
		"[[date_modified]]", d.ModifiedAt,
	)
	return replacer.Replace(template)
}
