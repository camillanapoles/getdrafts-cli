package drafts

import "github.com/nerveband/drafts-applescript-cli/core"

// Canonical domain types live in core (the shared Drafto engine consumed by
// Android, Linux and the macOS bridge). pkg/drafts is the macOS AppleScript
// bridge; these aliases keep it a thin façade and guarantee the CLI and the
// native clients never disagree about the shape of a draft.

const Separator = core.Separator

type (
	Draft  = core.Draft
	Folder = core.Folder
	Filter = core.Filter
	Sort   = core.Sort
)

const (
	FolderInbox   = core.FolderInbox
	FolderArchive = core.FolderArchive

	FilterInbox   = core.FilterInbox
	FilterFlagged = core.FilterFlagged
	FilterArchive = core.FilterArchive
	FilterTrash   = core.FilterTrash
	FilterAll     = core.FilterAll

	SortCreated  = core.SortCreated
	SortModified = core.SortModified
	SortAccessed = core.SortAccessed
)

// tagSeparator joins multiple tags in AppleScript output.
const tagSeparator = "|||"
