package drafts

import "github.com/nerveband/drafts-applescript-cli/core"

// Options mirror the core engine so the AppleScript bridge and the native
// clients share identical request shapes.

type (
	CreateOptions = core.CreateOptions
	ModifyOptions = core.ModifyOptions
	QueryOptions  = core.QueryOptions
)
