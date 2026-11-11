package core

// CreateOptions controls draft creation.
type CreateOptions struct {
	Tags    []string
	Folder  Folder
	Flagged bool
	Action  string
}

// QueryOptions carries sort/tag options (parity with the AppleScript bridge).
type QueryOptions struct {
	Tags             []string
	OmitTags         []string
	Sort             Sort
	SortDescending   bool
	SortFlaggedToTop bool
}

// ModifyOptions controls append/prepend modifications.
type ModifyOptions struct {
	Tags   []string
	Action string
}

// Query is the full set of filters for Store.Query.
type Query struct {
	Filter           Filter
	Search           string
	Tags             []string
	OmitTags         []string
	Workspace        string
	Sort             Sort
	SortDescending   bool
	SortFlaggedToTop bool
	Limit            int // 0 means no limit
	Full             bool
}

// Workspace is a saved filter/sort configuration applied to a draft list.
type Workspace struct {
	Name           string   `json:"name"`
	Folder         string   `json:"folder"`
	Search         string   `json:"search,omitempty"`
	Tags           []string `json:"tags,omitempty"`
	OmitTags       []string `json:"omit_tags,omitempty"`
	Sort           Sort     `json:"-"`
	SortDescending bool     `json:"sort_desc"`
	FlaggedTop     bool     `json:"flagged_top"`
	ActionGroup    string   `json:"action_group,omitempty"`
}

// Counts summarizes draft counts per folder.
type Counts struct {
	Inbox   int `json:"inbox"`
	Flagged int `json:"flagged"`
	Archive int `json:"archive"`
	Trash   int `json:"trash"`
	All     int `json:"all"`
}
