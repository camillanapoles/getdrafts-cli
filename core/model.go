// Package core defines the platform-agnostic domain model and storage
// abstraction shared by every Drafto client (Android, Linux CLI, macOS bridge).
//
// The Draft model is the single source of truth. pkg/drafts (the macOS
// AppleScript bridge) aliases these types so the CLI and the native clients
// never disagree about the shape of a draft.
package core

import "strings"

// Separator is the display separator used by the CLI list/select commands.
const Separator = '|'

// Draft is the canonical draft record. The base field set mirrors the
// historical pkg/drafts model so aliasing is transparent; Drafto-specific
// fields are additive (omitempty) and do not affect existing consumers.
type Draft struct {
	UUID              string   `json:"uuid"`
	Content           string   `json:"content"`
	Title             string   `json:"title"`
	Tags              []string `json:"tags"`
	IsFlagged         bool     `json:"isFlagged"`
	IsArchived        bool     `json:"isArchived"`
	IsTrashed         bool     `json:"isTrashed"`
	Folder            string   `json:"folder"`
	CreatedAt         string   `json:"createdAt"`
	ModifiedAt        string   `json:"modifiedAt"`
	CreatedLatitude   float64  `json:"createdLatitude"`
	CreatedLongitude  float64  `json:"createdLongitude"`
	ModifiedLatitude  float64  `json:"modifiedLatitude"`
	ModifiedLongitude float64  `json:"modifiedLongitude"`
	Permalink         string   `json:"permalink"`

	// Drafto extensions (additive; omitted when empty).
	Pinned    bool   `json:"pinned,omitempty"`
	Syntax    string `json:"syntax,omitempty"`
	Workspace string `json:"workspace,omitempty"`
}

// Folder identifies a draft's location. Note: "Folder" is both a type and a
// Draft field name; Go keeps these in separate namespaces (as in pkg/drafts).
type Folder int

const (
	FolderInbox Folder = iota
	FolderArchive
)

func (f Folder) String() string {
	return [...]string{"inbox", "archive"}[f]
}

// Filter selects a subset of drafts for listing/querying.
type Filter int

const (
	FilterInbox Filter = iota
	FilterFlagged
	FilterArchive
	FilterTrash
	FilterAll
)

func (f Filter) String() string {
	return [...]string{"inbox", "flagged", "archive", "trash", "all"}[f]
}

// Sort orders query results.
type Sort int

const (
	SortCreated Sort = iota
	SortModified
	SortAccessed
)

func (s Sort) String() string {
	return [...]string{"created", "modified", "accessed"}[s]
}

// Permalink builds the Drafto deep link for a draft.
func Permalink(uuid string) string {
	return "drafto://open?uuid=" + uuid
}

// titleOf derives the display title (first non-empty line) from content.
func titleOf(content string) string {
	for _, line := range strings.Split(content, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return line
		}
	}
	return ""
}
