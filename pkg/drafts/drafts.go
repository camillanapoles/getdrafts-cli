package drafts

import (
	"fmt"
	"strings"
)

// tagSeparator is declared in struct.go (shared with the core aliases).

type ActionRunResult struct {
	UUID         string `json:"uuid"`
	CreatedDraft bool   `json:"createdDraft"`
}

// Create a new draft. Return new draft's UUID.
func Create(text string, opt CreateOptions) (string, error) {
	folder := "inbox"
	if opt.Folder == FolderArchive {
		folder = "archive"
	}

	flaggedStr := "false"
	if opt.Flagged {
		flaggedStr = "true"
	}

	script := fmt.Sprintf(`tell application "Drafts"
	set d to make new draft with properties {content:"%s", flagged:%s, tag list:%s}
	set folder of d to %s
	return id of d
end tell`, escapeForAppleScript(text), flaggedStr, tagsToAppleScript(opt.Tags), folder)

	uuid, err := runAppleScript(script)
	if err != nil {
		return "", err
	}

	if opt.Action != "" {
		if err := RunActionOnDraft(opt.Action, uuid); err != nil {
			return uuid, err
		}
	}

	return uuid, nil
}

// Prepend to an existing draft.
func Prepend(uuid, text string, opt ModifyOptions) error {
	exists, err := DraftExists(uuid)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%w: %s", ErrDraftNotFound, uuid)
	}

	script := fmt.Sprintf(`tell application "Drafts"
	set d to draft id "%s"
	set content of d to "%s" & linefeed & (content of d)
end tell`, escapeForAppleScript(uuid), escapeForAppleScript(text))

	if _, err := runAppleScript(script); err != nil {
		return err
	}

	if len(opt.Tags) > 0 {
		if err := Tag(uuid, opt.Tags...); err != nil {
			return err
		}
	}
	if opt.Action != "" {
		if err := RunActionOnDraft(opt.Action, uuid); err != nil {
			return err
		}
	}

	return nil
}

// Append to an existing draft.
func Append(uuid, text string, opt ModifyOptions) error {
	exists, err := DraftExists(uuid)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%w: %s", ErrDraftNotFound, uuid)
	}

	script := fmt.Sprintf(`tell application "Drafts"
	set d to draft id "%s"
	set content of d to (content of d) & linefeed & "%s"
end tell`, escapeForAppleScript(uuid), escapeForAppleScript(text))

	if _, err := runAppleScript(script); err != nil {
		return err
	}

	if len(opt.Tags) > 0 {
		if err := Tag(uuid, opt.Tags...); err != nil {
			return err
		}
	}
	if opt.Action != "" {
		if err := RunActionOnDraft(opt.Action, uuid); err != nil {
			return err
		}
	}

	return nil
}

// Replace content of an existing draft.
func Replace(uuid, text string) error {
	exists, err := DraftExists(uuid)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%w: %s", ErrDraftNotFound, uuid)
	}

	script := fmt.Sprintf(`tell application "Drafts"
	set d to draft id "%s"
	set content of d to "%s"
end tell`, escapeForAppleScript(uuid), escapeForAppleScript(text))

	_, err = runAppleScript(script)
	return err
}

// Trash a draft.
func Trash(uuid string) error {
	exists, err := DraftExists(uuid)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%w: %s", ErrDraftNotFound, uuid)
	}

	script := fmt.Sprintf(`tell application "Drafts"
	set d to draft id "%s"
	set folder of d to trash
end tell`, escapeForAppleScript(uuid))

	_, err = runAppleScript(script)
	return err
}

// Archive a draft.
func Archive(uuid string) error {
	exists, err := DraftExists(uuid)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%w: %s", ErrDraftNotFound, uuid)
	}

	script := fmt.Sprintf(`tell application "Drafts"
	set d to draft id "%s"
	set folder of d to archive
end tell`, escapeForAppleScript(uuid))

	_, err = runAppleScript(script)
	return err
}

// Tag adds tags to a draft.
func Tag(uuid string, tags ...string) error {
	if len(tags) == 0 {
		return nil
	}

	exists, err := DraftExists(uuid)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%w: %s", ErrDraftNotFound, uuid)
	}

	script := fmt.Sprintf(`tell application "Drafts"
	set d to draft id "%s"
	set existingTags to tag list of d
	set newTags to %s
	repeat with t in newTags
		if t is not in existingTags then
			set end of existingTags to t
		end if
	end repeat
	set tag list of d to existingTags
end tell`, escapeForAppleScript(uuid), tagsToAppleScript(tags))

	_, err = runAppleScript(script)
	return err
}

// SetFlagged sets the flagged status of a draft.
func SetFlagged(uuid string, flagged bool) error {
	exists, err := DraftExists(uuid)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%w: %s", ErrDraftNotFound, uuid)
	}

	flaggedStr := "false"
	if flagged {
		flaggedStr = "true"
	}
	script := fmt.Sprintf(`tell application "Drafts"
	set d to draft id "%s"
	set flagged of d to %s
end tell`, escapeForAppleScript(uuid), flaggedStr)

	_, err = runAppleScript(script)
	return err
}

// Get content of draft.
func Get(uuid string) (Draft, error) {
	exists, err := DraftExists(uuid)
	if err != nil {
		return Draft{}, err
	}
	if !exists {
		return Draft{}, fmt.Errorf("%w: %s", ErrDraftNotFound, uuid)
	}

	script := fmt.Sprintf(`tell application "Drafts"
	set d to draft id "%s"
	set folder_name to folder of d as string
	set is_archived to false
	set is_trashed to false
	if folder_name is "archive" then
		set is_archived to true
	else if folder_name is "trash" then
		set is_trashed to true
	end if
	set tag_list to tag list of d
	set tag_str to ""
	repeat with t in tag_list
		if tag_str is not "" then
			set tag_str to tag_str & "|||"
		end if
		set tag_str to tag_str & t
	end repeat
	return (id of d) & "	" & (title of d) & "	" & (content of d) & "	" & folder_name & "	" & (flagged of d) & "	" & is_archived & "	" & is_trashed & "	" & tag_str & "	" & ((creation date of d) as string) & "	" & ((modification date of d) as string) & "	" & (permalink of d) & "	" & ((creation latitude of d) as string) & "	" & ((creation longitude of d) as string) & "	" & ((modification latitude of d) as string) & "	" & ((modification longitude of d) as string)
end tell`, escapeForAppleScript(uuid))

	output, err := runAppleScript(script)
	if err != nil {
		return Draft{}, err
	}

	return parseDraftFromAppleScript(output), nil
}

// parseDraftFromAppleScript parses tab-separated AppleScript output into a Draft.
func parseDraftFromAppleScript(output string) Draft {
	parts := strings.Split(output, "\t")
	if len(parts) < 11 {
		return Draft{}
	}

	tags := []string{}
	if parts[7] != "" {
		tags = strings.Split(parts[7], tagSeparator)
	}

	d := Draft{
		UUID:       parts[0],
		Title:      parts[1],
		Content:    parts[2],
		Folder:     parts[3],
		IsFlagged:  parts[4] == "true",
		IsArchived: parts[5] == "true",
		IsTrashed:  parts[6] == "true",
		Tags:       tags,
		CreatedAt:  parts[8],
		ModifiedAt: parts[9],
		Permalink:  parts[10],
	}

	if len(parts) > 11 {
		fmt.Sscanf(parts[11], "%f", &d.CreatedLatitude)
	}
	if len(parts) > 12 {
		fmt.Sscanf(parts[12], "%f", &d.CreatedLongitude)
	}
	if len(parts) > 13 {
		fmt.Sscanf(parts[13], "%f", &d.ModifiedLatitude)
	}
	if len(parts) > 14 {
		fmt.Sscanf(parts[14], "%f", &d.ModifiedLongitude)
	}

	return d
}

// Query for drafts.
func Query(queryString string, filter Filter, opt QueryOptions) ([]Draft, error) {
	return queryDrafts("every draft", queryString, filter, opt)
}

func queryDrafts(scope, queryString string, filter Filter, opt QueryOptions) ([]Draft, error) {
	whereClause := buildWhereClause(filter, queryString, opt)

	script := fmt.Sprintf(`tell application "Drafts"
	set output to ""
	set allDrafts to %s%s
	repeat with d in allDrafts
		set folder_name to folder of d as string
		set is_archived to false
		set is_trashed to false
		if folder_name is "archive" then
			set is_archived to true
		else if folder_name is "trash" then
			set is_trashed to true
		end if
		set tag_list to tag list of d
		set tag_str to ""
		repeat with t in tag_list
			if tag_str is not "" then
				set tag_str to tag_str & "|||"
			end if
			set tag_str to tag_str & t
		end repeat
		set line_out to (id of d) & "	" & (title of d) & "	" & (content of d) & "	" & folder_name & "	" & (flagged of d) & "	" & is_archived & "	" & is_trashed & "	" & tag_str & "	" & ((creation date of d) as string) & "	" & ((modification date of d) as string) & "	" & (permalink of d) & "	" & ((creation latitude of d) as string) & "	" & ((creation longitude of d) as string) & "	" & ((modification latitude of d) as string) & "	" & ((modification longitude of d) as string)
		if output is "" then
			set output to line_out
		else
			set output to output & linefeed & line_out
		end if
	end repeat
	return output
end tell`, scope, whereClause)

	output, err := runAppleScript(script)
	if err != nil {
		return []Draft{}, err
	}

	if output == "" {
		return []Draft{}, nil
	}

	lines := strings.Split(output, "\n")
	drafts := make([]Draft, 0, len(lines))
	for _, line := range lines {
		if line != "" {
			d := parseDraftFromAppleScript(line)
			if d.UUID != "" {
				drafts = append(drafts, d)
			}
		}
	}

	return applyQuerySorting(drafts, opt), nil
}

func buildWhereClause(filter Filter, queryString string, opt QueryOptions) string {
	var clauses []string

	switch filter {
	case FilterArchive:
		clauses = append(clauses, "folder is archive")
	case FilterTrash:
		clauses = append(clauses, "folder is trash")
	case FilterFlagged:
		clauses = append(clauses, "folder is inbox", "flagged is true")
	case FilterAll:
	default:
		clauses = append(clauses, "folder is inbox")
	}

	if queryString != "" {
		clauses = append(clauses, fmt.Sprintf(`content contains "%s"`, escapeForAppleScript(queryString)))
	}

	for _, tag := range opt.Tags {
		clauses = append(clauses, fmt.Sprintf(`query tag names contains "#%s#"`, escapeForAppleScript(tag)))
	}

	for _, tag := range opt.OmitTags {
		clauses = append(clauses, fmt.Sprintf(`query tag names does not contain "#%s#"`, escapeForAppleScript(tag)))
	}

	if len(clauses) == 0 {
		return ""
	}

	return " whose " + strings.Join(clauses, " and ")
}

// Select sets the active draft.
func Select(uuid string) error {
	exists, err := DraftExists(uuid)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%w: %s", ErrDraftNotFound, uuid)
	}

	script := fmt.Sprintf(`tell application "Drafts"
	set d to draft id "%s"
	open d
	delay 0.1
end tell`, escapeForAppleScript(uuid))

	_, err = runAppleScript(script)
	return err
}

// Active returns the UUID of the active draft.
func Active() (string, error) {
	script := `tell application "Drafts"
	return id of current draft
end tell`

	return runAppleScript(script)
}

// RunAction runs an action with text, creating a transient draft for execution.
func RunAction(action, text string) (ActionRunResult, error) {
	exists, err := ActionExists(action)
	if err != nil {
		return ActionRunResult{}, err
	}
	if !exists {
		return ActionRunResult{}, fmt.Errorf("%w: %s", ErrActionNotFound, action)
	}

	script := fmt.Sprintf(`tell application "Drafts"
	set d to make new draft with properties {content:"%s"}
	set actionToRun to action "%s"
	perform action actionToRun on draft d
	return id of d
end tell`, escapeForAppleScript(text), escapeForAppleScript(action))

	uuid, err := runAppleScript(script)
	if err != nil {
		return ActionRunResult{}, err
	}

	return ActionRunResult{
		UUID:         uuid,
		CreatedDraft: true,
	}, nil
}

// QueryWorkspace returns drafts from a specific workspace.
func QueryWorkspace(workspace, queryString string, filter Filter, opt QueryOptions) ([]Draft, error) {
	if workspace == "" {
		return []Draft{}, nil
	}

	exists, err := WorkspaceExists(workspace)
	if err != nil {
		return []Draft{}, err
	}
	if !exists {
		return []Draft{}, fmt.Errorf("%w: %s", ErrWorkspaceNotFound, workspace)
	}

	scope := fmt.Sprintf(`every draft of workspace "%s"`, escapeForAppleScript(workspace))
	return queryDrafts(scope, queryString, filter, opt)
}

// CurrentWorkspace returns the name of the current workspace.
func CurrentWorkspace() (string, error) {
	script := `tell application "Drafts"
	return name of current workspace
end tell`

	return runAppleScript(script)
}

// OpenWorkspace opens a workspace by name.
func OpenWorkspace(name string) error {
	exists, err := WorkspaceExists(name)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%w: %s", ErrWorkspaceNotFound, name)
	}

	script := fmt.Sprintf(`tell application "Drafts"
	open workspace "%s"
end tell`, escapeForAppleScript(name))

	_, err = runAppleScript(script)
	return err
}

// Workspaces returns the names of all workspaces.
func Workspaces() ([]string, error) {
	script := `tell application "Drafts"
	set wsNames to {}
	repeat with w in (every workspace)
		set end of wsNames to (name of w)
	end repeat
	set output to ""
	repeat with n in wsNames
		if output is "" then
			set output to n
		else
			set output to output & "|||" & n
		end if
	end repeat
	return output
end tell`

	output, err := runAppleScript(script)
	if err != nil || output == "" {
		return []string{}, err
	}
	return strings.Split(output, tagSeparator), nil
}

func applyQuerySorting(items []Draft, opt QueryOptions) []Draft {
	if len(items) < 2 {
		return items
	}

	// Drafts returns newest-first from AppleScript queries. Normalize to
	// oldest-first so the CLI contract is deterministic unless descending is requested.
	reverseDrafts(items)
	if opt.SortDescending {
		reverseDrafts(items)
	}
	if opt.SortFlaggedToTop {
		flagged := make([]Draft, 0, len(items))
		others := make([]Draft, 0, len(items))
		for _, item := range items {
			if item.IsFlagged {
				flagged = append(flagged, item)
			} else {
				others = append(others, item)
			}
		}
		return append(flagged, others...)
	}

	return items
}

func reverseDrafts(items []Draft) {
	for i, j := 0, len(items)-1; i < j; i, j = i+1, j-1 {
		items[i], items[j] = items[j], items[i]
	}
}
