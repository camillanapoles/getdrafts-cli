package core

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteStore is a SQLite-backed Store implementation. It is the production
// backend for the Drafto clients (Android, Linux). FTS5 provides full-text
// search over content and title (parity: Drafts search). The schema, trash
// retention and workspace semantics mirror MemoryStore exactly so the two
// backends are interchangeable.
//
// SQLite is opened via modernc.org/sqlite (pure Go, no CGO) so the same
// binary runs on Linux, Android (gomobile) and any Go host.
type SQLiteStore struct {
	db             *sql.DB
	trashRetention time.Duration
}

// NewSQLiteStore opens (or creates) a SQLite database at path and returns a
// Store. The schema is created if needed. Trash retention defaults to 30
// days (Drafts parity); use SetTrashRetention to change or disable it.
// Pass ":memory:" for an in-memory database (useful for tests).
func NewSQLiteStore(path string) (*SQLiteStore, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}
	s := &SQLiteStore{db: db, trashRetention: defaultTrashRetention}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *SQLiteStore) Close() error { return s.db.Close() }

// SetTrashRetention sets the trash auto-delete window. A duration <= 0
// disables automatic expiration (manual PurgeTrash still works).
func (s *SQLiteStore) SetTrashRetention(d time.Duration) {
	if d < 0 {
		d = 0
	}
	s.trashRetention = d
}

// TrashRetention returns the configured trash auto-delete window (0 = off).
func (s *SQLiteStore) TrashRetention() time.Duration { return s.trashRetention }

// migrate creates the schema if it does not exist. It is idempotent.
func (s *SQLiteStore) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS drafts (
			uuid         TEXT PRIMARY KEY,
			content      TEXT NOT NULL,
			title        TEXT NOT NULL DEFAULT '',
			folder       TEXT NOT NULL DEFAULT 'inbox',
			flagged      INTEGER NOT NULL DEFAULT 0,
			pinned       INTEGER NOT NULL DEFAULT 0,
			syntax       TEXT NOT NULL DEFAULT '',
			workspace    TEXT NOT NULL DEFAULT '',
			created_at   TEXT NOT NULL,
			modified_at  TEXT NOT NULL,
			created_lat  REAL NOT NULL DEFAULT 0,
			created_lon  REAL NOT NULL DEFAULT 0,
			modified_lat REAL NOT NULL DEFAULT 0,
			modified_lon REAL NOT NULL DEFAULT 0,
			permalink    TEXT NOT NULL DEFAULT '',
			accessed_at  TEXT NOT NULL DEFAULT '',
			trashed_at   TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE VIRTUAL TABLE IF NOT EXISTS drafts_fts USING fts5(
			content, title, content='drafts', content_rowid='rowid'
		)`,
		`CREATE TRIGGER IF NOT EXISTS drafts_ai AFTER INSERT ON drafts BEGIN
			INSERT INTO drafts_fts(rowid, content, title) VALUES (new.rowid, new.content, new.title);
		END`,
		`CREATE TRIGGER IF NOT EXISTS drafts_ad AFTER DELETE ON drafts BEGIN
			INSERT INTO drafts_fts(drafts_fts, rowid, content, title)
			VALUES('delete', old.rowid, old.content, old.title);
		END`,
		`CREATE TRIGGER IF NOT EXISTS drafts_au AFTER UPDATE ON drafts BEGIN
			INSERT INTO drafts_fts(drafts_fts, rowid, content, title)
			VALUES('delete', old.rowid, old.content, old.title);
			INSERT INTO drafts_fts(rowid, content, title) VALUES (new.rowid, new.content, new.title);
		END`,
		`CREATE TABLE IF NOT EXISTS tags (
			draft_uuid TEXT NOT NULL REFERENCES drafts(uuid) ON DELETE CASCADE,
			tag        TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_tags_tag ON tags(tag)`,
		`CREATE INDEX IF NOT EXISTS idx_tags_uuid ON tags(draft_uuid)`,
		`CREATE TABLE IF NOT EXISTS workspaces (
			name         TEXT PRIMARY KEY,
			folder       TEXT NOT NULL DEFAULT '',
			search       TEXT NOT NULL DEFAULT '',
			tags         TEXT NOT NULL DEFAULT '',
			omit_tags    TEXT NOT NULL DEFAULT '',
			sort         TEXT NOT NULL DEFAULT 'created',
			sort_desc    INTEGER NOT NULL DEFAULT 0,
			flagged_top  INTEGER NOT NULL DEFAULT 0,
			action_group TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS settings (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL DEFAULT ''
		)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	return nil
}

// Create adds a new draft and returns it.
func (s *SQLiteStore) Create(ctx context.Context, content string, opts CreateOptions) (Draft, error) {
	uuid := newUUID()
	ts := nowStr()
	folder := "inbox"
	if opts.Folder == FolderArchive {
		folder = "archive"
	}
	d := Draft{
		UUID:       uuid,
		Content:    content,
		Title:      titleOf(content),
		Tags:       append([]string{}, opts.Tags...),
		IsFlagged:  opts.Flagged,
		Folder:     folder,
		CreatedAt:  ts,
		ModifiedAt: ts,
		Permalink:  Permalink(uuid),
		Workspace:  s.activeWorkspace(),
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Draft{}, err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `INSERT INTO drafts
		(uuid, content, title, folder, flagged, pinned, syntax, workspace, created_at, modified_at,
		 created_lat, created_lon, modified_lat, modified_lon, permalink, accessed_at, trashed_at)
		VALUES (?,?,?,?,?,0,'',?,?,?,0,0,0,0,?,'','')`,
		d.UUID, d.Content, d.Title, d.Folder, d.IsFlagged, d.Workspace,
		d.CreatedAt, d.ModifiedAt, d.Permalink); err != nil {
		return Draft{}, fmt.Errorf("insert draft: %w", err)
	}

	for _, t := range d.Tags {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO tags(draft_uuid, tag) VALUES (?,?)`, d.UUID, t); err != nil {
			return Draft{}, err
		}
	}

	if err := tx.Commit(); err != nil {
		return Draft{}, err
	}
	return d, nil
}

// Get returns a draft by UUID. Accessing a draft refreshes its AccessedAt
// (parity: Drafts "accessed" sort); the modification time is untouched.
func (s *SQLiteStore) Get(ctx context.Context, uuid string) (Draft, error) {
	s.purgeExpiredTrash(ctx)

	row := s.db.QueryRowContext(ctx, `SELECT uuid, content, title, folder, flagged, pinned, syntax, workspace,
		created_at, modified_at, created_lat, created_lon, modified_lat, modified_lon, permalink, accessed_at, trashed_at
		FROM drafts WHERE uuid = ?`, uuid)

	d, err := scanDraft(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return Draft{}, fmt.Errorf("%w: %s", ErrDraftNotFound, uuid)
		}
		return Draft{}, err
	}

	tags, err := s.loadTags(ctx, []string{uuid})
	if err != nil {
		return Draft{}, err
	}
	d.Tags = tags[uuid]

	// Refresh AccessedAt.
	if _, err := s.db.ExecContext(ctx, `UPDATE drafts SET accessed_at = ? WHERE uuid = ?`, nowStr(), uuid); err != nil {
		return Draft{}, err
	}
	return d, nil
}

// Query returns drafts matching the query, sorted and limited. Trashed
// drafts past the retention window are auto-purged before the filters run.
func (s *SQLiteStore) Query(ctx context.Context, q Query) ([]Draft, error) {
	s.purgeExpiredTrash(ctx)

	filter := q.Filter
	search := q.Search
	incTags := q.Tags
	omitTags := q.OmitTags

	if q.Workspace != "" {
		ws, err := s.getWorkspace(ctx, q.Workspace)
		if err != nil {
			return nil, err
		}
		if ws.Folder != "" {
			filter = filterFromFolder(ws.Folder)
		}
		if ws.Search != "" {
			search = ws.Search
		}
		if len(ws.Tags) > 0 {
			incTags = ws.Tags
		}
		if len(ws.OmitTags) > 0 {
			omitTags = ws.OmitTags
		}
	}

	// Build the base SQL: filter by folder.
	var folders []string
	switch filter {
	case FilterInbox:
		folders = []string{"inbox"}
	case FilterFlagged:
		folders = []string{"inbox"} // flagged is added as a condition below
	case FilterArchive:
		folders = []string{"archive"}
	case FilterTrash:
		folders = []string{"trash"}
	case FilterAll:
		folders = []string{"inbox", "archive"}
	default:
		folders = []string{"inbox"}
	}

	// Build the SQL query.
	query := `SELECT uuid, content, title, folder, flagged, pinned, syntax, workspace,
		created_at, modified_at, created_lat, created_lon, modified_lat, modified_lon, permalink, accessed_at, trashed_at
		FROM drafts WHERE folder IN (` + placeholders(len(folders)) + `)`
	args := make([]interface{}, len(folders))
	for i, f := range folders {
		args[i] = f
	}

	if filter == FilterFlagged {
		query += ` AND flagged = 1`
	}

	// FTS5 search.
	if search != "" {
		ftsQuery := ftsPhrase(search)
		query += ` AND rowid IN (SELECT rowid FROM drafts_fts WHERE drafts_fts MATCH ?)`
		args = append(args, ftsQuery)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Draft{}
	uuids := []string{}
	for rows.Next() {
		d, err := scanDraft(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
		uuids = append(uuids, d.UUID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Load tags for all matching drafts.
	tagMap, err := s.loadTags(ctx, uuids)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Tags = tagMap[out[i].UUID]
	}

	// Tag filtering in memory (consistent with MemoryStore semantics).
	filtered := out[:0]
	for _, d := range out {
		if !hasAllTags(d, incTags) || !hasNoTags(d, omitTags) {
			continue
		}
		filtered = append(filtered, d)
	}
	out = filtered

	out = applySorting(out, q)

	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

// Update mutates a draft atomically.
func (s *SQLiteStore) Update(ctx context.Context, uuid string, mutate func(*Draft) error) (Draft, error) {
	s.purgeExpiredTrash(ctx)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Draft{}, err
	}
	defer tx.Rollback()

	row := tx.QueryRowContext(ctx, `SELECT uuid, content, title, folder, flagged, pinned, syntax, workspace,
		created_at, modified_at, created_lat, created_lon, modified_lat, modified_lon, permalink, accessed_at, trashed_at
		FROM drafts WHERE uuid = ?`, uuid)
	d, err := scanDraft(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return Draft{}, fmt.Errorf("%w: %s", ErrDraftNotFound, uuid)
		}
		return Draft{}, err
	}

	tags, err := loadTagsTx(ctx, tx, []string{uuid})
	if err != nil {
		return Draft{}, err
	}
	d.Tags = tags[uuid]

	if err := mutate(&d); err != nil {
		return Draft{}, err
	}

	d.ModifiedAt = nowStr()
	// Trash lifecycle invariant: entering the trash stamps TrashedAt; any
	// move out of the trash clears it.
	if d.Folder == "trash" {
		if d.TrashedAt == "" {
			d.TrashedAt = d.ModifiedAt
		}
	} else {
		d.TrashedAt = ""
	}
	d.IsArchived = d.Folder == "archive"
	d.IsTrashed = d.Folder == "trash"

	// Update draft columns.
	if _, err := tx.ExecContext(ctx, `UPDATE drafts SET
		content=?, title=?, folder=?, flagged=?, pinned=?, syntax=?, workspace=?,
		modified_at=?, modified_lat=?, modified_lon=?, accessed_at=?, trashed_at=?
		WHERE uuid=?`,
		d.Content, d.Title, d.Folder, d.IsFlagged, d.Pinned, d.Syntax, d.Workspace,
		d.ModifiedAt, d.ModifiedLatitude, d.ModifiedLongitude, d.AccessedAt, d.TrashedAt,
		uuid); err != nil {
		return Draft{}, err
	}

	// Reconcile tags: delete all old tags for this draft, insert the new set.
	if _, err := tx.ExecContext(ctx, `DELETE FROM tags WHERE draft_uuid = ?`, uuid); err != nil {
		return Draft{}, err
	}
	for _, t := range d.Tags {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO tags(draft_uuid, tag) VALUES (?,?)`, uuid, t); err != nil {
			return Draft{}, err
		}
	}

	if err := tx.Commit(); err != nil {
		return Draft{}, err
	}
	return d, nil
}

// Replace overwrites a draft's content.
func (s *SQLiteStore) Replace(ctx context.Context, uuid, content string) (Draft, error) {
	return s.Update(ctx, uuid, func(d *Draft) error {
		d.Content = content
		d.Title = titleOf(content)
		return nil
	})
}

// Prepend inserts text before the existing content.
func (s *SQLiteStore) Prepend(ctx context.Context, uuid, text string) (Draft, error) {
	return s.Update(ctx, uuid, func(d *Draft) error {
		d.Content = text + "\n" + d.Content
		d.Title = titleOf(d.Content)
		return nil
	})
}

// Append inserts text after the existing content.
func (s *SQLiteStore) Append(ctx context.Context, uuid, text string) (Draft, error) {
	return s.Update(ctx, uuid, func(d *Draft) error {
		d.Content = d.Content + "\n" + text
		return nil
	})
}

// Trash moves a draft to trash.
func (s *SQLiteStore) Trash(ctx context.Context, uuid string) error {
	_, err := s.Update(ctx, uuid, func(d *Draft) error {
		d.Folder = "trash"
		d.IsTrashed = true
		d.IsArchived = false
		return nil
	})
	return err
}

// EmptyTrash permanently removes all trashed drafts.
func (s *SQLiteStore) EmptyTrash(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM drafts WHERE folder = 'trash'`)
	return err
}

// PurgeTrash permanently removes trashed drafts older than olderThan
// (parity: Drafts trash expiry). olderThan <= 0 purges the entire trash.
// It implements the TrashPruner capability. Returns the number of drafts
// removed.
func (s *SQLiteStore) PurgeTrash(ctx context.Context, olderThan time.Duration) (int, error) {
	if olderThan <= 0 {
		res, err := s.db.ExecContext(ctx, `DELETE FROM drafts WHERE folder = 'trash'`)
		if err != nil {
			return 0, err
		}
		n, _ := res.RowsAffected()
		return int(n), nil
	}

	cutoff := time.Now().Add(-olderThan).Format(timeLayout)
	res, err := s.db.ExecContext(ctx, `DELETE FROM drafts WHERE folder = 'trash' AND trashed_at != '' AND trashed_at <= ?`, cutoff)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// Archive moves a draft to archive.
func (s *SQLiteStore) Archive(ctx context.Context, uuid string) error {
	_, err := s.Update(ctx, uuid, func(d *Draft) error {
		d.Folder = "archive"
		d.IsArchived = true
		d.IsTrashed = false
		return nil
	})
	return err
}

// SetFlagged sets the flagged flag.
func (s *SQLiteStore) SetFlagged(ctx context.Context, uuid string, flagged bool) (Draft, error) {
	return s.Update(ctx, uuid, func(d *Draft) error {
		d.IsFlagged = flagged
		return nil
	})
}

// SetTags replaces the draft's tags.
func (s *SQLiteStore) SetTags(ctx context.Context, uuid string, tags []string) (Draft, error) {
	return s.Update(ctx, uuid, func(d *Draft) error {
		d.Tags = append([]string{}, tags...)
		return nil
	})
}

// AddTags unions tags onto the draft.
func (s *SQLiteStore) AddTags(ctx context.Context, uuid string, tags []string) (Draft, error) {
	return s.Update(ctx, uuid, func(d *Draft) error {
		d.Tags = unionTags(d.Tags, tags)
		return nil
	})
}

// Delete permanently removes a draft.
func (s *SQLiteStore) Delete(ctx context.Context, uuid string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM drafts WHERE uuid = ?`, uuid)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("%w: %s", ErrDraftNotFound, uuid)
	}
	return nil
}

// ListTags returns all tags in use, sorted.
func (s *SQLiteStore) ListTags(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT tag FROM tags ORDER BY tag`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Counts returns per-folder counts.
func (s *SQLiteStore) Counts(ctx context.Context) (Counts, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT folder, flagged, COUNT(*) FROM drafts GROUP BY folder, flagged`)
	if err != nil {
		return Counts{}, err
	}
	defer rows.Close()
	c := Counts{}
	for rows.Next() {
		var folder string
		var flagged int
		var n int
		if err := rows.Scan(&folder, &flagged, &n); err != nil {
			return Counts{}, err
		}
		switch folder {
		case "inbox":
			c.Inbox += n
			if flagged == 1 {
				c.Flagged += n
			}
		case "archive":
			c.Archive += n
		case "trash":
			c.Trash += n
		}
	}
	c.All = c.Inbox + c.Archive
	return c, rows.Err()
}

// Workspaces lists saved workspaces.
func (s *SQLiteStore) Workspaces(ctx context.Context) ([]Workspace, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, folder, search, tags, omit_tags, sort, sort_desc, flagged_top, action_group FROM workspaces ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Workspace{}
	for rows.Next() {
		ws, err := scanWorkspace(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ws)
	}
	return out, rows.Err()
}

// ActiveWorkspace returns the current workspace name.
func (s *SQLiteStore) ActiveWorkspace(ctx context.Context) (string, error) {
	return s.activeWorkspace(), nil
}

// SetActiveWorkspace sets the current workspace.
func (s *SQLiteStore) SetActiveWorkspace(ctx context.Context, name string) error {
	if name != "" {
		var exists int
		err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM workspaces WHERE name = ?`, name).Scan(&exists)
		if err != nil {
			return err
		}
		if exists == 0 {
			return fmt.Errorf("%w: %s", ErrWorkspaceNotFound, name)
		}
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES ('active_workspace', ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, name)
	return err
}

// SaveWorkspace persists a workspace definition.
func (s *SQLiteStore) SaveWorkspace(ctx context.Context, ws Workspace) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO workspaces(name, folder, search, tags, omit_tags, sort, sort_desc, flagged_top, action_group)
		VALUES (?,?,?,?,?,?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET
			folder=excluded.folder, search=excluded.search, tags=excluded.tags,
			omit_tags=excluded.omit_tags, sort=excluded.sort, sort_desc=excluded.sort_desc,
			flagged_top=excluded.flagged_top, action_group=excluded.action_group`,
		ws.Name, ws.Folder, ws.Search, strings.Join(ws.Tags, ","), strings.Join(ws.OmitTags, ","),
		ws.Sort.String(), ws.SortDescending, ws.FlaggedTop, ws.ActionGroup)
	return err
}

// getWorkspace returns a workspace by name.
func (s *SQLiteStore) getWorkspace(ctx context.Context, name string) (Workspace, error) {
	row := s.db.QueryRowContext(ctx, `SELECT name, folder, search, tags, omit_tags, sort, sort_desc, flagged_top, action_group FROM workspaces WHERE name = ?`, name)
	ws, err := scanWorkspace(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return Workspace{}, fmt.Errorf("%w: %s", ErrWorkspaceNotFound, name)
		}
		return Workspace{}, err
	}
	return ws, nil
}

// activeWorkspace returns the current workspace name from settings.
func (s *SQLiteStore) activeWorkspace() string {
	var name string
	_ = s.db.QueryRow(`SELECT value FROM settings WHERE key = 'active_workspace'`).Scan(&name)
	return name
}

// purgeExpiredTrash auto-purges trashed drafts past the retention window.
func (s *SQLiteStore) purgeExpiredTrash(ctx context.Context) {
	if s.trashRetention <= 0 {
		return
	}
	_, _ = s.PurgeTrash(ctx, s.trashRetention)
}

// ---- helpers --------------------------------------------------------------

// scanDraft scans a draft row from the database.
func scanDraft(row interface{ Scan(...interface{}) error }) (Draft, error) {
	var d Draft
	err := row.Scan(&d.UUID, &d.Content, &d.Title, &d.Folder, &d.IsFlagged, &d.Pinned,
		&d.Syntax, &d.Workspace, &d.CreatedAt, &d.ModifiedAt,
		&d.CreatedLatitude, &d.CreatedLongitude, &d.ModifiedLatitude, &d.ModifiedLongitude,
		&d.Permalink, &d.AccessedAt, &d.TrashedAt)
	if err != nil {
		return Draft{}, err
	}
	d.IsArchived = d.Folder == "archive"
	d.IsTrashed = d.Folder == "trash"
	return d, nil
}

// scanWorkspace scans a workspace row.
func scanWorkspace(row interface{ Scan(...interface{}) error }) (Workspace, error) {
	var ws Workspace
	var tagsStr, omitTagsStr, sortStr string
	var sortDesc, flaggedTop int
	err := row.Scan(&ws.Name, &ws.Folder, &ws.Search, &tagsStr, &omitTagsStr,
		&sortStr, &sortDesc, &flaggedTop, &ws.ActionGroup)
	if err != nil {
		return Workspace{}, err
	}
	ws.Tags = splitCSV(tagsStr)
	ws.OmitTags = splitCSV(omitTagsStr)
	ws.Sort = sortFromString(sortStr)
	ws.SortDescending = sortDesc == 1
	ws.FlaggedTop = flaggedTop == 1
	return ws, nil
}

// loadTags returns a map of uuid -> tags for the given uuids.
func (s *SQLiteStore) loadTags(ctx context.Context, uuids []string) (map[string][]string, error) {
	return loadTagsQuery(ctx, s.db, uuids)
}

// loadTagsTx loads tags within a transaction.
func loadTagsTx(ctx context.Context, tx *sql.Tx, uuids []string) (map[string][]string, error) {
	return loadTagsQuery(ctx, tx, uuids)
}

// loadTagsQuery loads tags for the given uuids using either a *sql.DB or *sql.Tx.
func loadTagsQuery(ctx context.Context, q interface {
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
}, uuids []string) (map[string][]string, error) {
	out := map[string][]string{}
	if len(uuids) == 0 {
		return out, nil
	}
	args := make([]interface{}, len(uuids))
	for i, u := range uuids {
		args[i] = u
	}
	rows, err := q.QueryContext(ctx, `SELECT draft_uuid, tag FROM tags WHERE draft_uuid IN (`+placeholders(len(uuids))+`) ORDER BY tag`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var uuid, tag string
		if err := rows.Scan(&uuid, &tag); err != nil {
			return nil, err
		}
		out[uuid] = append(out[uuid], tag)
	}
	return out, rows.Err()
}

// placeholders returns a string of ? placeholders joined by commas.
func placeholders(n int) string {
	if n <= 0 {
		return "''"
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// ftsPhrase wraps a search string in double quotes for FTS5 phrase search,
// escaping embedded quotes. This prevents FTS5 query syntax injection while
// still matching the search terms as a phrase.
func ftsPhrase(s string) string {
	s = strings.ReplaceAll(s, `"`, `""`)
	return `"` + s + `"`
}

// splitCSV splits a comma-separated string, filtering empty entries.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// sortFromString maps a Sort string to a Sort constant.
func sortFromString(s string) Sort {
	switch s {
	case "modified":
		return SortModified
	case "accessed":
		return SortAccessed
	case "name":
		return SortName
	default:
		return SortCreated
	}
}

// Ensure SQLiteStore satisfies Store.
var _ Store = (*SQLiteStore)(nil)
// Ensure SQLiteStore satisfies TrashPruner.
var _ TrashPruner = (*SQLiteStore)(nil)
