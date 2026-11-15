package core_test

import (
	"context"
	"testing"

	"github.com/nerveband/drafts-applescript-cli/core"
	"github.com/nerveband/drafts-applescript-cli/core/storetest"
)

// sqliteBackend adapts SQLiteStore to the suite's WorkspaceSeeder (see
// memory_conformance_test.go for why the bridge lives in the runners).
type sqliteBackend struct{ *core.SQLiteStore }

func (s sqliteBackend) SeedWorkspace(ctx context.Context, ws core.Workspace) error {
	return s.SaveWorkspace(ctx, ws)
}

// TestSQLiteStoreConformance runs the shared SPEC-CORE-01 suite against the
// production backend on an isolated in-memory database.
func TestSQLiteStoreConformance(t *testing.T) {
	storetest.Run(t, "sqlite", func(tb testing.TB) core.Store {
		s, err := core.NewSQLiteStore(":memory:")
		if err != nil {
			tb.Fatalf("NewSQLiteStore(:memory:): %v", err)
		}
		return sqliteBackend{s}
	})
}
