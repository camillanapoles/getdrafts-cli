package core_test

import (
	"context"
	"testing"

	"github.com/nerveband/drafts-applescript-cli/core"
	"github.com/nerveband/drafts-applescript-cli/core/storetest"
)

// memoryBackend adapts MemoryStore to the suite's WorkspaceSeeder. The
// workspace write API is not in core.Store yet (divergence D3/F1 —
// SPEC-CORE-02 will land a symmetric signature), so each runner bridges it
// here instead of the shared suite knowing about backends.
type memoryBackend struct{ *core.MemoryStore }

func (m memoryBackend) SeedWorkspace(_ context.Context, ws core.Workspace) error {
	m.SaveWorkspace(ws)
	return nil
}

// TestMemoryStoreConformance runs the shared SPEC-CORE-01 suite against the
// reference backend. Every case the SQLite runner also passes is contract;
// Divergence/… entries are documented skips with a tracking spec.
func TestMemoryStoreConformance(t *testing.T) {
	storetest.Run(t, "memory", func(tb testing.TB) core.Store {
		return memoryBackend{core.NewMemoryStore()}
	})
}
