// Package storetest implements the backend conformance suite for core.Store
// (SPEC-CORE-01): one table of behavioural cases, run against every backend
// (MemoryStore, SQLiteStore), so the two can no longer diverge test-suite by
// test-suite.
//
// The suite asserts only behaviour that both backends already share. Known or
// unresolved divergences appear as documented skip entries named
// "Divergence/…" — each carries the spec id that owns the fix. Flipping a
// documented skip into a real case is a one-line diff inside the production
// PR that fixes the divergence, which is the point: the case lives here first,
// not in whichever backend got its own test (the anti-pattern behind the PR #11
// bug batch — see docs/drafto/06-HANDOFF.md §3.1).
package storetest

import (
	"context"
	"errors"
	"io"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/nerveband/drafts-applescript-cli/core"
)

// timeLayout mirrors the canonical timestamp layout used by the core
// ("2006-01-02 15:04:05"). It is duplicated here so the suite can compute the
// exact expected timestamp strings when it pins the clock.
const timeLayout = "2006-01-02 15:04:05"

// Factory creates a fresh, empty Store for a single conformance case. The
// store must start empty; it is closed via io.Closer after the case when the
// backend implements it.
type Factory func(tb testing.TB) core.Store

// WorkspaceSeeder lets a runner seed workspace definitions through the
// backend-specific write API. SaveWorkspace is deliberately NOT part of
// core.Store yet — the two backends expose divergent signatures (audit D3/F1)
// — and SPEC-CORE-02 will move it into the interface. Until then the seeder
// lives at the runner level, so the shared suite still verifies workspace
// *read* semantics (list, active, Query override, Create stamping).
type WorkspaceSeeder interface {
	SeedWorkspace(ctx context.Context, ws core.Workspace) error
}

// conformanceCase is one named behavioural expectation.
type conformanceCase struct {
	name string
	fn   func(t *testing.T, s core.Store)
}

// Run executes the whole conformance table against the backend produced by f.
// name only labels the backend in failures. Subtests are sequential on
// purpose: cases that pin the clock mutate the package-level core.NowFunc,
// and that is shared state.
func Run(t *testing.T, name string, f Factory) {
	t.Helper()
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			store := f(t)
			if store == nil {
				t.Fatalf("%s: factory returned a nil store", name)
			}
			if c, ok := store.(io.Closer); ok {
				t.Cleanup(func() {
					if err := c.Close(); err != nil {
						t.Errorf("%s: close store: %v", name, err)
					}
				})
			}
			tc.fn(t, store)
		})
	}
}

// ---- case helpers -----------------------------------------------------------

func mustCreate(t *testing.T, s core.Store, content string) core.Draft {
	t.Helper()
	return mustCreateWith(t, s, content, core.CreateOptions{})
}

func mustCreateWith(t *testing.T, s core.Store, content string, opts core.CreateOptions) core.Draft {
	t.Helper()
	d, err := s.Create(context.Background(), content, opts)
	if err != nil {
		t.Fatalf("Create(%q): %v", content, err)
	}
	return d
}

func mustGet(t *testing.T, s core.Store, uuid string) core.Draft {
	t.Helper()
	d, err := s.Get(context.Background(), uuid)
	if err != nil {
		t.Fatalf("Get(%s): %v", uuid, err)
	}
	return d
}

func mustQuery(t *testing.T, s core.Store, q core.Query) []core.Draft {
	t.Helper()
	ds, err := s.Query(context.Background(), q)
	if err != nil {
		t.Fatalf("Query(%+v): %v", q, err)
	}
	return ds
}

// act runs a void store mutation and fails the test on error.
func act(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

// wantErrIs asserts err wraps target.
func wantErrIs(t *testing.T, what string, err, target error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected error %v, got nil", what, target)
	}
	if !errors.Is(err, target) {
		t.Errorf("%s: got error %v, want it to wrap %v", what, err, target)
	}
}

func seedWorkspace(t *testing.T, s core.Store, ws core.Workspace) {
	t.Helper()
	seeder, ok := s.(WorkspaceSeeder)
	if !ok {
		t.Skipf("%T exposes no WorkspaceSeeder (SPEC-CORE-02 will move SaveWorkspace into core.Store)", s)
	}
	if err := seeder.SeedWorkspace(context.Background(), ws); err != nil {
		t.Fatalf("SeedWorkspace(%q): %v", ws.Name, err)
	}
}

// getErr calls Get ignoring the draft, for wantErrIs assertions.
func getErr(s core.Store, uuid string) error {
	_, err := s.Get(context.Background(), uuid)
	return err
}

// skipDiverge documents a known Memory↔SQLite divergence as a skipped case.
// The spec id in the message owns the fix; deleting the skip and asserting the
// behaviour is the acceptance test for that fix.
func skipDiverge(t *testing.T, spec, why string) {
	t.Helper()
	t.Skipf("DIVERGE(%s): %s", spec, why)
}

// setClock pins core.NowFunc to a fixed base instant for the duration of the
// case and returns the base plus an advance function: at(d) makes every clock
// read return base+d. Exact-string timestamp assertions become possible and
// same-second ties disappear.
func setClock(t *testing.T) (base time.Time, at func(d time.Duration)) {
	t.Helper()
	base = time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	cur := base
	old := core.NowFunc
	core.NowFunc = func() time.Time { return cur }
	t.Cleanup(func() { core.NowFunc = old })
	return base, func(d time.Duration) { cur = base.Add(d) }
}

// ts formats an instant the way the core stores it.
func ts(t time.Time) string { return t.Format(timeLayout) }

// ---- assertion helpers ------------------------------------------------------

func uuidsOf(ds []core.Draft) []string {
	out := make([]string, len(ds))
	for i, d := range ds {
		out[i] = d.UUID
	}
	return out
}

// wantUUIDs asserts a query result is exactly the listed drafts, in order.
func wantUUIDs(t *testing.T, ds []core.Draft, want ...string) {
	t.Helper()
	if want == nil {
		want = []string{}
	}
	if got := uuidsOf(ds); !reflect.DeepEqual(got, want) {
		t.Errorf("query result order/identity: got %v, want %v", got, want)
	}
}

// wantAsSet asserts a query result contains exactly the listed drafts,
// ignoring order — used where the ordering contract is still open (Divergence/
// TagOrderIsContractual) or irrelevant to the case.
func wantAsSet(t *testing.T, ds []core.Draft, want ...string) {
	t.Helper()
	got := uuidsOf(ds)
	sort.Strings(got)
	w := append([]string{}, want...)
	sort.Strings(w)
	if !reflect.DeepEqual(got, w) {
		t.Errorf("query result set: got %v, want %v", got, w)
	}
}

// wantTags compares tag lists as sorted sets: the backends agree on which
// tags exist, not on the order they come back in (see Divergence/
// TagOrderIsContractual).
func wantTags(t *testing.T, what string, got []string, want ...string) {
	t.Helper()
	norm := func(in []string) []string {
		out := append([]string{}, in...)
		sort.Strings(out)
		dedup := make([]string, 0, len(out))
		for _, v := range out {
			if n := len(dedup); n == 0 || dedup[n-1] != v {
				dedup = append(dedup, v)
			}
		}
		return dedup
	}
	if g, w := norm(got), norm(want); !reflect.DeepEqual(g, w) {
		t.Errorf("%s: tags: got %v, want %v", what, g, w)
	}
}
