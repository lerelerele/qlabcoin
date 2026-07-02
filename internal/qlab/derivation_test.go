package qlab

import (
	"math/big"
	"testing"
)

func TestDeriveRegistryGenesisOnlyIsEmpty(t *testing.T) {
	c := newTestChain(t) // genesis only
	r, err := DeriveRegistry(c)
	if err != nil {
		t.Fatalf("DeriveRegistry: %v", err)
	}
	if got := len(r.All()); got != 0 {
		t.Fatalf("expected 0 entries from genesis-only chain, got %d", got)
	}
}

// TestDeriveRegistryFullLifecycle replays submit -> harden -> reopen and checks
// that level 5 ends reopened and level 6 is opened.
func TestDeriveRegistryFullLifecycle(t *testing.T) {
	c := newTestChain(t)
	sub := Submission{Solution: "36", CircuitHash: "sha256:abc", VerifiedAt: "2026-01-01T00:00:00Z"}
	_, _ = c.Append(Event{Type: EventSubmit, Level: 5, Submission: &sub, Timestamp: "2026-01-01T00:00:00Z"})
	_, _ = c.Append(Event{Type: EventHarden, Level: 5, Timestamp: "2026-01-02T00:00:00Z"})
	_, _ = c.Append(Event{Type: EventReopen, Level: 5, Timestamp: "2026-01-03T00:00:00Z"})

	r, err := DeriveRegistry(c)
	if err != nil {
		t.Fatalf("DeriveRegistry: %v", err)
	}
	e5, _ := r.Entry(5)
	if e5.State != StateReopened {
		t.Fatalf("level 5 state = %s, want reopened", e5.State)
	}
	if e5.Submission == nil || e5.Submission.Solution != "36" {
		t.Fatalf("submission not derived: %+v", e5.Submission)
	}
	e6, _ := r.Entry(6)
	if e6.State != StateOpen {
		t.Fatalf("level 6 state = %s, want open", e6.State)
	}
}

// TestDeriveRegistryRejectsInvalidEvent: hardening a level that was never broken
// (or opened) must fail derivation.
func TestDeriveRegistryRejectsInvalidEvent(t *testing.T) {
	c := newTestChain(t)
	// Harden without any prior submit: level 5 is open -> hardened is not a valid edge.
	_, _ = c.Append(Event{Type: EventHarden, Level: 5, Timestamp: "t"})
	if _, err := DeriveRegistry(c); err == nil {
		t.Fatal("expected DeriveRegistry to reject an invalid harden event")
	}
}

// TestDeriveRegistryRejectsBogusSolution: replay must re-run classical
// verification, so a chain whose head block records a wrong order (which no
// later prev_hash binds) is rejected instead of trusted.
func TestDeriveRegistryRejectsBogusSolution(t *testing.T) {
	c := newTestChain(t)
	sub := Submission{Solution: "35", CircuitHash: "sha256:abc", VerifiedAt: "t"} // true order is 36
	_, _ = c.Append(Event{Type: EventSubmit, Level: 5, Submission: &sub, Timestamp: "t"})
	if err := c.Verify(); err != nil {
		t.Fatalf("hash links are intact by construction: %v", err)
	}
	if _, err := DeriveRegistry(c); err == nil {
		t.Fatal("expected DeriveRegistry to reject a recorded solution that fails classical verification")
	}
}

// TestDeriveRegistryRejectsNonIntegerSolution: a toy-order submission whose
// solution is not an integer cannot have passed verification and must fail replay.
func TestDeriveRegistryRejectsNonIntegerSolution(t *testing.T) {
	c := newTestChain(t)
	sub := Submission{Solution: "not-a-number", CircuitHash: "sha256:abc", VerifiedAt: "t"}
	_, _ = c.Append(Event{Type: EventSubmit, Level: 5, Submission: &sub, Timestamp: "t"})
	if _, err := DeriveRegistry(c); err == nil {
		t.Fatal("expected DeriveRegistry to reject a non-integer toy-order solution")
	}
}

// TestDeriveRegistryPrimitiveReplay: a primitive submission replays only if its
// recorded measured outputs still pass the distribution check.
func TestDeriveRegistryPrimitiveReplay(t *testing.T) {
	good := newTestChain(t)
	sub := Submission{
		CircuitHash:     "sha256:abc",
		VerifiedAt:      "t",
		MeasuredOutputs: map[string]interface{}{"0": 512.0, "1": 488.0},
	}
	_, _ = good.Append(Event{Type: EventSubmit, Level: 1, Submission: &sub, Timestamp: "t"})
	r, err := DeriveRegistry(good)
	if err != nil {
		t.Fatalf("valid primitive submission rejected on replay: %v", err)
	}
	if e, _ := r.Entry(1); e.State != StateBroken {
		t.Fatalf("level 1 state = %s, want broken", e.State)
	}

	// Tampered counts (or a legacy submission without them) must fail replay.
	bad := newTestChain(t)
	badSub := Submission{
		CircuitHash:     "sha256:abc",
		VerifiedAt:      "t",
		MeasuredOutputs: map[string]interface{}{"0": 900.0, "1": 100.0},
	}
	_, _ = bad.Append(Event{Type: EventSubmit, Level: 1, Submission: &badSub, Timestamp: "t"})
	if _, err := DeriveRegistry(bad); err == nil {
		t.Fatal("biased primitive counts replayed without error")
	}

	missing := newTestChain(t)
	noCounts := Submission{Solution: "bell-state report", CircuitHash: "sha256:abc", VerifiedAt: "t"}
	_, _ = missing.Append(Event{Type: EventSubmit, Level: 1, Submission: &noCounts, Timestamp: "t"})
	if _, err := DeriveRegistry(missing); err == nil {
		t.Fatal("primitive submission without measured outputs replayed without error")
	}
}

// TestDeriveRegistryECDLPReplay: an ECDLP submission replays only if its
// recorded scalar still satisfies d·G == Q.
func TestDeriveRegistryECDLPReplay(t *testing.T) {
	level := FirstECDLPLevel
	good := newTestChain(t)
	sub := Submission{
		Solution:    ECDLPReferenceSolution(level),
		CircuitHash: "sha256:abc",
		VerifiedAt:  "t",
	}
	_, _ = good.Append(Event{Type: EventSubmit, Level: level, Submission: &sub, Timestamp: "t"})
	r, err := DeriveRegistry(good)
	if err != nil {
		t.Fatalf("valid ECDLP submission rejected on replay: %v", err)
	}
	if e, _ := r.Entry(level); e.State != StateBroken {
		t.Fatalf("level %d state = %s, want broken", level, e.State)
	}

	// d+1 provably fails: (d+1)G = Q+G != Q because G is not the identity.
	ref, ok := new(big.Int).SetString(ECDLPReferenceSolution(level), 10)
	if !ok {
		t.Fatal("reference solution is not decimal")
	}
	bad := newTestChain(t)
	badSub := Submission{Solution: ref.Add(ref, big.NewInt(1)).String(), CircuitHash: "sha256:abc", VerifiedAt: "t"}
	_, _ = bad.Append(Event{Type: EventSubmit, Level: level, Submission: &badSub, Timestamp: "t"})
	if _, err := DeriveRegistry(bad); err == nil {
		t.Fatal("bogus ECDLP scalar replayed without error")
	}
}

// TestDeriveRegistryRejectsDoubleSubmit: a second submit on a broken level is
// invalid and must fail derivation.
func TestDeriveRegistryRejectsDoubleSubmit(t *testing.T) {
	c := newTestChain(t)
	sub := Submission{Solution: "36", CircuitHash: "sha256:abc", VerifiedAt: "t"}
	_, _ = c.Append(Event{Type: EventSubmit, Level: 5, Submission: &sub, Timestamp: "t"})
	_, _ = c.Append(Event{Type: EventSubmit, Level: 5, Submission: &sub, Timestamp: "t"})
	if _, err := DeriveRegistry(c); err == nil {
		t.Fatal("expected DeriveRegistry to reject a double submit")
	}
}

// TestDeriveRegistryRoundTrip: saving and reloading the chain yields the same
// derived state.
func TestDeriveRegistryRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/chain.json"
	c1 := NewChain(path)
	_ = c1.Load()
	sub := Submission{Solution: "36", CircuitHash: "sha256:abc", VerifiedAt: "t"}
	_, _ = c1.Append(Event{Type: EventSubmit, Level: 5, Submission: &sub, Timestamp: "t"})
	_ = c1.Save()

	c2 := NewChain(path)
	_ = c2.Load()
	r1, _ := DeriveRegistry(c1)
	r2, err := DeriveRegistry(c2)
	if err != nil {
		t.Fatalf("reload DeriveRegistry: %v", err)
	}
	e1, _ := r1.Entry(5)
	e2, _ := r2.Entry(5)
	if e1.State != e2.State || e1.Submission.Solution != e2.Submission.Solution {
		t.Fatalf("state diverged after round-trip: %+v vs %+v", e1, e2)
	}
}

// helper: build a chain with level 5 submitted (broken) and return it.
func chainWithBrokenLevel5(t *testing.T) *Chain {
	t.Helper()
	c := newTestChain(t)
	sub := Submission{Solution: "36", CircuitHash: "sha256:abc", VerifiedAt: "t"}
	_, _ = c.Append(Event{Type: EventSubmit, Level: 5, Submission: &sub, Timestamp: "t"})
	return c
}

// TestDeriveReproductionIncrements: a positive reproduction on a broken level
// raises the reproductions counter to 1.
func TestDeriveReproductionIncrements(t *testing.T) {
	c := chainWithBrokenLevel5(t)
	rep := &Reproduction{Author: "lab-b", CircuitHash: "sha256:rep", Result: ReproductionReproduced}
	_, _ = c.Append(Event{Type: EventReproduce, Level: 5, Reproduction: rep, Timestamp: "t"})
	r, err := DeriveRegistry(c)
	if err != nil {
		t.Fatalf("DeriveRegistry: %v", err)
	}
	e, _ := r.Entry(5)
	if e.Reproductions != 1 {
		t.Fatalf("reproductions = %d, want 1", e.Reproductions)
	}
}

// TestDeriveReproductionAccumulates: multiple positive reproductions accumulate.
func TestDeriveReproductionAccumulates(t *testing.T) {
	c := chainWithBrokenLevel5(t)
	for _, author := range []string{"lab-b", "lab-c", "lab-d"} {
		rep := &Reproduction{Author: author, CircuitHash: "sha256:rep", Result: ReproductionReproduced}
		_, _ = c.Append(Event{Type: EventReproduce, Level: 5, Reproduction: rep, Timestamp: "t"})
	}
	r, err := DeriveRegistry(c)
	if err != nil {
		t.Fatalf("DeriveRegistry: %v", err)
	}
	e, _ := r.Entry(5)
	if e.Reproductions != 3 {
		t.Fatalf("reproductions = %d, want 3", e.Reproductions)
	}
}

// TestDeriveReproductionFailedDoesNotIncrement: a failed reproduction is
// recorded but does not add positive confidence.
func TestDeriveReproductionFailedDoesNotIncrement(t *testing.T) {
	c := chainWithBrokenLevel5(t)
	rep := &Reproduction{Author: "lab-x", CircuitHash: "sha256:rep", Result: ReproductionFailed}
	_, _ = c.Append(Event{Type: EventReproduce, Level: 5, Reproduction: rep, Timestamp: "t"})
	r, err := DeriveRegistry(c)
	if err != nil {
		t.Fatalf("DeriveRegistry: %v", err)
	}
	e, _ := r.Entry(5)
	if e.Reproductions != 0 {
		t.Fatalf("failed reproduction incremented counter to %d, want 0", e.Reproductions)
	}
}

// TestDeriveReproductionRejectsNotBroken: reproducing a level that was never
// broken is invalid and must fail derivation.
func TestDeriveReproductionRejectsNotBroken(t *testing.T) {
	c := newTestChain(t) // level 5 never touched
	rep := &Reproduction{Author: "lab-b", CircuitHash: "sha256:rep", Result: ReproductionReproduced}
	_, _ = c.Append(Event{Type: EventReproduce, Level: 5, Reproduction: rep, Timestamp: "t"})
	if _, err := DeriveRegistry(c); err == nil {
		t.Fatal("expected DeriveRegistry to reject a reproduction on a non-broken level")
	}
}

// TestDeriveReproductionPersistsAfterRoundTrip: the counter survives save/load.
func TestDeriveReproductionPersistsAfterRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/chain.json"
	c1 := NewChain(path)
	_ = c1.Load()
	sub := Submission{Solution: "36", CircuitHash: "sha256:abc", VerifiedAt: "t"}
	_, _ = c1.Append(Event{Type: EventSubmit, Level: 5, Submission: &sub, Timestamp: "t"})
	rep := &Reproduction{Author: "lab-b", CircuitHash: "sha256:rep", Result: ReproductionReproduced}
	_, _ = c1.Append(Event{Type: EventReproduce, Level: 5, Reproduction: rep, Timestamp: "t"})
	_ = c1.Save()

	c2 := NewChain(path)
	_ = c2.Load()
	r, err := DeriveRegistry(c2)
	if err != nil {
		t.Fatalf("reload DeriveRegistry: %v", err)
	}
	e, _ := r.Entry(5)
	if e.Reproductions != 1 {
		t.Fatalf("reproductions after round-trip = %d, want 1", e.Reproductions)
	}
}
