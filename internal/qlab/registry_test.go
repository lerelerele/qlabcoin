package qlab

import (
	"encoding/json"
	"testing"
)

func TestNewRegistryIsEmpty(t *testing.T) {
	r := NewRegistry()
	if got := len(r.All()); got != 0 {
		t.Fatalf("expected empty registry, got %d entries", got)
	}
}

func TestRegistryEntryCreatedOpen(t *testing.T) {
	r := NewRegistry()
	e, existed := r.Entry(5)
	if existed {
		t.Fatal("first Entry() should report not-existed")
	}
	if e.State != StateOpen {
		t.Fatalf("state = %s, want open", e.State)
	}
	if e.ChallengeID == "" {
		t.Fatal("expected non-empty challenge id")
	}
	if e.Level != 5 {
		t.Fatalf("level = %d, want 5", e.Level)
	}
}

func TestRegistryEntryInvalidLevel(t *testing.T) {
	r := NewRegistry()
	if e, _ := r.Entry(0); e != nil {
		t.Fatal("Entry(0) should return nil")
	}
	if e, _ := r.Entry(-1); e != nil {
		t.Fatal("Entry(-1) should return nil")
	}
}

// TestValidTransition covers every accepted and a few rejected edges.
func TestValidTransition(t *testing.T) {
	accepted := map[EntryState]EntryState{
		StateOpen:     StateClaimed,
		StateClaimed:  StateVerified,
		StateVerified: StateBroken,
		StateBroken:   StateHardened,
		StateHardened: StateReopened,
	}
	for from, to := range accepted {
		if !ValidTransition(from, to) {
			t.Fatalf("expected %s → %s to be valid", from, to)
		}
	}
	rejected := []struct{ from, to EntryState }{
		{StateOpen, StateHardened},   // skip too many steps
		{StateBroken, StateOpen},     // no going back
		{StateReopened, StateOpen},   // reopened is terminal here
		{StateHardened, StateBroken}, // no going back
	}
	for _, c := range rejected {
		if ValidTransition(c.from, c.to) {
			t.Fatalf("expected %s → %s to be invalid", c.from, c.to)
		}
	}
}

// TestTransitionCollapsedThenReopenAdvancesClock drives a level open→broken
// (the edge submit collapses) then broken→hardened→reopened, and checks that
// reopening opens the next level.
func TestTransitionReopenAdvancesClock(t *testing.T) {
	r := NewRegistry()
	for _, to := range []EntryState{StateBroken, StateHardened, StateReopened} {
		if err := r.Transition(5, to); err != nil {
			t.Fatalf("transition to %s: %v", to, err)
		}
	}
	next, _ := r.Entry(6)
	if next == nil || next.State != StateOpen {
		t.Fatalf("reopening level 5 did not open level 6 as open: %+v", next)
	}
}

// TestTransitionInvalidEdgeRejected: a bad edge must error without mutating.
func TestTransitionInvalidEdgeRejected(t *testing.T) {
	r := NewRegistry()
	r.Entry(5)                            // open
	err := r.Transition(5, StateHardened) // open -> hardened skipped
	if err == nil {
		t.Fatal("expected invalid-transition error")
	}
	e, _ := r.Entry(5)
	if e.State != StateOpen {
		t.Fatalf("state mutated to %s on rejected transition", e.State)
	}
}

// TestSubmissionReportFieldsRoundTrip: the Phase 3 report fields (spec §6)
// survive JSON marshal/unmarshal.
func TestSubmissionReportFieldsRoundTrip(t *testing.T) {
	s := Submission{
		ChallengeID:                "qlab-L005-b6816f32eb",
		Level:                      5,
		ClaimedLogicalAttackQubits: 5,
		Solution:                   "36",
		CircuitHash:                "sha256:abc",
		CircuitDescription:         "3-qubit order-finding circuit",
		ReproducibilityNotes:       "run on simulator, 1024 shots",
		VerificationProof:          "2^36 mod 37 == 1, minimal",
		MeasuredOutputs:            map[string]interface{}{"peak_prob": 0.98},
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Submission
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.CircuitDescription != s.CircuitDescription ||
		got.ReproducibilityNotes != s.ReproducibilityNotes ||
		got.VerificationProof != s.VerificationProof ||
		got.MeasuredOutputs["peak_prob"] != s.MeasuredOutputs["peak_prob"] {
		t.Fatalf("report fields lost in round-trip: %+v", got)
	}
}

// TestSubmissionOmitsEmptyReportFields: empty report fields are omitted, so old
// chains/submissions keep their compact shape.
func TestSubmissionOmitsEmptyReportFields(t *testing.T) {
	b, err := json.Marshal(Submission{Solution: "36", CircuitHash: "sha256:abc"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	for _, key := range []string{"circuit_description", "measured_outputs", "reproducibility_notes", "verification_proof"} {
		if containsSubstring(s, key) {
			t.Fatalf("empty report field %q should be omitted, got %s", key, s)
		}
	}
}

func containsSubstring(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
