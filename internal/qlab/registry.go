package qlab

import (
	"fmt"
	"sort"
)

// Challenge lifecycle states (see docs/QLABCOIN_SPEC.md §5):
//
//	open      challenge published
//	claimed   a solver submitted a report + solution
//	verified  classical verification accepted the solution
//	broken    the level is marked broken
//	hardened  protocol mitigation applied
//	reopened  next challenge opened
const (
	StateOpen     EntryState = "open"
	StateClaimed  EntryState = "claimed"
	StateVerified EntryState = "verified"
	StateBroken   EntryState = "broken"
	StateHardened EntryState = "hardened"
	StateReopened EntryState = "reopened"
)

// EntryState is a challenge lifecycle state.
type EntryState string

// Submission is a solver's claim against a challenge: a proposed solution plus
// the circuit/backend metadata required for reproducibility.
type Submission struct {
	ChallengeID                string                 `json:"challenge_id"`
	Level                      int                    `json:"level"`
	ClaimedLogicalAttackQubits int                    `json:"claimed_logical_attack_qubits"`
	Solution                   string                 `json:"solution"`
	CircuitHash                string                 `json:"circuit_hash"`
	Backend                    map[string]interface{} `json:"backend,omitempty"`
	VerifiedAt                 string                 `json:"verified_at,omitempty"`
	// Phase 3 report fields (spec §6 "Submission Requirements"). All optional so
	// existing chains/tests keep deserializing unchanged.
	CircuitDescription   string                 `json:"circuit_description,omitempty"`
	MeasuredOutputs      map[string]interface{} `json:"measured_outputs,omitempty"`
	ReproducibilityNotes string                 `json:"reproducibility_notes,omitempty"`
	VerificationProof    string                 `json:"verification_proof,omitempty"`
}

// Entry is the registry's view of one level: its current state and, once a
// solver has submitted, the winning submission.
type Entry struct {
	Level         int         `json:"level"`
	ChallengeID   string      `json:"challenge_id"`
	State         EntryState  `json:"state"`
	Submission    *Submission `json:"submission,omitempty"`
	Reproductions int         `json:"reproductions,omitempty"` // independent corroborations (derived from chain)
}

// Registry is the in-memory view of challenge state. It is never persisted on
// its own: the append-only event chain is the single source of truth, and a
// Registry is always produced by replaying that chain (see DeriveRegistry).
type Registry struct {
	entries map[int]*Entry
}

// NewRegistry returns an empty in-memory registry, ready to have chain events
// applied to it.
func NewRegistry() *Registry {
	return &Registry{entries: make(map[int]*Entry)}
}

// Entry returns the registry entry for level. If none exists and the level is a
// valid challenge level, it is created in StateOpen and the second result is
// false (indicating it was just created). An invalid level returns (nil, false).
func (r *Registry) Entry(level int) (*Entry, bool) {
	if level < 1 {
		return nil, false
	}
	if e, ok := r.entries[level]; ok {
		return e, true
	}
	spec := LevelSpec(level)
	e := &Entry{
		Level:       level,
		ChallengeID: ChallengeID(level, spec.Family),
		State:       StateOpen,
	}
	r.entries[level] = e
	return e, false
}

// All returns every entry, sorted by level.
func (r *Registry) All() []*Entry {
	return r.sortedEntries()
}

// MaxBrokenLevel returns the highest level that has been demonstrated (reached
// state broken/hardened/reopened), or 0 if none. It drives the derived
// mitigation mode: the further the academic clock has advanced, the harder the
// recommended posture.
func (r *Registry) MaxBrokenLevel() int {
	max := 0
	for _, e := range r.entries {
		if e.Level > max && isBrokenOrAfter(e.State) {
			max = e.Level
		}
	}
	return max
}

// applySubmit stamps a verified submission onto an entry and moves it to broken.
// Called from the chain re-derivation path (DeriveRegistry); it assumes the
// caller has already verified the solution.
func applySubmit(e *Entry, s Submission) {
	e.Submission = &s
	e.State = StateBroken // open → claimed → verified → broken in one accepted step
}

// Transition moves level to the requested state after validating the edge. The
// special case StateReopened also opens level+1 in StateOpen, advancing the
// research clock. It mutates the in-memory registry only; the caller records the
// corresponding event on the chain.
func (r *Registry) Transition(level int, to EntryState) error {
	e, _ := r.Entry(level)
	if !ValidTransition(e.State, to) {
		return fmt.Errorf("invalid transition for level %d: %s → %s", level, e.State, to)
	}
	if err := applyTransition(r, e, to); err != nil {
		return err
	}
	return nil
}

// applyTransition mutates an entry to the next state and handles the reopen
// side-effect (opening the next level). Shared by Transition and chain
// re-derivation so both follow identical rules.
func applyTransition(r *Registry, e *Entry, to EntryState) error {
	e.State = to
	if to == StateReopened {
		// Advance the clock: open the next level. r may be nil when called in a
		// context that does not need auto-open (it never is today, but be safe).
		if r != nil {
			r.Entry(e.Level + 1)
		}
	}
	return nil
}

// ValidTransition reports whether moving directly from one state to another is
// allowed. The model is a linear chain:
//
//	open → claimed → verified → broken → hardened → reopened
//
// submit() collapses open→broken, so verified/claimed are reachable only via
// explicit transitions or are passed through internally.
func ValidTransition(from, to EntryState) bool {
	switch from {
	case StateOpen:
		return to == StateClaimed || to == StateVerified || to == StateBroken
	case StateClaimed:
		return to == StateVerified || to == StateBroken
	case StateVerified:
		return to == StateBroken
	case StateBroken:
		return to == StateHardened || to == StateReopened
	case StateHardened:
		return to == StateReopened
	}
	return false
}

func (r *Registry) sortedEntries() []*Entry {
	out := make([]*Entry, 0, len(r.entries))
	for _, e := range r.entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Level < out[j].Level })
	return out
}
