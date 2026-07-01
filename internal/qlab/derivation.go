package qlab

import "fmt"

// DeriveRegistry replays the chain in order and reconstructs the live registry.
// The chain is the single source of truth; the registry is a derived view.
//
// Each event is applied with the same transition rules used by the live
// Registry methods, so on-chain and off-chain paths cannot diverge. An event
// that violates a valid transition makes the chain corrupt and returns an error
// pinpointing the offending block/level.
func DeriveRegistry(c *Chain) (*Registry, error) {
	r := NewRegistry("")
	blocks := c.Blocks()
	for bi, b := range blocks {
		if bi == 0 {
			continue // genesis block carries no events
		}
		for _, ev := range b.Events {
			if err := applyEvent(r, ev); err != nil {
				return nil, fmt.Errorf("block %d: %w", b.Index, err)
			}
		}
	}
	return r, nil
}

// applyEvent applies one chain event to the derived registry. It mirrors the
// validation in registry.go: a submit requires an open level, and transitions
// must follow ValidTransition. The submission's VerifiedAt is taken from the
// event as-is (it was stamped when the block was created).
func applyEvent(r *Registry, ev Event) error {
	switch ev.Type {
	case EventSubmit:
		if ev.Submission == nil {
			return fmt.Errorf("level %d: submit event has no submission", ev.Level)
		}
		e, _ := r.Entry(ev.Level)
		if e.State != StateOpen {
			return fmt.Errorf("level %d is %s, cannot submit", ev.Level, e.State)
		}
		s := *ev.Submission
		s.ChallengeID = e.ChallengeID
		s.Level = ev.Level
		if s.ClaimedLogicalAttackQubits == 0 {
			s.ClaimedLogicalAttackQubits = ev.Level
		}
		applySubmit(e, s)
		return nil
	case EventHarden:
		return applyEventTransition(r, ev.Level, StateHardened)
	case EventReopen:
		return applyEventTransition(r, ev.Level, StateReopened)
	case EventReproduce:
		return applyReproduction(r, ev)
	default:
		return fmt.Errorf("level %d: unknown event type %q", ev.Level, ev.Type)
	}
}

// applyReproduction records an independent corroboration against an already-broken
// level. Only positive reproductions ("reproduced") raise the entry's counter;
// failures are recorded on chain (auditable) but do not add confidence. A level
// that has never been broken cannot be reproduced.
func applyReproduction(r *Registry, ev Event) error {
	if ev.Reproduction == nil {
		return fmt.Errorf("level %d: reproduce event has no reproduction", ev.Level)
	}
	e, _ := r.Entry(ev.Level)
	if !isBrokenOrAfter(e.State) {
		return fmt.Errorf("level %d is %s, cannot be reproduced (must be broken first)", ev.Level, e.State)
	}
	if ev.Reproduction.Result == ReproductionReproduced {
		e.Reproductions++
	}
	return nil
}

// isBrokenOrAfter reports whether a level has, at some point, been broken: the
// only states from which a reproduction is meaningful.
func isBrokenOrAfter(s EntryState) bool {
	switch s {
	case StateBroken, StateHardened, StateReopened:
		return true
	}
	return false
}

// applyEventTransition is the derivation-side counterpart of Registry.Transition
// and reuses the same shared applyTransition helper.
func applyEventTransition(r *Registry, level int, to EntryState) error {
	e, _ := r.Entry(level)
	if !ValidTransition(e.State, to) {
		return fmt.Errorf("invalid transition for level %d: %s → %s", level, e.State, to)
	}
	return applyTransition(r, e, to)
}

// Mitigation band boundaries. The highest demonstrated (broken) level maps to a
// rung of the hardening ladder: the further the academic clock has advanced, the
// harder the recommended posture. These are deliberately coarse didactic bands,
// not a scientific claim of when to migrate.
const (
	mitBandB = 1    // at least one level broken
	mitBandC = 5    // order-finding demonstrated at scale
	mitBandE = 100  // non-trivial curve sizes reachable
	mitBandF = 1000 // approaching the Bitcoin reference threshold
)

// mitBandD marks the first ECDLP-shaped demonstration. It mirrors
// FirstECDLPLevel (19) but is kept as a var because FirstECDLPLevel is derived.
var mitBandD = FirstECDLPLevel

// DeriveMitigationMode returns the recommended mitigation posture implied by the
// current derived registry state (i.e. how far the clock has advanced). It does
// not depend on any explicit "mitigate" event: the chain is the source of truth.
func DeriveMitigationMode(r *Registry) MitigationMode {
	m := r.MaxBrokenLevel()
	switch {
	case m >= mitBandF:
		return ModeF
	case m >= mitBandE:
		return ModeE
	case m >= mitBandD:
		return ModeD
	case m >= mitBandC:
		return ModeC
	case m >= mitBandB:
		return ModeB
	}
	return ModeA
}
