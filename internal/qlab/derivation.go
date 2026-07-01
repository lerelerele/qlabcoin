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
	default:
		return fmt.Errorf("level %d: unknown event type %q", ev.Level, ev.Type)
	}
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
