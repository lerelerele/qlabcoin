package qlab

import (
	"fmt"
	"math"
)

// Quantum-primitive challenges (levels 1..QuantumPrimitiveMaxLevel).
//
// These levels have no cryptographic secret; the deliverable is statistical
// evidence of a repeatable quantum subroutine using `level` logical qubits:
//
//	level 1  plus-state   H q0                  outcomes 0/1 each ≈ 50%
//	level 2  bell-pair    H q0; CX q0 q1        outcomes 00/11 each ≈ 50%
//	level 3  ghz-3        H q0; CX q0 q1; CX q1 q2   outcomes 000/111 each ≈ 50%
//
// Classical verification checks the *shape* of the submitted measurement
// distribution: enough shots, the expected outcomes near their ideal 50%
// probability, and at most a small fraction of forbidden outcomes. It cannot
// prove the counts came from quantum hardware — fabricating them classically is
// trivial. The circuit hash, backend report, and independent reproductions are
// the audit trail that makes a claim credible; the verifier only guarantees the
// claim is at least self-consistent.

const (
	// PrimitiveMinShots is the minimum number of measurements a submission must
	// aggregate for the distribution check to be meaningful.
	PrimitiveMinShots = 100
	// PrimitiveTolerance is the allowed absolute deviation of each expected
	// outcome's frequency from the ideal 0.5.
	PrimitiveTolerance = 0.10
	// PrimitiveMaxNoise is the maximum tolerated total fraction of outcomes
	// outside the expected set (readout errors, decoherence).
	PrimitiveMaxNoise = 0.05
)

// PrimitiveChallenge describes a level's quantum-primitive target.
type PrimitiveChallenge struct {
	Level            int      `json:"level"`
	Name             string   `json:"name"`
	Qubits           int      `json:"qubits"`
	Circuit          string   `json:"circuit"`
	ExpectedOutcomes []string `json:"expected_outcomes"`
	MinShots         int      `json:"min_shots"`
	Tolerance        float64  `json:"tolerance"`
	MaxNoise         float64  `json:"max_noise"`
	Hint             string   `json:"hint"`
}

// IsPrimitiveLevel reports whether level is in the quantum-primitive band.
func IsPrimitiveLevel(level int) bool {
	return level >= 1 && level <= QuantumPrimitiveMaxLevel
}

// PrimitiveChallengeForLevel returns the deterministic primitive challenge for
// a level in the band. Out-of-band levels get zero parameters and a hint
// explaining the family mismatch, mirroring ToyOrderChallengeForLevel.
func PrimitiveChallengeForLevel(level int) PrimitiveChallenge {
	c := PrimitiveChallenge{
		Level:     level,
		Qubits:    level,
		MinShots:  PrimitiveMinShots,
		Tolerance: PrimitiveTolerance,
		MaxNoise:  PrimitiveMaxNoise,
	}
	switch level {
	case 1:
		c.Name = "plus-state"
		c.Circuit = "H q0"
		c.ExpectedOutcomes = []string{"0", "1"}
	case 2:
		c.Name = "bell-pair"
		c.Circuit = "H q0; CX q0 q1"
		c.ExpectedOutcomes = []string{"00", "11"}
	case 3:
		c.Name = "ghz-3"
		c.Circuit = "H q0; CX q0 q1; CX q1 q2"
		c.ExpectedOutcomes = []string{"000", "111"}
	default:
		return PrimitiveChallenge{
			Level: level,
			Hint:  fmt.Sprintf("level %d is not a quantum-primitive challenge", level),
		}
	}
	c.Hint = fmt.Sprintf(
		"run %q for at least %d shots and submit the outcome counts; expected outcomes %v each within ±%.0f%% of 50%%, at most %.0f%% other outcomes",
		c.Circuit, c.MinShots, c.ExpectedOutcomes, 100*c.Tolerance, 100*c.MaxNoise)
	return c
}

// VerifyPrimitive checks submitted outcome counts against the level's expected
// distribution. nil means the distribution is consistent with the target
// circuit; a non-nil error explains the first rule that failed.
func VerifyPrimitive(level int, counts map[string]int) error {
	if !IsPrimitiveLevel(level) {
		return fmt.Errorf("level %d is not a quantum-primitive challenge", level)
	}
	c := PrimitiveChallengeForLevel(level)
	if len(counts) == 0 {
		return fmt.Errorf("no measured outcomes submitted")
	}
	shots := 0
	for outcome, n := range counts {
		if len(outcome) != c.Qubits {
			return fmt.Errorf("outcome %q has %d bits, want %d", outcome, len(outcome), c.Qubits)
		}
		for _, r := range outcome {
			if r != '0' && r != '1' {
				return fmt.Errorf("outcome %q is not a bitstring", outcome)
			}
		}
		if n < 0 {
			return fmt.Errorf("outcome %q has negative count %d", outcome, n)
		}
		shots += n
	}
	if shots < c.MinShots {
		return fmt.Errorf("only %d shots submitted, need at least %d", shots, c.MinShots)
	}
	expected := make(map[string]bool, len(c.ExpectedOutcomes))
	for _, o := range c.ExpectedOutcomes {
		expected[o] = true
	}
	noise := 0
	for outcome, n := range counts {
		if !expected[outcome] {
			noise += n
		}
	}
	if frac := float64(noise) / float64(shots); frac > c.MaxNoise {
		return fmt.Errorf("%.1f%% of shots landed outside %v, max %.1f%% allowed", 100*frac, c.ExpectedOutcomes, 100*c.MaxNoise)
	}
	ideal := 1.0 / float64(len(c.ExpectedOutcomes))
	for _, o := range c.ExpectedOutcomes {
		freq := float64(counts[o]) / float64(shots)
		if math.Abs(freq-ideal) > c.Tolerance {
			return fmt.Errorf("outcome %q frequency %.3f deviates from ideal %.2f by more than %.2f", o, freq, ideal, c.Tolerance)
		}
	}
	return nil
}

// CountsFromJSON converts generic JSON measured outputs (as stored in a
// Submission) into outcome counts. JSON numbers arrive as float64; they must be
// non-negative integers. Used by the CLI and by chain replay re-verification.
func CountsFromJSON(m map[string]interface{}) (map[string]int, error) {
	if len(m) == 0 {
		return nil, fmt.Errorf("no measured outputs recorded")
	}
	counts := make(map[string]int, len(m))
	for outcome, v := range m {
		var n float64
		switch x := v.(type) {
		case float64:
			n = x
		case int:
			n = float64(x)
		default:
			return nil, fmt.Errorf("measured output %q has non-numeric count %v", outcome, v)
		}
		if n < 0 || n != math.Trunc(n) {
			return nil, fmt.Errorf("measured output %q has invalid count %v (need a non-negative integer)", outcome, v)
		}
		counts[outcome] = int(n)
	}
	return counts, nil
}
