package qlab

import (
	"strings"
	"testing"
)

// TestPrimitiveChallengeBand: each level in the band gets a named circuit with
// outcome width equal to its qubit count; out-of-band levels get none.
func TestPrimitiveChallengeBand(t *testing.T) {
	names := map[int]string{1: "plus-state", 2: "bell-pair", 3: "ghz-3"}
	for level := 1; level <= QuantumPrimitiveMaxLevel; level++ {
		c := PrimitiveChallengeForLevel(level)
		if c.Name != names[level] {
			t.Fatalf("level %d name = %q, want %q", level, c.Name, names[level])
		}
		if c.Qubits != level {
			t.Fatalf("level %d qubits = %d, want %d", level, c.Qubits, level)
		}
		for _, o := range c.ExpectedOutcomes {
			if len(o) != level {
				t.Fatalf("level %d outcome %q has width %d, want %d", level, o, len(o), level)
			}
		}
	}
	if c := PrimitiveChallengeForLevel(4); c.Name != "" || len(c.ExpectedOutcomes) != 0 {
		t.Fatalf("level 4 should not be a primitive challenge: %+v", c)
	}
}

func TestVerifyPrimitiveAccepts(t *testing.T) {
	cases := []struct {
		name   string
		level  int
		counts map[string]int
	}{
		{"clean plus-state", 1, map[string]int{"0": 512, "1": 488}},
		{"clean bell pair", 2, map[string]int{"00": 510, "11": 490}},
		{"noisy but tolerable bell", 2, map[string]int{"00": 480, "11": 470, "01": 30, "10": 20}},
		{"clean ghz", 3, map[string]int{"000": 505, "111": 495}},
		{"minimum shots", 1, map[string]int{"0": 50, "1": 50}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := VerifyPrimitive(c.level, c.counts); err != nil {
				t.Fatalf("expected accept, got: %v", err)
			}
		})
	}
}

func TestVerifyPrimitiveRejects(t *testing.T) {
	cases := []struct {
		name   string
		level  int
		counts map[string]int
		want   string // substring of the expected reason
	}{
		{"out of band level", 4, map[string]int{"0": 500, "1": 500}, "not a quantum-primitive"},
		{"empty counts", 1, map[string]int{}, "no measured outcomes"},
		{"too few shots", 1, map[string]int{"0": 30, "1": 30}, "shots"},
		{"wrong outcome width", 1, map[string]int{"00": 500, "11": 500}, "bits"},
		{"not a bitstring", 1, map[string]int{"0x": 500, "1": 500}, "bits"},
		{"negative count", 1, map[string]int{"0": -5, "1": 500}, "negative"},
		{"biased distribution", 2, map[string]int{"00": 700, "11": 300}, "deviates"},
		{"too much noise", 2, map[string]int{"00": 450, "11": 450, "01": 100}, "outside"},
		{"missing expected outcome", 2, map[string]int{"00": 1000}, "deviates"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := VerifyPrimitive(c.level, c.counts)
			if err == nil {
				t.Fatalf("expected reject")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("reason %q does not mention %q", err.Error(), c.want)
			}
		})
	}
}

// TestVerifyPrimitiveNotABitstringWidthTwo: a non-binary outcome of the right
// width must still be rejected.
func TestVerifyPrimitiveNotABitstringWidthTwo(t *testing.T) {
	err := VerifyPrimitive(2, map[string]int{"0a": 500, "11": 500})
	if err == nil || !strings.Contains(err.Error(), "bitstring") {
		t.Fatalf("expected bitstring rejection, got: %v", err)
	}
}

func TestCountsFromJSON(t *testing.T) {
	counts, err := CountsFromJSON(map[string]interface{}{"00": 510.0, "11": 490.0})
	if err != nil {
		t.Fatalf("valid counts rejected: %v", err)
	}
	if counts["00"] != 510 || counts["11"] != 490 {
		t.Fatalf("counts mangled: %v", counts)
	}
	bad := []map[string]interface{}{
		nil,                              // empty
		{"0": "many"},                    // non-numeric
		{"0": -1.0},                      // negative
		{"0": 1.5},                       // fractional
	}
	for _, m := range bad {
		if _, err := CountsFromJSON(m); err == nil {
			t.Fatalf("expected rejection for %v", m)
		}
	}
}
