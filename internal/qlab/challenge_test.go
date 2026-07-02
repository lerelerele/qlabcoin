package qlab

import "testing"

// TestToyOrderDeterministic asserts that the same level always yields the same
// modulus and base. Reproducibility is required for the registry and examples.
func TestToyOrderDeterministic(t *testing.T) {
	for level := QuantumPrimitiveMaxLevel + 1; level < FirstECDLPLevel; level++ {
		a := ToyOrderChallengeForLevel(level)
		b := ToyOrderChallengeForLevel(level)
		if a != b {
			t.Fatalf("level %d not deterministic: %+v vs %+v", level, a, b)
		}
	}
}

// TestSolveOrderSatisfiesVerify: the brute-force solution must always verify,
// across the whole order-finding band.
func TestSolveOrderSatisfiesVerify(t *testing.T) {
	for level := QuantumPrimitiveMaxLevel + 1; level < FirstECDLPLevel; level++ {
		c := ToyOrderChallengeForLevel(level)
		sol := SolveOrder(level, c.Modulus, c.Base)
		if sol < 2 {
			t.Fatalf("level %d: trivial solution %d", level, sol)
		}
		if !VerifyOrder(level, c.Modulus, c.Base, sol) {
			t.Fatalf("level %d: SolveOrder=%d fails VerifyOrder", level, sol)
		}
	}
}

// TestVerifyOrderRejectsBadExponents: a wrong exponent (not the order) must be
// rejected, including multiples that are congruent to 1 but not minimal.
func TestVerifyOrderRejectsBadExponents(t *testing.T) {
	level := 5
	c := ToyOrderChallengeForLevel(level)
	order := SolveOrder(level, c.Modulus, c.Base)

	// A divisor of the order is not the order (unless equal): never accepted as a
	// minimal claim. A strict multiple that is still congruent to 1 must also be
	// rejected because it is not minimal.
	cases := map[string]int{
		"order minus one": order - 1,
		"double order":    2 * order, // congruent to 1 but NOT minimal
		"one":             1,
		"zero":            0,
		"negative":        -3,
	}
	for name, bad := range cases {
		if VerifyOrder(level, c.Modulus, c.Base, bad) {
			t.Fatalf("level %d: VerifyOrder wrongly accepted %s=%d (true order %d)", level, name, bad, order)
		}
	}
}

// TestVerifyOrderRejectsWrongModulusOrBase: tampering with the challenge
// parameters must fail verification.
func TestVerifyOrderRejectsWrongModulusOrBase(t *testing.T) {
	level := 5
	c := ToyOrderChallengeForLevel(level)
	sol := SolveOrder(level, c.Modulus, c.Base)
	if !VerifyOrder(level, c.Modulus, c.Base, sol) {
		t.Fatalf("baseline verify failed")
	}
	if VerifyOrder(level, c.Modulus+1, c.Base, sol) {
		t.Fatal("accepted wrong modulus")
	}
	if VerifyOrder(level, c.Modulus, c.Base+1, sol) {
		t.Fatal("accepted wrong base")
	}
}

// TestVerifyOrderRejectsOutOfBandLevels: only the toy-order-finding band is
// verifiable by VerifyOrder. Quantum-primitive and ECDLP levels have their own
// verifiers (VerifyPrimitive, VerifyECDLP) and must be rejected here.
func TestVerifyOrderRejectsOutOfBandLevels(t *testing.T) {
	outOfBand := []int{0, 1, 3, FirstECDLPLevel, FirstECDLPLevel + 1, BitcoinLogicalThreshold}
	for _, level := range outOfBand {
		if VerifyOrder(level, 31, 6, 6) {
			t.Fatalf("VerifyOrder accepted out-of-band level %d", level)
		}
	}
}
