package qlab

import (
	"math/big"
	"strings"
	"testing"
)

// TestECDLPDeterministic: the same level must always yield the same challenge.
func TestECDLPDeterministic(t *testing.T) {
	for _, level := range []int{FirstECDLPLevel, 25, 100} {
		a := ECDLPChallengeForLevel(level)
		b := ECDLPChallengeForLevel(level)
		if a != b {
			t.Fatalf("level %d not deterministic:\n%+v\nvs\n%+v", level, a, b)
		}
	}
}

// TestECDLPCurveWellFormed: for a spread of levels, the curve must be
// nonsingular and both G and Q must lie on it, with G of order > 2 (y != 0).
func TestECDLPCurveWellFormed(t *testing.T) {
	for _, level := range []int{FirstECDLPLevel, 30, 100, 500} {
		prm := ecdlpParamsForLevel(level)
		if !prm.p.ProbablyPrime(32) {
			t.Fatalf("level %d: p=%s is not prime", level, prm.p)
		}
		if isSingular(prm.a, prm.b, prm.p) {
			t.Fatalf("level %d: curve is singular", level)
		}
		if !isOnCurve(prm.g, prm.a, prm.b, prm.p) {
			t.Fatalf("level %d: G is not on the curve", level)
		}
		if !isOnCurve(prm.q, prm.a, prm.b, prm.p) {
			t.Fatalf("level %d: Q is not on the curve", level)
		}
		if prm.g.y.Sign() == 0 {
			t.Fatalf("level %d: base point has order 2", level)
		}
		if prm.q.inf {
			t.Fatalf("level %d: Q is the identity", level)
		}
	}
}

// TestECDLPFieldBitsFloor: the smallest ECDLP levels share the minimum 3-bit
// field even though the reference model only "fits" a 1-bit curve there.
func TestECDLPFieldBitsFloor(t *testing.T) {
	c := ECDLPChallengeForLevel(FirstECDLPLevel)
	if c.ReferenceCurveBits != 1 {
		t.Fatalf("reference bits = %d, want 1", c.ReferenceCurveBits)
	}
	if c.FieldBits != minECDLPFieldBits {
		t.Fatalf("field bits = %d, want %d", c.FieldBits, minECDLPFieldBits)
	}
}

// TestECDLPReferenceSolutionVerifies: the generator's own scalar must verify,
// across small, mid, and reference-line levels.
func TestECDLPReferenceSolutionVerifies(t *testing.T) {
	for _, level := range []int{FirstECDLPLevel, 100} {
		if err := VerifyECDLP(level, ECDLPReferenceSolution(level)); err != nil {
			t.Fatalf("level %d: reference solution rejected: %v", level, err)
		}
	}
}

// TestECDLPBitcoinReferenceLevel: level 2330 is a concrete 256-bit challenge
// whose reference solution verifies. It is an educational curve, not secp256k1.
func TestECDLPBitcoinReferenceLevel(t *testing.T) {
	c := ECDLPChallengeForLevel(BitcoinLogicalThreshold)
	if c.FieldBits != 256 {
		t.Fatalf("field bits = %d, want 256", c.FieldBits)
	}
	if c.Family != "bitcoin-reference" {
		t.Fatalf("family = %q, want bitcoin-reference", c.Family)
	}
	if err := VerifyECDLP(BitcoinLogicalThreshold, ECDLPReferenceSolution(BitcoinLogicalThreshold)); err != nil {
		t.Fatalf("reference solution rejected: %v", err)
	}
}

// TestECDLPIndependentBruteForceSolves: on the tiny level-19 curve, a discrete
// log found by brute force (not the generator's scalar) must also verify —
// any representative of d mod ord(G) is a valid solution.
func TestECDLPIndependentBruteForceSolves(t *testing.T) {
	level := FirstECDLPLevel
	prm := ecdlpParamsForLevel(level)
	if !prm.p.IsInt64() || prm.p.Int64() > 1024 {
		t.Fatalf("level %d curve unexpectedly large for brute force: p=%s", level, prm.p)
	}
	found := ""
	acc := ecPoint{inf: true}
	limit := 4 * prm.p.Int64() // covers any group order by Hasse
	for k := int64(1); k <= limit; k++ {
		acc = ecAdd(acc, prm.g, prm.a, prm.p)
		if ecEqual(acc, prm.q) {
			found = big.NewInt(k).String()
			break
		}
	}
	if found == "" {
		t.Fatalf("brute force found no discrete log within %d steps", limit)
	}
	if err := VerifyECDLP(level, found); err != nil {
		t.Fatalf("brute-forced solution %s rejected: %v", found, err)
	}
}

// TestVerifyECDLPRejects: wrong scalars and malformed input must be refused.
func TestVerifyECDLPRejects(t *testing.T) {
	level := FirstECDLPLevel
	ref, ok := new(big.Int).SetString(ECDLPReferenceSolution(level), 10)
	if !ok {
		t.Fatal("reference solution is not decimal")
	}
	wrong := new(big.Int).Add(ref, big.NewInt(1)) // (d+1)G = Q+G != Q since G != identity
	cases := map[string]string{
		"off by one":  wrong.String(),
		"negative":    "-5",
		"garbage":     "not-a-number",
		"empty":       "",
		"exponential": strings.Repeat("9", 200), // far beyond the size bound for a 3-bit field
	}
	for name, sol := range cases {
		if err := VerifyECDLP(level, sol); err == nil {
			t.Fatalf("%s: VerifyECDLP wrongly accepted %q", name, sol)
		}
	}
	if err := VerifyECDLP(5, "1"); err == nil {
		t.Fatal("VerifyECDLP accepted an out-of-band level")
	}
}

// TestECScalarMulMatchesRepeatedAddition: double-and-add must agree with naive
// repeated addition on a tiny curve.
func TestECScalarMulMatchesRepeatedAddition(t *testing.T) {
	prm := ecdlpParamsForLevel(FirstECDLPLevel)
	acc := ecPoint{inf: true}
	for k := int64(0); k <= 24; k++ {
		got := ecScalarMul(big.NewInt(k), prm.g, prm.a, prm.p)
		if !ecEqual(got, acc) {
			t.Fatalf("k=%d: scalar mul disagrees with repeated addition", k)
		}
		acc = ecAdd(acc, prm.g, prm.a, prm.p)
	}
}
