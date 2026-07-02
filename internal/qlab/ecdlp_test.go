package qlab

import (
	"math/big"
	"strconv"
	"strings"
	"testing"
)

// bruteForceECDLP finds the smallest d >= 1 with d·G == Q by repeated addition.
// Only usable on tiny (certified) curves where the group order is small.
func bruteForceECDLP(prm ecdlpParams, limit int64) (string, bool) {
	acc := ecPoint{inf: true}
	for k := int64(1); k <= limit; k++ {
		acc = ecAdd(acc, prm.g, prm.a, prm.p)
		if ecEqual(acc, prm.q) {
			return strconv.FormatInt(k, 10), true
		}
	}
	return "", false
}

// TestECDLPDeterministic: the same level must always yield the same challenge.
func TestECDLPDeterministic(t *testing.T) {
	for _, level := range []int{FirstECDLPLevel, 25, 100, 200, BitcoinLogicalThreshold} {
		a := ECDLPChallengeForLevel(level)
		b := ECDLPChallengeForLevel(level)
		if a != b {
			t.Fatalf("level %d not deterministic:\n%+v\nvs\n%+v", level, a, b)
		}
	}
}

// TestECDLPCurveWellFormed: for a spread of levels the curve must be
// nonsingular and both G and Q must lie on it, with G of order > 2 (y != 0).
func TestECDLPCurveWellFormed(t *testing.T) {
	for _, level := range []int{FirstECDLPLevel, 30, 100, 200, 500, BitcoinLogicalThreshold} {
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

// TestECDLPCertifiedBoundary: small fields are certified (prime order); fields
// beyond the point-counting horizon are reference markers.
func TestECDLPCertifiedBoundary(t *testing.T) {
	if c := ECDLPChallengeForLevel(FirstECDLPLevel); !c.Certified {
		t.Fatalf("level %d should be certified, got %+v", FirstECDLPLevel, c)
	}
	if c := ECDLPChallengeForLevel(100); !c.Certified {
		t.Fatalf("level 100 (small field) should be certified, got field_bits=%d", c.FieldBits)
	}
	// A 256-bit level cannot be certified by this build.
	if c := ECDLPChallengeForLevel(BitcoinLogicalThreshold); c.Certified {
		t.Fatal("level 2330 must not be certified (256-bit field is beyond point counting)")
	}
	if c := ECDLPChallengeForLevel(BitcoinLogicalThreshold); c.Order != "" {
		t.Fatal("reference levels must not publish a group order")
	}
}

// TestECDLPCertifiedHasPrimeOrder: certified levels must actually have prime
// group order, which guarantees the curve is cyclic and Q lies in <G>.
func TestECDLPCertifiedHasPrimeOrder(t *testing.T) {
	for _, level := range []int{FirstECDLPLevel, 50, 100, 150} {
		prm := ecdlpParamsForLevel(level)
		if !prm.certified {
			t.Fatalf("level %d unexpectedly not certified (field_bits=%d)", level, prm.p.BitLen())
		}
		if prm.order == nil || !prm.order.ProbablyPrime(32) {
			t.Fatalf("level %d: order %v is not prime", level, prm.order)
		}
	}
}

// TestECDLPCertifiedIsSolvable: on certified curves a discrete log found by
// brute force must verify — the challenge is genuinely solvable, and the
// solution is not derivable from the source (we had to search for it).
func TestECDLPCertifiedIsSolvable(t *testing.T) {
	for _, level := range []int{FirstECDLPLevel, 60, 120} {
		prm := ecdlpParamsForLevel(level)
		d, ok := bruteForceECDLP(prm, prm.order.Int64())
		if !ok {
			t.Fatalf("level %d: no discrete log found within the group order %s", level, prm.order)
		}
		if err := VerifyECDLP(level, d); err != nil {
			t.Fatalf("level %d: brute-forced solution %s rejected: %v", level, d, err)
		}
		// d+1 must fail: (d+1)G = Q + G != Q because G is not the identity.
		di, _ := new(big.Int).SetString(d, 10)
		if err := VerifyECDLP(level, di.Add(di, big.NewInt(1)).String()); err == nil {
			t.Fatalf("level %d: VerifyECDLP accepted d+1", level)
		}
	}
}

// TestECDLPBitcoinReferenceLevel: level 2330 is a concrete 256-bit reference
// marker (not certified, no known solution), on an educational curve — not
// secp256k1.
func TestECDLPBitcoinReferenceLevel(t *testing.T) {
	c := ECDLPChallengeForLevel(BitcoinLogicalThreshold)
	if c.FieldBits != 256 {
		t.Fatalf("field bits = %d, want 256", c.FieldBits)
	}
	if c.Family != "bitcoin-reference" {
		t.Fatalf("family = %q, want bitcoin-reference", c.Family)
	}
	if c.Certified {
		t.Fatal("the 256-bit reference marker must not be certified")
	}
	if !strings.Contains(c.Hint, "reference marker") {
		t.Fatalf("hint should flag a reference marker: %q", c.Hint)
	}
}

// TestVerifyECDLPRejects: malformed and clearly-wrong inputs must be refused.
func TestVerifyECDLPRejects(t *testing.T) {
	level := FirstECDLPLevel
	cases := map[string]string{
		"zero (identity)": "0",
		"negative":        "-5",
		"garbage":         "not-a-number",
		"empty":           "",
		"exponential":     strings.Repeat("9", 200), // beyond the size bound for a tiny field
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

// TestECDLPNoDerivableSolution documents the honesty property: the challenge is
// generated with no discrete log, so there is no ECDLPReferenceSolution-style
// backdoor. The point is verified structurally elsewhere; here we just assert Q
// was not built as 1·G or 2·G (the cheapest guessable scalars).
func TestECDLPNoTrivialSolution(t *testing.T) {
	prm := ecdlpParamsForLevel(FirstECDLPLevel)
	g1 := prm.g
	g2 := ecScalarMul(big.NewInt(2), prm.g, prm.a, prm.p)
	if ecEqual(prm.q, g1) {
		t.Fatal("Q equals G (trivial d=1)")
	}
	if ecEqual(prm.q, g2) {
		t.Fatal("Q equals 2G (trivial d=2)")
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

// TestCurveOrderSmallMatchesEnumeration: the O(p) order formula must match a
// direct enumeration of curve points on a tiny curve.
func TestCurveOrderSmallMatchesEnumeration(t *testing.T) {
	prm := ecdlpParamsForLevel(FirstECDLPLevel)
	a, b, p := prm.a.Int64(), prm.b.Int64(), prm.p.Int64()
	want := int64(1) // infinity
	for x := int64(0); x < p; x++ {
		for y := int64(0); y < p; y++ {
			if (y*y-(x*x*x+a*x+b))%p == 0 {
				want++
			}
		}
	}
	if got := curveOrderSmall(a, b, p); got != want {
		t.Fatalf("curveOrderSmall = %d, enumerated = %d", got, want)
	}
}
