package qlab

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"
)

// Toy ECDLP challenges (levels >= FirstECDLPLevel, including the level-2330
// bitcoin-reference line).
//
// Each level gets a deterministic tiny elliptic curve y² = x³ + ax + b over a
// prime field F_p, a base point G, and a public point Q = dG. The win condition
// is recovering any scalar d' with d'G == Q (every representative of d modulo
// ord(G) is a valid discrete log). Verification is classical and cheap
// (double-and-add), even at 256 bits.
//
// Honesty notes:
//   - Parameters are derived deterministically from the level so the challenge
//     is reproducible without coordination. That means d itself can be
//     re-derived from this source code (see ECDLPReferenceSolution) — exactly
//     like SolveOrder for the order-finding band. The value of a submission is
//     the audited protocol (circuit report, reproductions), not secrecy.
//   - The level-2330 curve is an arbitrary educational 256-bit curve, NOT
//     secp256k1 and NOT anything holding value. It exists so the reference
//     line is a concrete, verifiable object rather than a slogan.

// minECDLPFieldBits is the smallest usable field size. The reference resource
// model "fits" a 1-bit curve at level 19, but no meaningful short-Weierstrass
// curve exists below a 3-bit field, so the smallest levels share the smallest
// lab curve size.
const minECDLPFieldBits = 3

// maxECDLPSolutionSlack bounds how much larger than the field a claimed scalar
// may be (in bits). Any d' ≡ d (mod ord(G)) is a valid discrete log, so small
// over-representatives are fine; absurdly long scalars are rejected before the
// (linear in bit-length) scalar multiplication runs.
const maxECDLPSolutionSlack = 64

// ECDLPChallenge is the JSON-facing description of a level's curve target.
// All field elements are decimal strings so 256-bit values survive JSON.
type ECDLPChallenge struct {
	Level              int    `json:"level"`
	Family             string `json:"family"`
	ReferenceCurveBits int    `json:"reference_curve_bits"` // what the resource model fits at this level
	FieldBits          int    `json:"field_bits"`           // actual bit length of P (>= minECDLPFieldBits)
	P                  string `json:"p"`
	A                  string `json:"a"`
	B                  string `json:"b"`
	Gx                 string `json:"gx"`
	Gy                 string `json:"gy"`
	Qx                 string `json:"qx"`
	Qy                 string `json:"qy"`
	Hint               string `json:"hint"`
}

// IsECDLPLevel reports whether level gets a concrete curve challenge. It spans
// both the toy-ecdlp band and the bitcoin-reference level.
func IsECDLPLevel(level int) bool {
	return level >= FirstECDLPLevel
}

// ecPoint is an affine point, with inf marking the identity.
type ecPoint struct {
	x, y *big.Int
	inf  bool
}

// ecdlpParams is the internal (big.Int) form of a level's challenge.
type ecdlpParams struct {
	p, a, b *big.Int
	g, q    ecPoint
	d       *big.Int // reference solution; derivable by design
}

// ECDLPChallengeForLevel returns the deterministic curve challenge for level.
// Out-of-band levels get zero parameters and an explanatory hint.
func ECDLPChallengeForLevel(level int) ECDLPChallenge {
	if !IsECDLPLevel(level) {
		return ECDLPChallenge{
			Level: level,
			Hint:  fmt.Sprintf("level %d is not an ECDLP challenge", level),
		}
	}
	prm := ecdlpParamsForLevel(level)
	spec := LevelSpec(level)
	return ECDLPChallenge{
		Level:              level,
		Family:             spec.Family,
		ReferenceCurveBits: spec.EstimatedCurveBits,
		FieldBits:          prm.p.BitLen(),
		P:                  prm.p.String(),
		A:                  prm.a.String(),
		B:                  prm.b.String(),
		Gx:                 prm.g.x.String(),
		Gy:                 prm.g.y.String(),
		Qx:                 prm.q.x.String(),
		Qy:                 prm.q.y.String(),
		Hint: fmt.Sprintf("recover d with Q = dG on y² = x³ + %sx + %s over F_%s (any d with dG = Q verifies)",
			prm.a.String(), prm.b.String(), prm.p.String()),
	}
}

// VerifyECDLP checks a claimed discrete log classically. nil means d'G == Q on
// the level's deterministic curve; a non-nil error explains the rejection.
func VerifyECDLP(level int, solution string) error {
	if !IsECDLPLevel(level) {
		return fmt.Errorf("level %d is not an ECDLP challenge", level)
	}
	d, ok := new(big.Int).SetString(strings.TrimSpace(solution), 10)
	if !ok {
		return fmt.Errorf("solution %q is not a decimal integer", solution)
	}
	if d.Sign() < 0 {
		return fmt.Errorf("solution must be non-negative")
	}
	prm := ecdlpParamsForLevel(level)
	if d.BitLen() > prm.p.BitLen()+maxECDLPSolutionSlack {
		return fmt.Errorf("solution is unreasonably large (%d bits for a %d-bit field)", d.BitLen(), prm.p.BitLen())
	}
	got := ecScalarMul(d, prm.g, prm.a, prm.p)
	if !ecEqual(got, prm.q) {
		return fmt.Errorf("d·G does not equal Q")
	}
	return nil
}

// ECDLPReferenceSolution returns the scalar used to build the level's public
// point. It is derivable by design (deterministic challenge); used by tests and
// as a reference, never required from a solver, who may submit any congruent d.
// Returns "" for out-of-band levels.
func ECDLPReferenceSolution(level int) string {
	if !IsECDLPLevel(level) {
		return ""
	}
	return ecdlpParamsForLevel(level).d.String()
}

// ecdlpParamsForLevel derives the deterministic curve for a level: the smallest
// prime of the target bit length, hash-derived (a, b) rejected until the curve
// is nonsingular and has a base point of order > 2, and Q = dG with d hashed
// into [1, p-1] (bumped once if Q would be the identity).
func ecdlpParamsForLevel(level int) ecdlpParams {
	bits := MaxCurveBitsForLogicalQubits(level)
	if bits < minECDLPFieldBits {
		bits = minECDLPFieldBits
	}
	one := big.NewInt(1)
	p := nextPrimeBig(new(big.Int).Lsh(one, uint(bits-1)))
	for seed := 0; seed < 256; seed++ {
		a := hashToBig("a", level, seed)
		a.Mod(a, p)
		b := hashToBig("b", level, seed)
		b.Mod(b, p)
		if isSingular(a, b, p) {
			continue
		}
		g, ok := findBasePoint(a, b, p)
		if !ok {
			continue
		}
		pm1 := new(big.Int).Sub(p, one)
		d := hashToBig("d", level, seed)
		d.Mod(d, pm1)
		d.Add(d, one) // 1 <= d <= p-1
		q := ecScalarMul(d, g, a, p)
		// Skip degenerate publics: the identity (no affine Q to publish) and
		// Q == G (visibly d ≡ 1, no challenge at all). ord(G) >= 3 because
		// G is affine with y != 0, so among any three consecutive scalars at
		// most one hits each degenerate case.
		for tries := 0; (q.inf || ecEqual(q, g)) && tries < 4; tries++ {
			d.Add(d, one)
			q = ecScalarMul(d, g, a, p)
		}
		if q.inf || ecEqual(q, g) {
			continue // pathological seed; try the next one
		}
		return ecdlpParams{p: p, a: a, b: b, g: g, q: q, d: d}
	}
	// Unreachable in practice: nonsingular curves with points are abundant.
	panic(fmt.Sprintf("qlabcoin: could not derive an ECDLP challenge for level %d", level))
}

// isSingular reports whether y² = x³ + ax + b is singular over F_p
// (discriminant 4a³ + 27b² ≡ 0 mod p).
func isSingular(a, b, p *big.Int) bool {
	a3 := new(big.Int).Exp(a, big.NewInt(3), p)
	a3.Mul(a3, big.NewInt(4))
	b2 := new(big.Int).Exp(b, big.NewInt(2), p)
	b2.Mul(b2, big.NewInt(27))
	disc := new(big.Int).Add(a3, b2)
	disc.Mod(disc, p)
	return disc.Sign() == 0
}

// findBasePoint scans x = 0, 1, ... for a point with y ≠ 0 (order > 2). The
// scan is bounded; roughly half of all x values yield a point, so failure
// within the bound means the curve is pathological and a new seed is tried.
func findBasePoint(a, b, p *big.Int) (ecPoint, bool) {
	limit := int64(4096)
	if p.IsInt64() && p.Int64() < limit {
		limit = p.Int64()
	}
	for xi := int64(0); xi < limit; xi++ {
		x := big.NewInt(xi)
		rhs := new(big.Int).Exp(x, big.NewInt(3), p)
		ax := new(big.Int).Mul(a, x)
		rhs.Add(rhs, ax)
		rhs.Add(rhs, b)
		rhs.Mod(rhs, p)
		y := new(big.Int).ModSqrt(rhs, p)
		if y == nil || y.Sign() == 0 {
			continue
		}
		return ecPoint{x: x, y: y}, true
	}
	return ecPoint{}, false
}

// ecEqual reports whether two points are the same (identity-aware).
func ecEqual(p1, p2 ecPoint) bool {
	if p1.inf || p2.inf {
		return p1.inf == p2.inf
	}
	return p1.x.Cmp(p2.x) == 0 && p1.y.Cmp(p2.y) == 0
}

// ecAdd adds two affine points on y² = x³ + ax + b over F_p.
func ecAdd(p1, p2 ecPoint, a, p *big.Int) ecPoint {
	if p1.inf {
		return p2
	}
	if p2.inf {
		return p1
	}
	var lam *big.Int
	if p1.x.Cmp(p2.x) == 0 {
		ysum := new(big.Int).Add(p1.y, p2.y)
		ysum.Mod(ysum, p)
		if ysum.Sign() == 0 {
			return ecPoint{inf: true} // P + (−P), including doubling a y=0 point
		}
		// Doubling: λ = (3x² + a) / 2y.
		num := new(big.Int).Mul(p1.x, p1.x)
		num.Mul(num, big.NewInt(3))
		num.Add(num, a)
		den := new(big.Int).Lsh(p1.y, 1)
		lam = divMod(num, den, p)
	} else {
		// Chord: λ = (y2 − y1) / (x2 − x1).
		num := new(big.Int).Sub(p2.y, p1.y)
		den := new(big.Int).Sub(p2.x, p1.x)
		lam = divMod(num, den, p)
	}
	x3 := new(big.Int).Mul(lam, lam)
	x3.Sub(x3, p1.x)
	x3.Sub(x3, p2.x)
	x3.Mod(x3, p)
	y3 := new(big.Int).Sub(p1.x, x3)
	y3.Mul(y3, lam)
	y3.Sub(y3, p1.y)
	y3.Mod(y3, p)
	return ecPoint{x: x3, y: y3}
}

// divMod returns (num / den) mod p for prime p.
func divMod(num, den, p *big.Int) *big.Int {
	inv := new(big.Int).ModInverse(new(big.Int).Mod(den, p), p)
	out := new(big.Int).Mod(num, p)
	out.Mul(out, inv)
	out.Mod(out, p)
	return out
}

// ecScalarMul computes k·pt by double-and-add. k must be non-negative.
func ecScalarMul(k *big.Int, pt ecPoint, a, p *big.Int) ecPoint {
	result := ecPoint{inf: true}
	add := pt
	for i := 0; i < k.BitLen(); i++ {
		if k.Bit(i) == 1 {
			result = ecAdd(result, add, a, p)
		}
		add = ecAdd(add, add, a, p)
	}
	return result
}

// isOnCurve reports whether an affine point satisfies the curve equation.
// Used by tests.
func isOnCurve(pt ecPoint, a, b, p *big.Int) bool {
	if pt.inf {
		return true
	}
	lhs := new(big.Int).Exp(pt.y, big.NewInt(2), p)
	rhs := new(big.Int).Exp(pt.x, big.NewInt(3), p)
	ax := new(big.Int).Mul(a, pt.x)
	rhs.Add(rhs, ax)
	rhs.Add(rhs, b)
	rhs.Mod(rhs, p)
	return lhs.Cmp(rhs) == 0
}

// nextPrimeBig returns the smallest prime >= n. ProbablyPrime is deterministic
// for a given input (fixed pseudorandom bases plus Baillie-PSW), so challenge
// generation stays reproducible.
func nextPrimeBig(n *big.Int) *big.Int {
	p := new(big.Int).Set(n)
	two := big.NewInt(2)
	if p.Cmp(two) <= 0 {
		return two
	}
	if p.Bit(0) == 0 {
		p.Add(p, big.NewInt(1))
	}
	for !p.ProbablyPrime(32) {
		p.Add(p, two)
	}
	return p
}

// hashToBig derives a deterministic big integer from a labeled level/seed pair.
func hashToBig(label string, level, seed int) *big.Int {
	sum := sha256.Sum256([]byte(fmt.Sprintf("qlabcoin:ecdlp:%s:%d:%d", label, level, seed)))
	return new(big.Int).SetBytes(sum[:])
}
