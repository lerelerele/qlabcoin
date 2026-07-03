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
// prime field F_p, a base point G, and a public point Q. The win condition is
// recovering any scalar d with d·G == Q. Verification is classical and cheap
// (double-and-add), even at 256 bits.
//
// Nobody-knows-d design:
//   - Q is NOT built as d·G for a project-chosen d. It is derived by hashing to
//     a point on the curve (try-and-increment on x). No discrete log is used in
//     generation, so no d is stored, and none is recoverable from this source.
//     Reading the code does not reveal a solution — unlike SolveOrder for the
//     order-finding band. Recovering d genuinely requires solving the ECDLP.
//   - For fields small enough to count points (<= maxCertifiedFieldBits), the
//     curve is chosen to have PRIME group order, so it is cyclic and every
//     affine point — including a hash-derived Q — lies in <G>. The challenge is
//     therefore certified solvable. The exact d is unknown until someone
//     computes it (classically or otherwise).
//   - For larger fields, point counting is infeasible here (Schoof is not
//     implemented), so the group order and thus whether Q lies in <G> are
//     unknown. These levels are honest REFERENCE MARKERS: a concrete curve and
//     a real hash-derived point, but solvability is not certified and no
//     solution is known to exist. The level-2330 curve is such a marker — an
//     arbitrary educational 256-bit curve, NOT secp256k1 and NOT holding value.

// minECDLPFieldBits is the smallest usable field size. The reference resource
// model "fits" a 1-bit curve at level 19, but no meaningful short-Weierstrass
// curve exists below a 3-bit field, so the smallest levels share it.
const minECDLPFieldBits = 3

// maxCertifiedFieldBits is the largest field for which we count points (O(p))
// and require a prime group order, certifying the challenge is solvable. Beyond
// it, levels are reference markers. It is a deliberate implementation bound
// (fast, int64-safe generation), raisable later with a faster order algorithm.
const maxCertifiedFieldBits = 16

// maxECDLPSolutionSlack bounds how much larger than the field a claimed scalar
// may be (in bits), so absurdly long inputs are rejected before the scalar
// multiplication (linear in bit-length) runs. Any d within the group order fits.
const maxECDLPSolutionSlack = 64

// ECDLPChallenge is the JSON-facing description of a level's curve target.
// All field elements are decimal strings so 256-bit values survive JSON.
type ECDLPChallenge struct {
	Level              int    `json:"level"`
	Family             string `json:"family"`
	ReferenceCurveBits int    `json:"reference_curve_bits"` // what the resource model fits at this level
	FieldBits          int    `json:"field_bits"`           // actual bit length of P (>= minECDLPFieldBits)
	Certified          bool   `json:"certified_solvable"`   // true => prime order, Q provably in <G>
	P                  string `json:"p"`
	A                  string `json:"a"`
	B                  string `json:"b"`
	Gx                 string `json:"gx"`
	Gy                 string `json:"gy"`
	Qx                 string `json:"qx"`
	Qy                 string `json:"qy"`
	Order              string `json:"order,omitempty"` // group order, published only for certified levels
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

// ecdlpParams is the internal (big.Int) form of a level's challenge. No d is
// stored: the challenge is generated without ever computing a discrete log.
type ecdlpParams struct {
	p, a, b   *big.Int
	g, q      ecPoint
	certified bool
	order     *big.Int // group order for certified levels; nil otherwise
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
	c := ECDLPChallenge{
		Level:              level,
		Family:             spec.Family,
		ReferenceCurveBits: spec.EstimatedCurveBits,
		FieldBits:          prm.p.BitLen(),
		Certified:          prm.certified,
		P:                  prm.p.String(),
		A:                  prm.a.String(),
		B:                  prm.b.String(),
		Gx:                 prm.g.x.String(),
		Gy:                 prm.g.y.String(),
		Qx:                 prm.q.x.String(),
		Qy:                 prm.q.y.String(),
	}
	if prm.certified {
		c.Order = prm.order.String()
		c.Hint = fmt.Sprintf("recover d with Q = dG on y² = x³ + %sx + %s over F_%s (prime-order curve, order %s: a solution is guaranteed to exist)",
			prm.a.String(), prm.b.String(), prm.p.String(), prm.order.String())
	} else {
		c.Hint = fmt.Sprintf("reference marker: Q is a hash-derived point on y² = x³ + %sx + %s over F_%s; the group order is beyond this build's point-counting horizon, so no solution is known to exist",
			prm.a.String(), prm.b.String(), prm.p.String())
	}
	return c
}

// VerifyECDLP checks a claimed discrete log classically. nil means d·G == Q on
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

// ecdlpParamsForLevel derives the deterministic curve for a level. Small fields
// get a certified prime-order curve; larger ones get a reference marker. Both
// take Q from a hash-to-point, so neither computes or stores a discrete log.
func ecdlpParamsForLevel(level int) ecdlpParams {
	bits := MaxCurveBitsForLogicalQubits(level)
	if bits < minECDLPFieldBits {
		bits = minECDLPFieldBits
	}
	if bits <= maxCertifiedFieldBits {
		if prm, ok := buildCertifiedCurve(level, bits); ok {
			return prm
		}
	}
	if prm, ok := buildReferenceCurve(level, bits); ok {
		return prm
	}
	// Unreachable in practice: nonsingular curves with points are abundant.
	panic(fmt.Sprintf("attack-qubits: could not derive an ECDLP challenge for level %d", level))
}

// buildCertifiedCurve finds a prime-order curve of the target size and a
// hash-derived non-trivial Q on it. Prime order makes the group cyclic, so Q is
// guaranteed to be a multiple of G (the challenge is solvable) without anyone
// knowing which multiple.
func buildCertifiedCurve(level, bits int) (ecdlpParams, bool) {
	one := big.NewInt(1)
	p := nextPrimeBig(new(big.Int).Lsh(one, uint(bits-1)))
	for bump := 0; bump < 8; bump++ {
		for seed := 0; seed < 512; seed++ {
			a := new(big.Int).Mod(hashToBig("a", level, seed), p)
			b := new(big.Int).Mod(hashToBig("b", level, seed), p)
			if isSingular(a, b, p) {
				continue
			}
			ord := curveOrderSmall(a.Int64(), b.Int64(), p.Int64())
			if !isPrimeInt64(ord) {
				continue
			}
			g, ok := findBasePoint(a, b, p)
			if !ok {
				continue
			}
			for qs := 0; qs < 512; qs++ {
				q, ok := hashToPoint("q", level, seed*1000+qs, a, b, p)
				if !ok || q.inf || ecEqual(q, g) {
					continue // skip failures and the trivial d=1 case
				}
				return ecdlpParams{p: p, a: a, b: b, g: g, q: q, certified: true, order: big.NewInt(ord)}, true
			}
		}
		p = nextPrimeBig(new(big.Int).Add(p, one))
	}
	return ecdlpParams{}, false
}

// buildReferenceCurve finds any nonsingular curve of the target size with a base
// point and a hash-derived Q. The group order is not computed, so solvability is
// not certified: this is a reference marker, not a live challenge.
func buildReferenceCurve(level, bits int) (ecdlpParams, bool) {
	one := big.NewInt(1)
	p := nextPrimeBig(new(big.Int).Lsh(one, uint(bits-1)))
	for seed := 0; seed < 1024; seed++ {
		a := new(big.Int).Mod(hashToBig("a", level, seed), p)
		b := new(big.Int).Mod(hashToBig("b", level, seed), p)
		if isSingular(a, b, p) {
			continue
		}
		g, ok := findBasePoint(a, b, p)
		if !ok {
			continue
		}
		q, ok := hashToPoint("q", level, seed, a, b, p)
		if !ok || ecEqual(q, g) {
			continue
		}
		return ecdlpParams{p: p, a: a, b: b, g: g, q: q, certified: false}, true
	}
	return ecdlpParams{}, false
}

// hashToPoint derives a point on the curve by try-and-increment: hash to a
// candidate x, take y = sqrt(x³ + ax + b) when it exists, choosing the smaller
// root for determinism. No discrete log is involved. y=0 (2-torsion) is skipped.
func hashToPoint(label string, level, seed int, a, b, p *big.Int) (ecPoint, bool) {
	for ctr := 0; ctr < 8192; ctr++ {
		x := new(big.Int).Mod(hashToBig(fmt.Sprintf("%s:x:%d", label, ctr), level, seed), p)
		rhs := ecRHS(x, a, b, p)
		y := new(big.Int).ModSqrt(rhs, p)
		if y == nil || y.Sign() == 0 {
			continue
		}
		if yneg := new(big.Int).Sub(p, y); yneg.Cmp(y) < 0 {
			y = yneg
		}
		return ecPoint{x: x, y: y}, true
	}
	return ecPoint{}, false
}

// ecRHS returns x³ + ax + b mod p.
func ecRHS(x, a, b, p *big.Int) *big.Int {
	rhs := new(big.Int).Exp(x, big.NewInt(3), p)
	ax := new(big.Int).Mul(a, x)
	rhs.Add(rhs, ax)
	rhs.Add(rhs, b)
	rhs.Mod(rhs, p)
	return rhs
}

// curveOrderSmall returns #E(F_p) = p + 1 + Σ_x legendre(x³+ax+b) for a small
// prime p (< 2^maxCertifiedFieldBits), using int64 arithmetic. Only called from
// the certified path, where overflow is impossible for the bounded p.
func curveOrderSmall(a, b, p int64) int64 {
	order := int64(1) // the point at infinity
	for x := int64(0); x < p; x++ {
		fx := (((x*x%p)*x)%p + (a%p)*x%p + b) % p
		fx = ((fx % p) + p) % p
		order += 1 + legendreInt64(fx, p)
	}
	return order
}

// legendreInt64 returns the Legendre symbol (n/p) as -1, 0, or 1 for odd prime p.
func legendreInt64(n, p int64) int64 {
	n = ((n % p) + p) % p
	if n == 0 {
		return 0
	}
	if modPowInt64(n, (p-1)/2, p) == 1 {
		return 1
	}
	return -1
}

// modPowInt64 computes base^exp mod m for m*m within int64 range (m < 2^31).
func modPowInt64(base, exp, m int64) int64 {
	result := int64(1)
	base %= m
	for exp > 0 {
		if exp&1 == 1 {
			result = result * base % m
		}
		exp >>= 1
		base = base * base % m
	}
	return result
}

// isPrimeInt64 tests small positive integers by trial division.
func isPrimeInt64(n int64) bool {
	if n < 2 {
		return false
	}
	for d := int64(2); d*d <= n; d++ {
		if n%d == 0 {
			return false
		}
	}
	return true
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
		rhs := ecRHS(x, a, b, p)
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
	return lhs.Cmp(ecRHS(pt.x, a, b, p)) == 0
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
// The "qlabcoin" domain-separation tag is the project's original name, frozen
// at genesis (see ChallengeID in model.go).
func hashToBig(label string, level, seed int) *big.Int {
	sum := sha256.Sum256([]byte(fmt.Sprintf("qlabcoin:ecdlp:%s:%d:%d", label, level, seed)))
	return new(big.Int).SetBytes(sum[:])
}
