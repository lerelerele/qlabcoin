package qlab

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
)

const (
	ProjectName             = "Attack Qubits"
	Version                 = "0.0.1"
	BitcoinCurveBits        = 256
	BitcoinLogicalThreshold = 2330

	// QuantumPrimitiveMaxLevel bounds the levels that only require demonstrating
	// useful logical qubits without a cryptographic target. It is a design choice.
	QuantumPrimitiveMaxLevel = 3
)

// FirstECDLPLevel is the lowest level at which the reference resource model can
// fit at least a one-bit curve; it equals LogicalQubitsForECDLP(1). Levels below
// it are toy period-finding / discrete-log challenges rather than ECDLP-shaped
// ones. Derived rather than hard-coded so the boundary tracks the resource model.
var FirstECDLPLevel = LogicalQubitsForECDLP(1)

type Level struct {
	Level                  int     `json:"level"`
	RequiredLogicalQubits  int     `json:"required_logical_qubits"`
	Family                 string  `json:"family"`
	EstimatedCurveBits     int     `json:"estimated_curve_bits,omitempty"`
	EstimatedToffoliGates  string  `json:"estimated_toffoli_gates,omitempty"`
	BitcoinDistancePercent float64 `json:"bitcoin_distance_percent"`
	Description            string  `json:"description"`
	NextMitigation         string  `json:"next_mitigation"`
}

type Challenge struct {
	ID                    string                 `json:"id"`
	Level                 int                    `json:"level"`
	RequiredLogicalQubits int                    `json:"required_logical_qubits"`
	Family                string                 `json:"family"`
	Status                string                 `json:"status"`
	Target                map[string]interface{} `json:"target"`
	Verification          map[string]bool        `json:"verification"`
	MitigationAfterBreak  string                 `json:"mitigation_after_break"`
}

func LogicalQubitsForECDLP(curveBits int) int {
	if curveBits <= 0 {
		return 0
	}
	return 9*curveBits + 2*ceilLog2(curveBits) + 10
}

func ToffoliForECDLP(curveBits int) float64 {
	if curveBits <= 0 {
		return 0
	}
	n := float64(curveBits)
	return 448*n*n*n*math.Log2(n) + 4090*n*n*n
}

func MaxCurveBitsForLogicalQubits(logicalQubits int) int {
	best := 0
	for bits := 1; bits <= BitcoinCurveBits; bits++ {
		if LogicalQubitsForECDLP(bits) <= logicalQubits {
			best = bits
		}
	}
	return best
}

func LevelSpec(level int) Level {
	if level < 1 {
		level = 1
	}
	spec := Level{
		Level:                  level,
		RequiredLogicalQubits:  level,
		BitcoinDistancePercent: 100 * float64(level) / float64(BitcoinLogicalThreshold),
		NextMitigation:         "publish result; open next level",
	}
	switch {
	case level <= QuantumPrimitiveMaxLevel:
		spec.Family = "quantum-primitive"
		spec.Description = "Demonstrate useful logical attack qubits in a repeatable quantum subroutine."
	case level < FirstECDLPLevel:
		spec.Family = "toy-order-finding"
		spec.Description = "Solve a tiny period-finding or discrete-log-shaped challenge."
	default:
		spec.Family = "toy-ecdlp"
		spec.EstimatedCurveBits = MaxCurveBitsForLogicalQubits(level)
		spec.EstimatedToffoliGates = scientific(ToffoliForECDLP(spec.EstimatedCurveBits))
		spec.Description = fmt.Sprintf("Solve a tiny ECDLP-shaped challenge of up to %d reference curve bits.", spec.EstimatedCurveBits)
	}
	if level >= BitcoinLogicalThreshold {
		spec.Family = "bitcoin-reference"
		spec.EstimatedCurveBits = BitcoinCurveBits
		spec.EstimatedToffoliGates = scientific(ToffoliForECDLP(BitcoinCurveBits))
		spec.Description = "Reference line for a Bitcoin-like secp256k1 logical-qubit estimate; still requires depth and physical error-correction resources."
		spec.NextMitigation = "activate post-quantum migration study"
	}
	return spec
}

func ChallengeForLevel(level int) Challenge {
	spec := LevelSpec(level)
	target := map[string]interface{}{
		"type":        spec.Family,
		"description": spec.Description,
	}
	if spec.EstimatedCurveBits > 0 {
		target["curve_bits"] = spec.EstimatedCurveBits
		target["public_key_model"] = "Q = dG over a deliberately tiny educational curve"
		target["win_condition"] = "recover d and submit a classically verifiable proof"
	} else {
		target["win_condition"] = "submit measured output, circuit hash, and reproducible verification notes"
	}
	id := ChallengeID(level, spec.Family)
	return Challenge{
		ID:                    id,
		Level:                 spec.Level,
		RequiredLogicalQubits: spec.RequiredLogicalQubits,
		Family:                spec.Family,
		Status:                "open",
		Target:                target,
		Verification: map[string]bool{
			"classical":               true,
			"requires_circuit_hash":   true,
			"requires_backend_report": true,
		},
		MitigationAfterBreak: spec.NextMitigation,
	}
}

// ChallengeID derives the deterministic challenge id for a level. The
// "qlabcoin" domain-separation tag is the project's original name, frozen at
// genesis: changing it would change every derived challenge and invalidate
// submissions already recorded on the canonical chain.
func ChallengeID(level int, family string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("qlabcoin:%d:%s", level, family)))
	return fmt.Sprintf("qlab-L%03d-%s", level, hex.EncodeToString(sum[:])[:10])
}

func ceilLog2(n int) int {
	if n <= 1 {
		return 0
	}
	return int(math.Ceil(math.Log2(float64(n))))
}

func scientific(v float64) string {
	if v <= 0 {
		return "0"
	}
	return fmt.Sprintf("%.3e", v)
}
