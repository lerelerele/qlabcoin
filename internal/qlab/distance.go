package qlab

// Bitcoin Distance Model (Phase 5).
//
// Only the academic clock (demonstrated logical attack qubits recorded on the
// chain) ever advances. These profiles do NOT add a second clock: they translate
// the fixed Bitcoin logical-qubit threshold into physical-qubit and processor
// terms under different QEC-overhead assumptions. They answer "how much
// Q6100-class hardware would the threshold cost if this overhead held", not
// "when will Bitcoin break".

// Q6100PhysicalQubits is the physical-qubit count of the reference processor
// unit (the Q6100-style neutral-atom array from the project's source notes).
// It is a hardware inspiration figure, never a logical-qubit claim.
const Q6100PhysicalQubits = 6100

// QECProfile is one assumption about the physical-per-logical qubit overhead of
// quantum error correction. PhysicalPerLogical == 0 marks the empirical profile,
// which refuses any hardware conversion and counts only demonstrated attack
// qubits.
type QECProfile struct {
	Name               string `json:"name"`
	Description        string `json:"description"`
	PhysicalPerLogical int    `json:"physical_per_logical"`
}

// QECProfiles returns the built-in assumption ladder, from most aggressive to
// none. The 25/100/1000 figures come from the project design notes: 25 is an
// aggressive lab example, 100 a middle ground, 1000 a commonly cited
// surface-code-scale overhead.
func QECProfiles() []QECProfile {
	return []QECProfile{
		{Name: "optimistic", Description: "Aggressive lab assumption: 25 physical qubits per logical qubit.", PhysicalPerLogical: 25},
		{Name: "moderate", Description: "Middle-ground assumption: 100 physical qubits per logical qubit.", PhysicalPerLogical: 100},
		{Name: "conservative", Description: "Surface-code-scale assumption: 1000 physical qubits per logical qubit.", PhysicalPerLogical: 1000},
		{Name: "empirical", Description: "No hardware conversion: only demonstrated logical attack qubits count.", PhysicalPerLogical: 0},
	}
}

// ProfileDistance reports the Bitcoin threshold translated under one profile,
// alongside the shared demonstrated clock. DistancePercent is identical across
// profiles on purpose: assumptions may re-price the threshold in hardware
// terms, but they must never make the clock look further along than what has
// actually been demonstrated on the chain.
type ProfileDistance struct {
	Profile                  string  `json:"profile"`
	Description              string  `json:"description"`
	PhysicalPerLogical       int     `json:"physical_per_logical,omitempty"`
	LogicalPerProcessor      int     `json:"logical_qubits_per_q6100,omitempty"`
	MaxCurveBitsPerProcessor int     `json:"max_curve_bits_per_q6100,omitempty"`
	ProcessorsForBitcoin     int     `json:"q6100_processors_for_bitcoin,omitempty"`
	PhysicalQubitsForBitcoin int     `json:"physical_qubits_for_bitcoin,omitempty"`
	DemonstratedLevel        int     `json:"demonstrated_level"`
	BitcoinThreshold         int     `json:"bitcoin_threshold"`
	DistancePercent          float64 `json:"distance_percent"`
}

// DistanceUnderProfile translates the Bitcoin threshold under one profile.
// Logical qubits per processor are floored (a fraction of a logical qubit is
// not usable), and the processor count for the threshold is rounded up.
func DistanceUnderProfile(p QECProfile, demonstratedLevel int) ProfileDistance {
	if demonstratedLevel < 0 {
		demonstratedLevel = 0
	}
	d := ProfileDistance{
		Profile:           p.Name,
		Description:       p.Description,
		DemonstratedLevel: demonstratedLevel,
		BitcoinThreshold:  BitcoinLogicalThreshold,
		DistancePercent:   100 * float64(demonstratedLevel) / float64(BitcoinLogicalThreshold),
	}
	if p.PhysicalPerLogical <= 0 {
		return d // empirical: no hardware conversion
	}
	d.PhysicalPerLogical = p.PhysicalPerLogical
	d.LogicalPerProcessor = Q6100PhysicalQubits / p.PhysicalPerLogical
	d.MaxCurveBitsPerProcessor = MaxCurveBitsForLogicalQubits(d.LogicalPerProcessor)
	if d.LogicalPerProcessor > 0 {
		d.ProcessorsForBitcoin = (BitcoinLogicalThreshold + d.LogicalPerProcessor - 1) / d.LogicalPerProcessor
	}
	d.PhysicalQubitsForBitcoin = BitcoinLogicalThreshold * p.PhysicalPerLogical
	return d
}

// DistanceReport evaluates every built-in profile against the same demonstrated
// level (normally Registry.MaxBrokenLevel derived from the chain).
func DistanceReport(demonstratedLevel int) []ProfileDistance {
	profiles := QECProfiles()
	out := make([]ProfileDistance, 0, len(profiles))
	for _, p := range profiles {
		out = append(out, DistanceUnderProfile(p, demonstratedLevel))
	}
	return out
}
