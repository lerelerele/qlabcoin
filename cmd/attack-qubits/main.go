package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lerelerele/attack-qubits/internal/qlab"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "clock":
		clock(os.Args[2:])
	case "level":
		level(os.Args[2:])
	case "challenge":
		challenge(os.Args[2:])
	case "verify":
		verify(os.Args[2:])
	case "submit":
		submit(os.Args[2:])
	case "transition":
		transition(os.Args[2:])
	case "reproduce":
		reproduce(os.Args[2:])
	case "state":
		state(os.Args[2:])
	case "history":
		history(os.Args[2:])
	case "verify-chain":
		verifyChain(os.Args[2:])
	case "mitigation":
		mitigation(os.Args[2:])
	case "distance":
		distance(os.Args[2:])
	case "dashboard":
		dashboard(os.Args[2:])
	case "keygen":
		keygen(os.Args[2:])
	case "register":
		register(os.Args[2:])
	case "bitcoin":
		bitcoin()
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Printf(`Attack Qubits %s

Commands:
  attack-qubits clock [-max 20]
  attack-qubits level <n>
  attack-qubits challenge <n>
  attack-qubits verify <n> [-solution <k|d>] [-measured <json>]
  attack-qubits keygen -author <handle>                          # generate an ed25519 key pair (offline)
  attack-qubits register -author <handle> -pubkey <hex> [-chain <path>]   # publish/rotate a public key on chain
  attack-qubits submit <n> -circuit <sha256:...> -author <handle> -key <hex> [-solution <k|d>] [-measured <json>] [-backend <json>] [-circuit-desc <text>] [-repro-notes <text>] [-proof <text>] [-chain <path>]
  attack-qubits transition <n> <state> [-chain <path>]
  attack-qubits reproduce <n> -author <handle> -key <hex> -circuit <sha256:...> -result reproduced|failed [-backend <json>] [-notes <text>] [-chain <path>]
  attack-qubits state [-chain <path>]
  attack-qubits history [-chain <path>]
  attack-qubits verify-chain [-chain <path>]
  attack-qubits mitigation [-list | -mode <A-F> -request <json> | -chain <path>]
  attack-qubits distance [-level <n>] [-chain <path>]
  attack-qubits dashboard [-html] [-out <file>] [-chain <path>]
  attack-qubits bitcoin

States: open, claimed, verified, broken, hardened, reopened
Solutions: levels 1-3 take -measured (outcome counts JSON); levels 4-18 take
-solution <order>; levels 19+ take -solution <d> (decimal discrete log).
Identity: submit and reproduce events are signed (ed25519). Register a public key
first (register), then sign with the matching private key (-key).
Chain: a local append-only JSON file (default %s); the registry is derived from it.
`, qlab.Version, qlab.DefaultChainPath)
}

func clock(args []string) {
	fs := flag.NewFlagSet("clock", flag.ExitOnError)
	max := fs.Int("max", 20, "maximum level to print")
	_ = fs.Parse(args)
	if *max < 1 {
		*max = 1
	}
	fmt.Printf("%-6s %-8s %-20s %-10s %-8s\n", "Level", "Qubits", "Family", "CurveBits", "BTC%")
	for i := 1; i <= *max; i++ {
		spec := qlab.LevelSpec(i)
		curve := "-"
		if spec.EstimatedCurveBits > 0 {
			curve = strconv.Itoa(spec.EstimatedCurveBits)
		}
		fmt.Printf("%-6d %-8d %-20s %-10s %6.2f\n", spec.Level, spec.RequiredLogicalQubits, spec.Family, curve, spec.BitcoinDistancePercent)
	}
}

func level(args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "level requires one number")
		os.Exit(1)
	}
	n := mustLevel(args[0])
	printJSON(qlab.LevelSpec(n))
}

func challenge(args []string) {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "challenge requires one number")
		os.Exit(1)
	}
	n := mustLevel(args[0])
	c := qlab.ChallengeForLevel(n)
	// Embed the family's deterministic target parameters so a solver has
	// everything needed to attempt the challenge.
	switch {
	case qlab.IsPrimitiveLevel(n):
		pc := qlab.PrimitiveChallengeForLevel(n)
		c.Target["name"] = pc.Name
		c.Target["circuit"] = pc.Circuit
		c.Target["expected_outcomes"] = pc.ExpectedOutcomes
		c.Target["min_shots"] = pc.MinShots
		c.Target["tolerance"] = pc.Tolerance
		c.Target["max_noise"] = pc.MaxNoise
		c.Target["hint"] = pc.Hint
	case qlab.IsToyOrderLevel(n):
		toy := qlab.ToyOrderChallengeForLevel(n)
		c.Target["modulus"] = toy.Modulus
		c.Target["base"] = toy.Base
		c.Target["hint"] = toy.Hint
	case qlab.IsECDLPLevel(n):
		ec := qlab.ECDLPChallengeForLevel(n)
		c.Target["field_bits"] = ec.FieldBits
		c.Target["certified_solvable"] = ec.Certified
		c.Target["p"] = ec.P
		c.Target["a"] = ec.A
		c.Target["b"] = ec.B
		c.Target["gx"] = ec.Gx
		c.Target["gy"] = ec.Gy
		c.Target["qx"] = ec.Qx
		c.Target["qy"] = ec.Qy
		if ec.Order != "" {
			c.Target["order"] = ec.Order
		}
		c.Target["hint"] = ec.Hint
	}
	printJSON(c)
}

// reorderFlags moves flag tokens (and their values) before positional args so
// that stdlib flag parsing accepts the natural "cmd <level> -flag value" order.
// A "-x=v" token is self-contained; otherwise the next token is taken as the
// flag's value unless it starts with '-'. Two consequences for flag authors:
// a boolean flag (like mitigation's -list) followed by a positional argument
// would swallow it, and a value that itself starts with '-' must be written in
// the -x=v form. Neither case arises with the current command set.
func reorderFlags(args []string) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) > 0 && a[0] == '-' {
			flags = append(flags, a)
			if !containsEqual(a) && i+1 < len(args) && (len(args[i+1]) == 0 || args[i+1][0] != '-') {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		pos = append(pos, a)
	}
	return append(flags, pos...)
}

func containsEqual(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '=' {
			return true
		}
	}
	return false
}

// verify checks a claimed result against the level's deterministic challenge:
// measured outcome counts for levels 1-3 (-measured), a multiplicative order
// for levels 4-18 (-solution), or a discrete-log scalar for levels 19+
// (-solution). Intended for inspection; submit() is the path that mutates state.
func verify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	solution := fs.String("solution", "", "claimed solution (order for levels 4-18, decimal d for 19+)")
	measured := fs.String("measured", "", `measured outcome counts as JSON for levels 1-3, e.g. '{"00":510,"11":490}'`)
	_ = fs.Parse(reorderFlags(args))
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "verify requires a level number")
		os.Exit(1)
	}
	n := mustLevel(rest[0])
	switch {
	case qlab.IsPrimitiveLevel(n):
		pc := qlab.PrimitiveChallengeForLevel(n)
		counts := mustCounts(*measured, n)
		verr := qlab.VerifyPrimitive(n, counts)
		out := map[string]interface{}{
			"level":             n,
			"family":            "quantum-primitive",
			"name":              pc.Name,
			"circuit":           pc.Circuit,
			"expected_outcomes": pc.ExpectedOutcomes,
			"verified":          verr == nil,
		}
		if verr != nil {
			out["reason"] = verr.Error()
		}
		printJSON(out)
		if verr != nil {
			os.Exit(1)
		}
	case qlab.IsToyOrderLevel(n):
		k := mustOrder(*solution)
		toy := qlab.ToyOrderChallengeForLevel(n)
		ok := qlab.VerifyOrder(n, toy.Modulus, toy.Base, k)
		printJSON(map[string]interface{}{
			"level":      n,
			"modulus":    toy.Modulus,
			"base":       toy.Base,
			"solution":   k,
			"verified":   ok,
			"true_order": qlab.SolveOrder(n, toy.Modulus, toy.Base),
		})
		if !ok {
			os.Exit(1)
		}
	default: // ECDLP band, including the bitcoin-reference level
		ec := qlab.ECDLPChallengeForLevel(n)
		verr := qlab.VerifyECDLP(n, *solution)
		out := map[string]interface{}{
			"level":              n,
			"family":             ec.Family,
			"field_bits":         ec.FieldBits,
			"certified_solvable": ec.Certified,
			"p":                  ec.P,
			"a":                  ec.A,
			"b":                  ec.B,
			"gx":                 ec.Gx,
			"gy":                 ec.Gy,
			"qx":                 ec.Qx,
			"qy":                 ec.Qy,
			"solution":           *solution,
			"verified":           verr == nil,
		}
		if verr != nil {
			out["reason"] = verr.Error()
		}
		printJSON(out)
		if verr != nil {
			os.Exit(1)
		}
	}
}

// mustCounts parses the -measured JSON into outcome counts, or exits.
func mustCounts(measured string, level int) map[string]int {
	if measured == "" {
		fmt.Fprintf(os.Stderr, "level %d is a quantum-primitive challenge: pass -measured with outcome counts JSON\n", level)
		os.Exit(1)
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(measured), &m); err != nil {
		fmt.Fprintf(os.Stderr, "invalid -measured JSON: %v\n", err)
		os.Exit(2)
	}
	counts, err := qlab.CountsFromJSON(m)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -measured counts: %v\n", err)
		os.Exit(2)
	}
	return counts
}

// mustOrder parses a toy-order solution (small positive integer), or exits.
func mustOrder(solution string) int {
	if solution == "" {
		fmt.Fprintln(os.Stderr, "this level requires -solution with the claimed multiplicative order")
		os.Exit(1)
	}
	k, err := strconv.Atoi(solution)
	if err != nil {
		fmt.Fprintf(os.Stderr, "-solution %q is not an integer\n", solution)
		os.Exit(2)
	}
	return k
}

// submit records a submission against a level, verifies it classically, and on
// success advances the entry open→broken in one step.
func submit(args []string) {
	fs := flag.NewFlagSet("submit", flag.ExitOnError)
	solution := fs.String("solution", "", "claimed solution (order for levels 4-18, decimal d for 19+)")
	circuit := fs.String("circuit", "", "circuit hash, e.g. sha256:...")
	backend := fs.String("backend", "", "backend metadata as JSON object")
	circuitDesc := fs.String("circuit-desc", "", "human-readable circuit description")
	measured := fs.String("measured", "", "measured outputs as JSON object")
	reproNotes := fs.String("repro-notes", "", "reproducibility notes")
	proof := fs.String("proof", "", "classical verification proof")
	author := fs.String("author", "", "registered author handle signing this submission (required)")
	keyHex := fs.String("key", "", "ed25519 private key (hex) to sign the event (required)")
	chainPath := fs.String("chain", qlab.DefaultChainPath, "chain file path")
	_ = fs.Parse(reorderFlags(args))
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "submit requires a level number")
		os.Exit(1)
	}
	n := mustLevel(rest[0])
	if *circuit == "" {
		fmt.Fprintln(os.Stderr, "submit requires -circuit")
		os.Exit(1)
	}
	if *author == "" || *keyHex == "" {
		fmt.Fprintln(os.Stderr, "submit requires -author and -key (signed events are mandatory)")
		os.Exit(1)
	}
	var backendMap map[string]interface{}
	if *backend != "" {
		if err := json.Unmarshal([]byte(*backend), &backendMap); err != nil {
			fmt.Fprintf(os.Stderr, "invalid -backend JSON: %v\n", err)
			os.Exit(2)
		}
	}
	var measuredMap map[string]interface{}
	if *measured != "" {
		if err := json.Unmarshal([]byte(*measured), &measuredMap); err != nil {
			fmt.Fprintf(os.Stderr, "invalid -measured JSON: %v\n", err)
			os.Exit(2)
		}
	}
	// Verify the claim classically before touching the chain. Each family has
	// its own verifier; the accepted claim becomes the recorded solution.
	solutionStr := ""
	switch {
	case qlab.IsPrimitiveLevel(n):
		if measuredMap == nil {
			fmt.Fprintf(os.Stderr, "level %d is a quantum-primitive challenge: pass -measured with outcome counts JSON\n", n)
			os.Exit(1)
		}
		counts, err := qlab.CountsFromJSON(measuredMap)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid -measured counts: %v\n", err)
			os.Exit(2)
		}
		if err := qlab.VerifyPrimitive(n, counts); err != nil {
			fmt.Fprintf(os.Stderr, "classical verification failed for level %d: %v\n", n, err)
			os.Exit(1)
		}
		// The measured distribution is the evidence; there is no scalar solution.
	case qlab.IsToyOrderLevel(n):
		k := mustOrder(*solution)
		toy := qlab.ToyOrderChallengeForLevel(n)
		if !qlab.VerifyOrder(n, toy.Modulus, toy.Base, k) {
			fmt.Fprintf(os.Stderr, "classical verification failed for level %d\n", n)
			os.Exit(1)
		}
		solutionStr = strconv.Itoa(k)
	default: // ECDLP band, including the bitcoin-reference level
		if err := qlab.VerifyECDLP(n, *solution); err != nil {
			fmt.Fprintf(os.Stderr, "classical verification failed for level %d: %v\n", n, err)
			os.Exit(1)
		}
		solutionStr = strings.TrimSpace(*solution)
	}

	// Load chain and derive the current registry to validate against live state.
	chain := loadChain(*chainPath)
	reg, err := qlab.DeriveRegistry(chain)
	if err != nil {
		fatal(err)
	}
	entry, _ := reg.Entry(n)
	if entry.State != qlab.StateOpen {
		fmt.Fprintf(os.Stderr, "level %d is %s, not open (cannot submit)\n", n, entry.State)
		os.Exit(1)
	}

	now := nowRFC3339()
	sub := qlab.Submission{
		ChallengeID:                entry.ChallengeID,
		Level:                      n,
		ClaimedLogicalAttackQubits: n,
		Solution:                   solutionStr,
		CircuitHash:                *circuit,
		Backend:                    backendMap,
		VerifiedAt:                 now,
		CircuitDescription:         *circuitDesc,
		MeasuredOutputs:            measuredMap,
		ReproducibilityNotes:       *reproNotes,
		VerificationProof:          *proof,
	}
	ev := qlab.Event{
		Type:       qlab.EventSubmit,
		Level:      n,
		Author:     *author,
		Submission: &sub,
		Timestamp:  now,
	}
	sig, err := signEvent(*keyHex, ev)
	if err != nil {
		fmt.Fprintf(os.Stderr, "signing failed: %v\n", err)
		os.Exit(2)
	}
	ev.Signature = sig
	if _, err := chain.Append(ev); err != nil {
		fatal(err)
	}
	if err := chain.Save(); err != nil {
		fatal(err)
	}
	// Re-derive to report the post-event state (entry now broken).
	reg2, err := qlab.DeriveRegistry(chain)
	if err != nil {
		fatal(err)
	}
	entry2, _ := reg2.Entry(n)
	printJSON(entry2)
}

// transition moves a level to a new state via a validated lifecycle edge.
func transition(args []string) {
	fs := flag.NewFlagSet("transition", flag.ExitOnError)
	chainPath := fs.String("chain", qlab.DefaultChainPath, "chain file path")
	_ = fs.Parse(reorderFlags(args))
	rest := fs.Args()
	if len(rest) != 2 {
		fmt.Fprintln(os.Stderr, "transition requires <level> <state>")
		os.Exit(1)
	}
	n := mustLevel(rest[0])
	to := qlab.EntryState(rest[1])
	evType, ok := transitionEventType(to)
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown or non-recordable state %q (recordable: hardened, reopened)\n", rest[1])
		os.Exit(2)
	}
	chain := loadChain(*chainPath)
	reg, err := qlab.DeriveRegistry(chain)
	if err != nil {
		fatal(err)
	}
	if err := reg.Transition(n, to); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if _, err := chain.Append(qlab.Event{Type: evType, Level: n, Timestamp: nowRFC3339()}); err != nil {
		fatal(err)
	}
	if err := chain.Save(); err != nil {
		fatal(err)
	}
	reg2, err := qlab.DeriveRegistry(chain)
	if err != nil {
		fatal(err)
	}
	entry, _ := reg2.Entry(n)
	printJSON(entry)
}

// reproduce records an independent corroboration of an already-broken level on
// the chain. It does not change the level's state; it raises the derived
// reproductions counter when result is "reproduced".
func reproduce(args []string) {
	fs := flag.NewFlagSet("reproduce", flag.ExitOnError)
	author := fs.String("author", "", "lab/team identifier (required)")
	circuit := fs.String("circuit", "", "circuit hash of the reproduction (required)")
	result := fs.String("result", "", "outcome: reproduced|failed (required)")
	backend := fs.String("backend", "", "backend metadata as JSON object")
	notes := fs.String("notes", "", "free-form reproducibility notes")
	keyHex := fs.String("key", "", "ed25519 private key (hex) to sign the event (required)")
	chainPath := fs.String("chain", qlab.DefaultChainPath, "chain file path")
	_ = fs.Parse(reorderFlags(args))
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "reproduce requires a level number")
		os.Exit(1)
	}
	n := mustLevel(rest[0])
	if *author == "" || *circuit == "" || *result == "" || *keyHex == "" {
		fmt.Fprintln(os.Stderr, "reproduce requires -author, -circuit, -result and -key")
		os.Exit(1)
	}
	if *result != qlab.ReproductionReproduced && *result != qlab.ReproductionFailed {
		fmt.Fprintf(os.Stderr, "-result must be %q or %q\n", qlab.ReproductionReproduced, qlab.ReproductionFailed)
		os.Exit(2)
	}
	var backendMap map[string]interface{}
	if *backend != "" {
		if err := json.Unmarshal([]byte(*backend), &backendMap); err != nil {
			fmt.Fprintf(os.Stderr, "invalid -backend JSON: %v\n", err)
			os.Exit(2)
		}
	}
	chain := loadChain(*chainPath)
	reg, err := qlab.DeriveRegistry(chain)
	if err != nil {
		fatal(err)
	}
	entry, _ := reg.Entry(n)
	switch entry.State {
	case qlab.StateBroken, qlab.StateHardened, qlab.StateReopened:
		// ok: level has been demonstrated and may be corroborated
	default:
		fmt.Fprintf(os.Stderr, "level %d is %s, not broken (cannot reproduce)\n", n, entry.State)
		os.Exit(1)
	}
	now := nowRFC3339()
	rep := qlab.Reproduction{
		Author:      *author,
		Backend:     backendMap,
		CircuitHash: *circuit,
		Result:      *result,
		Notes:       *notes,
		Timestamp:   now,
	}
	ev := qlab.Event{Type: qlab.EventReproduce, Level: n, Author: *author, Reproduction: &rep, Timestamp: now}
	sig, err := signEvent(*keyHex, ev)
	if err != nil {
		fmt.Fprintf(os.Stderr, "signing failed: %v\n", err)
		os.Exit(2)
	}
	ev.Signature = sig
	if _, err := chain.Append(ev); err != nil {
		fatal(err)
	}
	if err := chain.Save(); err != nil {
		fatal(err)
	}
	reg2, err := qlab.DeriveRegistry(chain)
	if err != nil {
		fatal(err)
	}
	entry2, _ := reg2.Entry(n)
	printJSON(entry2)
}

// Only hardened/reopened are reachable via transition; submit/verified are
// emitted by submit itself, so other targets are not recordable here.
func transitionEventType(to qlab.EntryState) (qlab.EventType, bool) {
	switch to {
	case qlab.StateHardened:
		return qlab.EventHarden, true
	case qlab.StateReopened:
		return qlab.EventReopen, true
	}
	return "", false
}

// state dumps the registry derived from the chain as JSON.
func state(args []string) {
	fs := flag.NewFlagSet("state", flag.ExitOnError)
	chainPath := fs.String("chain", qlab.DefaultChainPath, "chain file path")
	_ = fs.Parse(reorderFlags(args))
	chain := loadChain(*chainPath)
	reg, err := qlab.DeriveRegistry(chain)
	if err != nil {
		fatal(err)
	}
	mode := qlab.DeriveMitigationMode(reg)
	printJSON(map[string]interface{}{
		"entries":         reg.All(),
		"mitigation_mode": mode,
		"mitigation_name": qlab.MitigationModeName(mode),
	})
}

// history dumps the full chain (blocks with hashes and events) as JSON. It
// deliberately skips integrity verification so a corrupt chain can still be
// inspected; verify-chain is the command that gives the integrity verdict.
func history(args []string) {
	fs := flag.NewFlagSet("history", flag.ExitOnError)
	chainPath := fs.String("chain", qlab.DefaultChainPath, "chain file path")
	_ = fs.Parse(reorderFlags(args))
	chain := qlab.NewChain(*chainPath)
	if err := chain.Load(); err != nil {
		fatal(err)
	}
	printJSON(chainHistory{Blocks: chain.Blocks(), LastHash: chain.LastHash()})
}

type chainHistory struct {
	Blocks   []qlab.Block `json:"blocks"`
	LastHash string       `json:"last_hash"`
}

// verifyChain checks the chain's structural integrity and replays all events.
func verifyChain(args []string) {
	fs := flag.NewFlagSet("verify-chain", flag.ExitOnError)
	chainPath := fs.String("chain", qlab.DefaultChainPath, "chain file path")
	_ = fs.Parse(reorderFlags(args))
	chain := qlab.NewChain(*chainPath)
	if err := chain.Load(); err != nil {
		fatal(err)
	}
	if err := chain.Verify(); err != nil {
		fmt.Fprintf(os.Stderr, "chain integrity FAILED: %v\n", err)
		os.Exit(1)
	}
	if _, err := qlab.DeriveRegistry(chain); err != nil {
		fmt.Fprintf(os.Stderr, "chain replay FAILED: %v\n", err)
		os.Exit(1)
	}
	printJSON(map[string]interface{}{
		"valid":     true,
		"blocks":    len(chain.Blocks()),
		"last_hash": chain.LastHash(),
		"note":      "block hashes are chained correctly and all events replay to a valid registry",
	})
}

// mitigation shows the active mitigation posture (derived from the chain) or, with
// -list, the whole hardening ladder; with -request it evaluates a hypothetical spend.
func mitigation(args []string) {
	fs := flag.NewFlagSet("mitigation", flag.ExitOnError)
	list := fs.Bool("list", false, "list the whole A-F hardening ladder")
	modeFlag := fs.String("mode", "", "evaluate a spend under this explicit mode (A-F) instead of the derived one")
	request := fs.String("request", "", "spend request as JSON (pubkey_exposed, address_type, ...)")
	chainPath := fs.String("chain", qlab.DefaultChainPath, "chain file path")
	_ = fs.Parse(reorderFlags(args))

	if *list {
		ladder := qlab.MitigationLadder()
		out := make([]map[string]string, 0, len(ladder))
		for _, m := range ladder {
			out = append(out, map[string]string{
				"mode": string(m),
				"name": qlab.MitigationModeName(m),
				"desc": qlab.MitigationModeDesc(m),
			})
		}
		printJSON(map[string]interface{}{"ladder": out})
		return
	}

	// Determine the mode: explicit -mode overrides the derived one.
	mode := qlab.MitigationMode(*modeFlag)
	if *modeFlag == "" {
		chain := loadChain(*chainPath)
		reg, err := qlab.DeriveRegistry(chain)
		if err != nil {
			fatal(err)
		}
		mode = qlab.DeriveMitigationMode(reg)
	} else {
		valid := false
		for _, m := range qlab.MitigationLadder() {
			if m == mode {
				valid = true
				break
			}
		}
		if !valid {
			fmt.Fprintf(os.Stderr, "unknown mode %q (use A-F)\n", *modeFlag)
			os.Exit(2)
		}
	}

	// No -request: just report the active mode.
	if *request == "" {
		printJSON(map[string]interface{}{
			"mode":       mode,
			"name":       qlab.MitigationModeName(mode),
			"desc":       qlab.MitigationModeDesc(mode),
			"max_broken": maxBrokenFromChain(*chainPath),
		})
		return
	}

	// Evaluate a hypothetical spend under this mode.
	var req qlab.SpendRequest
	if err := json.Unmarshal([]byte(*request), &req); err != nil {
		fmt.Fprintf(os.Stderr, "invalid -request JSON: %v\n", err)
		os.Exit(2)
	}
	printJSON(qlab.EvaluateSpend(mode, req))
}

// maxBrokenFromChain loads the chain (best-effort) to report the highest broken
// level alongside the derived mode. Failures are reported as 0.
func maxBrokenFromChain(chainPath string) int {
	chain := qlab.NewChain(chainPath)
	if err := chain.Load(); err != nil {
		return 0
	}
	if err := chain.Verify(); err != nil {
		return 0
	}
	reg, err := qlab.DeriveRegistry(chain)
	if err != nil {
		return 0
	}
	return reg.MaxBrokenLevel()
}

// distance reports the Bitcoin threshold translated under every QEC assumption
// profile. The demonstrated level defaults to the chain's highest broken level;
// -level explores a hypothetical clock position without touching any chain.
func distance(args []string) {
	fs := flag.NewFlagSet("distance", flag.ExitOnError)
	levelFlag := fs.Int("level", -1, "hypothetical demonstrated level (default: derived from chain)")
	chainPath := fs.String("chain", qlab.DefaultChainPath, "chain file path")
	_ = fs.Parse(reorderFlags(args))
	lvl := *levelFlag
	if lvl < 0 {
		chain := loadChain(*chainPath)
		reg, err := qlab.DeriveRegistry(chain)
		if err != nil {
			fatal(err)
		}
		lvl = reg.MaxBrokenLevel()
	}
	printJSON(map[string]interface{}{
		"demonstrated_level": lvl,
		"bitcoin_threshold":  qlab.BitcoinLogicalThreshold,
		"profiles":           qlab.DistanceReport(lvl),
	})
}

// dashboard prints the quantum-clock snapshot derived from the chain. With
// -html it writes a self-contained static page (default attack-qubits-dashboard.html,
// or stdout with -out -) suitable for publishing as-is.
func dashboard(args []string) {
	fs := flag.NewFlagSet("dashboard", flag.ExitOnError)
	htmlFlag := fs.Bool("html", false, "write a self-contained HTML dashboard instead of text")
	out := fs.String("out", "", "output file for -html (default attack-qubits-dashboard.html; '-' for stdout)")
	chainPath := fs.String("chain", qlab.DefaultChainPath, "chain file path")
	_ = fs.Parse(reorderFlags(args))
	chain := loadChain(*chainPath)
	reg, err := qlab.DeriveRegistry(chain)
	if err != nil {
		fatal(err)
	}
	d := qlab.BuildDashboard(chain, reg, nowRFC3339())
	if !*htmlFlag {
		fmt.Print(d.RenderText())
		return
	}
	html, err := d.RenderHTML()
	if err != nil {
		fatal(err)
	}
	if *out == "-" {
		fmt.Print(html)
		return
	}
	path := *out
	if path == "" {
		path = "attack-qubits-dashboard.html"
	}
	if err := os.WriteFile(path, []byte(html), 0644); err != nil {
		fatal(err)
	}
	fmt.Println("wrote", path)
}

// keygen creates a fresh ed25519 key pair for an author. The public key is meant
// to be registered on chain (see register); the private key must be kept offline
// by the author. Nothing is written to the chain.
func keygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	author := fs.String("author", "", "author handle this key belongs to (required)")
	_ = fs.Parse(reorderFlags(args))
	if *author == "" {
		fmt.Fprintln(os.Stderr, "keygen requires -author")
		os.Exit(1)
	}
	pub, priv, err := qlab.GenerateIdentity()
	if err != nil {
		fatal(err)
	}
	printJSON(map[string]interface{}{
		"author":  *author,
		"pubkey":  hex.EncodeToString(pub),
		"privkey": hex.EncodeToString(priv),
		"note":    "keep the private key offline; register the public key on chain with `register`",
	})
}

// register appends an EventRegister, publishing (or rotating) an author's
// ed25519 public key. The author can then sign submit/reproduce events.
func register(args []string) {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	author := fs.String("author", "", "author handle to register (required)")
	pubkey := fs.String("pubkey", "", "ed25519 public key as hex (required)")
	chainPath := fs.String("chain", qlab.DefaultChainPath, "chain file path")
	_ = fs.Parse(reorderFlags(args))
	if *author == "" || *pubkey == "" {
		fmt.Fprintln(os.Stderr, "register requires -author and -pubkey")
		os.Exit(1)
	}
	pub, err := decodePubKeyHex(*pubkey)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	chain := loadChain(*chainPath)
	now := nowRFC3339()
	ev := qlab.Event{
		Type:      qlab.EventRegister,
		Level:     0, // register is global, not level-scoped
		Author:    *author,
		Identity:  &qlab.Identity{Author: *author, PubKey: pub},
		Timestamp: now,
	}
	if _, err := chain.Append(ev); err != nil {
		fatal(err)
	}
	if err := chain.Save(); err != nil {
		fatal(err)
	}
	printJSON(map[string]interface{}{
		"author":     *author,
		"pubkey":     hex.EncodeToString(pub),
		"registered": true,
		"block":      chain.LastHash(),
	})
}

func bitcoin() {
	spec := qlab.LevelSpec(qlab.BitcoinLogicalThreshold)
	printJSON(map[string]interface{}{
		"label":                    "bitcoin-reference",
		"curve_bits":               qlab.BitcoinCurveBits,
		"logical_qubits":           qlab.LogicalQubitsForECDLP(qlab.BitcoinCurveBits),
		"toffoli_gates":            spec.EstimatedToffoliGates,
		"warning":                  "Logical-qubit threshold only; not a practical break claim without depth, runtime, and physical error-correction resources.",
		"attack_qubits_reference_level": qlab.BitcoinLogicalThreshold,
	})
}

func mustLevel(raw string) int {
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		fmt.Fprintln(os.Stderr, "level must be a positive integer")
		os.Exit(1)
	}
	return n
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

// loadChain opens the chain at path and checks its hash links before any
// command uses it as the source of truth, so a tampered file is refused rather
// than silently extended or reported as live state. history skips this on
// purpose (a corrupt chain must remain inspectable); verify-chain reports the
// two failure kinds separately.
func loadChain(path string) *qlab.Chain {
	chain := qlab.NewChain(path)
	if err := chain.Load(); err != nil {
		fatal(err)
	}
	if err := chain.Verify(); err != nil {
		fatal(fmt.Errorf("chain integrity check failed (see verify-chain): %w", err))
	}
	return chain
}

// nowRFC3339 returns the current UTC time in RFC3339, the format used for chain
// event timestamps and submission VerifiedAt.
func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// signEvent decodes an ed25519 private key from hex and signs the canonical
// payload of ev. Returns the signature bytes.
func signEvent(keyHex string, ev qlab.Event) ([]byte, error) {
	priv, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid -key hex: %w", err)
	}
	return qlab.SignEvent(priv, ev)
}

// decodePubKeyHex decodes a hex ed25519 public key and validates its length.
func decodePubKeyHex(hexStr string) ([]byte, error) {
	pub, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid pubkey hex: %w", err)
	}
	if !qlab.ValidPublicKey(pub) {
		return nil, fmt.Errorf("invalid ed25519 public key: %d bytes (want 32)", len(pub))
	}
	return pub, nil
}

func printJSON(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
