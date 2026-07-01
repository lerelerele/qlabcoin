package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"qlabcoin/internal/qlab"
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
	case "bitcoin":
		bitcoin()
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Printf(`Qlabcoin %s

Commands:
  qlabcoin clock [-max 20]
  qlabcoin level <n>
  qlabcoin challenge <n>
  qlabcoin verify <n> -solution <k>
  qlabcoin submit <n> -solution <k> -circuit <sha256:...> [-backend <json>] [-circuit-desc <text>] [-measured <json>] [-repro-notes <text>] [-proof <text>] [-chain <path>]
  qlabcoin transition <n> <state> [-chain <path>]
  qlabcoin reproduce <n> -author <lab> -circuit <sha256:...> -result reproduced|failed [-backend <json>] [-notes <text>] [-chain <path>]
  qlabcoin state [-chain <path>]
  qlabcoin history [-chain <path>]
  qlabcoin verify-chain [-chain <path>]
  qlabcoin mitigation [-list | -mode <A-F> -request <json> | -chain <path>]
  qlabcoin bitcoin

States: open, claimed, verified, broken, hardened, reopened
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
	// For toy-order-finding levels, embed the deterministic group parameters so a
	// solver has everything needed to attempt the challenge.
	if qlab.IsToyOrderLevel(n) {
		toy := qlab.ToyOrderChallengeForLevel(n)
		c.Target["modulus"] = toy.Modulus
		c.Target["base"] = toy.Base
		c.Target["hint"] = toy.Hint
	}
	printJSON(c)
}

// reorderFlags moves flag tokens (and their values) before positional args so
// that stdlib flag parsing accepts the natural "cmd <level> -flag value" order.
// It assumes every flag takes a value (true for all qlabcoin flags: -max,
// -solution, -circuit, -backend, -registry). A "-x=v" token is self-contained.
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

// verify reports whether -solution is the multiplicative order for the level's
// deterministic toy group. Intended for inspection; submit() is the path that
// mutates state.
func verify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	solution := fs.Int("solution", 0, "claimed multiplicative order to check")
	_ = fs.Parse(reorderFlags(args))
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "verify requires a level number")
		os.Exit(1)
	}
	n := mustLevel(rest[0])
	if !qlab.IsToyOrderLevel(n) {
		fmt.Fprintf(os.Stderr, "level %d is not a toy-order-finding challenge; classical verification is not implemented for that family yet\n", n)
		os.Exit(2)
	}
	toy := qlab.ToyOrderChallengeForLevel(n)
	ok := qlab.VerifyOrder(n, toy.Modulus, toy.Base, *solution)
	printJSON(map[string]interface{}{
		"level":      n,
		"modulus":    toy.Modulus,
		"base":       toy.Base,
		"solution":   *solution,
		"verified":   ok,
		"true_order": qlab.SolveOrder(n, toy.Modulus, toy.Base),
	})
	if !ok {
		os.Exit(1)
	}
}

// submit records a submission against a level, verifies it classically, and on
// success advances the entry open→broken in one step.
func submit(args []string) {
	fs := flag.NewFlagSet("submit", flag.ExitOnError)
	solution := fs.Int("solution", 0, "claimed multiplicative order")
	circuit := fs.String("circuit", "", "circuit hash, e.g. sha256:...")
	backend := fs.String("backend", "", "backend metadata as JSON object")
	circuitDesc := fs.String("circuit-desc", "", "human-readable circuit description")
	measured := fs.String("measured", "", "measured outputs as JSON object")
	reproNotes := fs.String("repro-notes", "", "reproducibility notes")
	proof := fs.String("proof", "", "classical verification proof")
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
	if !qlab.IsToyOrderLevel(n) {
		fmt.Fprintf(os.Stderr, "level %d is not a toy-order-finding challenge; classical verification is not implemented for that family yet\n", n)
		os.Exit(2)
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
	toy := qlab.ToyOrderChallengeForLevel(n)

	// Load chain and derive the current registry to validate against live state.
	chain := qlab.NewChain(*chainPath)
	if err := chain.Load(); err != nil {
		fatal(err)
	}
	reg, err := qlab.DeriveRegistry(chain)
	if err != nil {
		fatal(err)
	}

	// Verify the solution classically before recording anything.
	if !qlab.VerifyOrder(n, toy.Modulus, toy.Base, *solution) {
		fmt.Fprintf(os.Stderr, "classical verification failed for level %d\n", n)
		os.Exit(1)
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
		Solution:                   strconv.Itoa(*solution),
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
		Submission: &sub,
		Timestamp:  now,
	}
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
	chain := qlab.NewChain(*chainPath)
	if err := chain.Load(); err != nil {
		fatal(err)
	}
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
	chainPath := fs.String("chain", qlab.DefaultChainPath, "chain file path")
	_ = fs.Parse(reorderFlags(args))
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "reproduce requires a level number")
		os.Exit(1)
	}
	n := mustLevel(rest[0])
	if *author == "" || *circuit == "" || *result == "" {
		fmt.Fprintln(os.Stderr, "reproduce requires -author, -circuit and -result")
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
	chain := qlab.NewChain(*chainPath)
	if err := chain.Load(); err != nil {
		fatal(err)
	}
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
	if _, err := chain.Append(qlab.Event{Type: qlab.EventReproduce, Level: n, Reproduction: &rep, Timestamp: now}); err != nil {
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
	chain := qlab.NewChain(*chainPath)
	if err := chain.Load(); err != nil {
		fatal(err)
	}
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

// history dumps the full chain (blocks with hashes and events) as JSON.
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
		chain := qlab.NewChain(*chainPath)
		if err := chain.Load(); err != nil {
			fatal(err)
		}
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
	reg, err := qlab.DeriveRegistry(chain)
	if err != nil {
		return 0
	}
	return reg.MaxBrokenLevel()
}

func bitcoin() {
	spec := qlab.LevelSpec(qlab.BitcoinLogicalThreshold)
	printJSON(map[string]interface{}{
		"label":                    "bitcoin-reference",
		"curve_bits":               qlab.BitcoinCurveBits,
		"logical_qubits":           qlab.LogicalQubitsForECDLP(qlab.BitcoinCurveBits),
		"toffoli_gates":            spec.EstimatedToffoliGates,
		"warning":                  "Logical-qubit threshold only; not a practical break claim without depth, runtime, and physical error-correction resources.",
		"qlabcoin_reference_level": qlab.BitcoinLogicalThreshold,
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

// nowRFC3339 returns the current UTC time in RFC3339, the format used for chain
// event timestamps and submission VerifiedAt.
func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func printJSON(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
