package qlab

import (
	"fmt"
	"html/template"
	"strings"
)

// Public dashboard (Phase 5): a single snapshot of the quantum clock, derived
// entirely from the chain. RenderText prints it for the terminal; RenderHTML
// produces a self-contained static page (no scripts, no external assets) that
// can be published as-is, e.g. on GitHub Pages.

// dashboardNote is the honest-language footer required by the threat model.
const dashboardNote = "Qlabcoin measures demonstrated logical attack qubits. " +
	"Nothing here claims that current hardware can break Bitcoin; the profiles " +
	"only re-price the reference threshold under different QEC assumptions."

// Dashboard is the derived snapshot behind both renderers.
type Dashboard struct {
	Project            string            `json:"project"`
	Version            string            `json:"version"`
	GeneratedAt        string            `json:"generated_at"`
	MaxBrokenLevel     int               `json:"max_broken_level"`
	MaxBrokenFamily    string            `json:"max_broken_family,omitempty"`
	TotalReproductions int               `json:"total_reproductions"`
	OpenLevels         []int             `json:"open_levels,omitempty"`
	Blocks             int               `json:"blocks"`
	LastHash           string            `json:"last_hash"`
	MitigationMode     MitigationMode    `json:"mitigation_mode"`
	MitigationName     string            `json:"mitigation_name"`
	MitigationDesc     string            `json:"mitigation_desc"`
	BitcoinThreshold   int               `json:"bitcoin_threshold"`
	DistancePercent    float64           `json:"distance_percent"`
	Distances          []ProfileDistance `json:"distances"`
	Note               string            `json:"note"`
}

// BuildDashboard assembles the snapshot from a chain and its derived registry.
// generatedAt is injected (RFC3339 UTC) so renders are reproducible in tests.
func BuildDashboard(c *Chain, r *Registry, generatedAt string) Dashboard {
	maxBroken := r.MaxBrokenLevel()
	var open []int
	repro := 0
	for _, e := range r.All() {
		if e.State == StateOpen {
			open = append(open, e.Level)
		}
		repro += e.Reproductions
	}
	if len(open) == 0 && maxBroken == 0 {
		open = []int{1} // fresh project: the frontier is level 1
	}
	mode := DeriveMitigationMode(r)
	d := Dashboard{
		Project:            ProjectName,
		Version:            Version,
		GeneratedAt:        generatedAt,
		MaxBrokenLevel:     maxBroken,
		TotalReproductions: repro,
		OpenLevels:         open,
		Blocks:             len(c.Blocks()),
		LastHash:           c.LastHash(),
		MitigationMode:     mode,
		MitigationName:     MitigationModeName(mode),
		MitigationDesc:     MitigationModeDesc(mode),
		BitcoinThreshold:   BitcoinLogicalThreshold,
		DistancePercent:    100 * float64(maxBroken) / float64(BitcoinLogicalThreshold),
		Distances:          DistanceReport(maxBroken),
		Note:               dashboardNote,
	}
	if maxBroken > 0 {
		d.MaxBrokenFamily = LevelSpec(maxBroken).Family
	}
	return d
}

// RenderText prints the dashboard for a terminal.
func (d Dashboard) RenderText() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s Quantum Clock — v%s\n", d.Project, d.Version)
	fmt.Fprintf(&b, "Generated: %s\n\n", d.GeneratedAt)

	fmt.Fprintf(&b, "Academic clock\n")
	if d.MaxBrokenLevel > 0 {
		fmt.Fprintf(&b, "  Highest broken level      : %d (%s)\n", d.MaxBrokenLevel, d.MaxBrokenFamily)
	} else {
		fmt.Fprintf(&b, "  Highest broken level      : none yet\n")
	}
	fmt.Fprintf(&b, "  Independent reproductions : %d\n", d.TotalReproductions)
	fmt.Fprintf(&b, "  Open challenges           : %s\n", formatLevels(d.OpenLevels))
	fmt.Fprintf(&b, "  Chain                     : %d blocks, head %.12s\n\n", d.Blocks, d.LastHash)

	fmt.Fprintf(&b, "Mitigation posture\n")
	fmt.Fprintf(&b, "  Mode %s — %s\n", d.MitigationMode, d.MitigationName)
	fmt.Fprintf(&b, "  %s\n\n", d.MitigationDesc)

	fmt.Fprintf(&b, "Bitcoin reference\n")
	fmt.Fprintf(&b, "  Threshold             : %d logical qubits (secp256k1 reference model)\n", d.BitcoinThreshold)
	fmt.Fprintf(&b, "  Demonstrated distance : %.2f%%\n\n", d.DistancePercent)

	fmt.Fprintf(&b, "Distance profiles (1 Q6100 = %d physical qubits)\n", Q6100PhysicalQubits)
	fmt.Fprintf(&b, "  %-13s %9s %10s %13s %14s %13s\n",
		"PROFILE", "PHYS/LOG", "LOG/Q6100", "CURVE b/Q6100", "Q6100 FOR BTC", "PHYS FOR BTC")
	for _, p := range d.Distances {
		if p.PhysicalPerLogical == 0 {
			fmt.Fprintf(&b, "  %-13s %9s %10s %13s %14s %13s\n", p.Profile, "—", "—", "—", "—", "—")
			continue
		}
		fmt.Fprintf(&b, "  %-13s %9d %10d %13d %14d %13d\n",
			p.Profile, p.PhysicalPerLogical, p.LogicalPerProcessor,
			p.MaxCurveBitsPerProcessor, p.ProcessorsForBitcoin, p.PhysicalQubitsForBitcoin)
	}
	fmt.Fprintf(&b, "\nNote: %s\n", d.Note)
	return b.String()
}

func formatLevels(levels []int) string {
	if len(levels) == 0 {
		return "none (highest level broken, awaiting harden/reopen)"
	}
	parts := make([]string, len(levels))
	for i, l := range levels {
		parts[i] = fmt.Sprintf("level %d", l)
	}
	return strings.Join(parts, ", ")
}

// RenderHTML produces the self-contained public dashboard page.
func (d Dashboard) RenderHTML() (string, error) {
	var b strings.Builder
	if err := dashboardTmpl.Execute(&b, d); err != nil {
		return "", err
	}
	return b.String(), nil
}

var dashboardTmpl = template.Must(template.New("dashboard").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Qlabcoin Quantum Clock</title>
<style>
  body{font-family:system-ui,-apple-system,sans-serif;background:#0e1116;color:#e6e6e6;margin:0;padding:2rem;}
  .wrap{max-width:920px;margin:0 auto;}
  h1{margin:0 0 .2rem;font-size:1.7rem;}
  h2{font-size:1.1rem;margin:1.6rem 0 .6rem;color:#c9d1d9;}
  .sub{color:#9aa4b2;font-size:.85rem;margin-bottom:1.6rem;}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:1rem;}
  .card{background:#161b22;border:1px solid #2d333b;border-radius:8px;padding:1rem;}
  .card .k{color:#9aa4b2;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;}
  .card .v{font-size:1.7rem;font-weight:700;margin-top:.3rem;}
  .card .s{color:#9aa4b2;font-size:.8rem;margin-top:.2rem;}
  table{width:100%;border-collapse:collapse;}
  th,td{padding:.45rem .6rem;text-align:right;border-bottom:1px solid #2d333b;font-size:.9rem;}
  th:first-child,td:first-child{text-align:left;}
  th{color:#9aa4b2;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;}
  .mode{display:inline-block;background:#1f6feb;color:#fff;border-radius:6px;padding:.05rem .5rem;}
  .note{color:#9aa4b2;font-size:.85rem;border-left:3px solid #1f6feb;padding-left:.8rem;margin-top:1.6rem;}
  p{color:#c9d1d9;font-size:.95rem;}
</style>
</head>
<body><div class="wrap">
<h1>Qlabcoin Quantum Clock</h1>
<div class="sub">{{.Project}} v{{.Version}} &middot; generated {{.GeneratedAt}} &middot; chain: {{.Blocks}} blocks, head {{printf "%.12s" .LastHash}}&hellip;</div>
<div class="grid">
  <div class="card"><div class="k">Highest broken level</div><div class="v">{{.MaxBrokenLevel}}</div>{{with .MaxBrokenFamily}}<div class="s">{{.}}</div>{{end}}</div>
  <div class="card"><div class="k">Demonstrated distance</div><div class="v">{{printf "%.2f" .DistancePercent}}%</div><div class="s">of {{.BitcoinThreshold}} logical qubits</div></div>
  <div class="card"><div class="k">Independent reproductions</div><div class="v">{{.TotalReproductions}}</div></div>
  <div class="card"><div class="k">Mitigation posture</div><div class="v"><span class="mode">{{.MitigationMode}}</span></div><div class="s">{{.MitigationName}}</div></div>
</div>
{{if .OpenLevels}}<p>Open challenges: {{range $i, $l := .OpenLevels}}{{if $i}}, {{end}}level {{$l}}{{end}}</p>{{end}}
<h2>Bitcoin distance under QEC assumptions (1 Q6100 = 6100 physical qubits)</h2>
<table>
<tr><th>Profile</th><th>Phys / logical</th><th>Logical per Q6100</th><th>Curve bits per Q6100</th><th>Q6100 for Bitcoin</th><th>Physical qubits for Bitcoin</th></tr>
{{range .Distances}}<tr><td>{{.Profile}}</td>{{if .PhysicalPerLogical}}<td>{{.PhysicalPerLogical}}</td><td>{{.LogicalPerProcessor}}</td><td>{{.MaxCurveBitsPerProcessor}}</td><td>{{.ProcessorsForBitcoin}}</td><td>{{.PhysicalQubitsForBitcoin}}</td>{{else}}<td>&mdash;</td><td>&mdash;</td><td>&mdash;</td><td>&mdash;</td><td>&mdash;</td>{{end}}</tr>
{{end}}</table>
<div class="note">{{.Note}}<br>Active mitigation: {{.MitigationDesc}}</div>
</div></body></html>
`))
