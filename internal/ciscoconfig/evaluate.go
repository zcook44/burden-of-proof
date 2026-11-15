package ciscoconfig

import "strings"

type idPair struct {
	Group string
	Rule  string
}

type checkContext struct {
	Config      *Config
	Roles       RoleTable
	Family      string
	BenchmarkID string
}

type checkSpec struct {
	Version string
	Title   string
	IDs     map[string]idPair
	Common  []string
	Phrases map[string][]string
	Eval    func(checkContext) (string, string, string)
}

// Evaluate returns a checklist status for one official rule.
// An empty status means this revision has no pinned check.
func Evaluate(cfg *Config, roles RoleTable, benchmarkID, groupID, ruleID, version, title, check string) (string, string, string) {
	spec, ok := checks[version]
	if !ok {
		return "", "", ""
	}
	id, ok := spec.IDs[benchmarkID]
	if !ok || id.Group != groupID || id.Rule != ruleID || !strings.Contains(title, spec.Title) {
		return "", "", ""
	}
	phrases := spec.Common
	if spec.Phrases != nil {
		if custom, exists := spec.Phrases[benchmarkID]; exists {
			phrases = custom
		}
	}
	for _, phrase := range phrases {
		if !strings.Contains(check, phrase) {
			return "", "", ""
		}
	}
	if cfg == nil || cfg.Uncertain {
		why := "The configuration could not be parsed unambiguously"
		if cfg != nil && cfg.Uncertainty != "" {
			why += " (" + cfg.Uncertainty + ")"
		}
		why += ", so this pinned check was not scored."
		return manual(why)
	}
	return spec.Eval(checkContext{Config: cfg, Roles: roles, Family: Family(benchmarkID), BenchmarkID: benchmarkID})
}

func pass(observation string) (string, string, string) {
	return "not_a_finding", "Automated config check: " + observation, "Not a Finding — " + observation
}

func fail(observation string) (string, string, string) {
	return "open", "Automated config check: " + observation, "Open — " + observation
}

func na(observation string) (string, string, string) {
	return "not_applicable", "Automated config check: " + observation, "Not Applicable — " + observation
}

func manual(why string) (string, string, string) {
	return "not_reviewed", why + " Manual review of the saved running config is required.", "NOT REVIEWED — " + why
}

func incomplete(family, what string) string {
	if family == "nxos" {
		return what + " The NX-OS snapshot has no version line or hostname, so a missing command was not scored as a finding."
	}
	return what + " The snapshot has no version line or closing end, so a missing command was not scored as a finding."
}

var checks = map[string]checkSpec{}

func register(spec checkSpec) {
	checks[spec.Version] = spec
}
