package draft

import "github.com/zcook44/burden-of-proof/internal/ciscoconfig"

// CiscoConfigEvaluatorVersion changes whenever supported rule logic changes,
// keeping previous CKLBs and provenance immutable across evaluator updates.
const CiscoConfigEvaluatorVersion = "cisco-config-review-v9"

func evaluateCiscoRule(b officialBenchmark, g group, r rule, cfg *ciscoconfig.Config, roles ciscoconfig.RoleTable) (string, string, string) {
	return ciscoconfig.Evaluate(cfg, roles, b.ID, g.ID, r.ID, r.Version, r.Title, r.Check.Content)
}
