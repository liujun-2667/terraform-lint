package bestpractice

import (
	"strings"

	"github.com/terraform-lint/terraform-lint/internal/rules"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type ModuleVersionRule struct {
	rules.BaseRule
}

func NewModuleVersionRule() *ModuleVersionRule {
	return &ModuleVersionRule{
		BaseRule: rules.NewBaseRule(
			"MODULE_VERSION",
			"Registry Module Missing Version Constraint",
			"Registry modules should have explicit version constraints",
			types.SeverityWarning,
			types.CategoryBestPractice,
		),
	}
}

func (r *ModuleVersionRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, mod := range ctx.ModuleCalls {
		if r.ShouldIgnore(ctx, mod.Range.Start.Line) {
			continue
		}

		source := mod.Source
		if source == "" {
			continue
		}

		if (strings.HasPrefix(source, "./") || strings.HasPrefix(source, "../")) {
			continue
		}

		if mod.Version == "" && !strings.Contains(source, "git::") {
			findings = append(findings, r.NewFinding(
				ctx,
				mod.Range.Start.Line,
				mod.Range.Start.Column,
				"Module '"+mod.Name+"' does not have a version constraint",
				"module",
				mod.Name,
			))
		}
	}

	return findings
}
