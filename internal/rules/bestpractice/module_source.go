package bestpractice

import (
	"strings"

	"github.com/terraform-lint/terraform-lint/internal/rules"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type ModuleSourceRule struct {
	rules.BaseRule
}

func NewModuleSourceRule() *ModuleSourceRule {
	return &ModuleSourceRule{
		BaseRule: rules.NewBaseRule(
			"MODULE_SOURCE",
			"Module Source Not Pinned",
			"Module sources should be pinned to a specific version or commit",
			types.SeverityWarning,
			types.CategoryBestPractice,
		),
	}
}

func (r *ModuleSourceRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, mod := range ctx.ModuleCalls {
		if r.ShouldIgnore(ctx, mod.Range.Start.Line) {
			continue
		}

		source := mod.Source
		if source == "" {
			continue
		}

		if strings.HasPrefix(source, "./") || strings.HasPrefix(source, "../") {
			continue
		}

		if mod.Version == "" {
			if strings.Contains(source, "?ref=") || strings.Contains(source, "//") {
				continue
			}
			findings = append(findings, r.NewFinding(
				ctx,
				mod.Range.Start.Line,
				mod.Range.Start.Column,
				"Module '"+mod.Name+"' source is not pinned to a specific version",
				"module",
				mod.Name,
			))
		}
	}

	return findings
}
