package bestpractice

import (
	"github.com/terraform-lint/terraform-lint/internal/rules"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type VariableDefaultRule struct {
	rules.BaseRule
}

func NewVariableDefaultRule() *VariableDefaultRule {
	return &VariableDefaultRule{
		BaseRule: rules.NewBaseRule(
			"VARIABLE_DEFAULT",
			"Variable Has No Default Value",
			"Consider providing a default value for variables that are commonly used",
			types.SeverityInfo,
			types.CategoryBestPractice,
		),
	}
}

func (r *VariableDefaultRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, variable := range ctx.Variables {
		if r.ShouldIgnore(ctx, variable.Range.Start.Line) {
			continue
		}

		if variable.Default == nil {
			findings = append(findings, r.NewFinding(
				ctx,
				variable.Range.Start.Line,
				variable.Range.Start.Column,
				"Variable '"+variable.Name+"' has no default value",
				"variable",
				variable.Name,
			))
		}
	}

	return findings
}
