package bestpractice

import (
	
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type VariableTypeRule struct {
	types.BaseRule
}

func NewVariableTypeRule() *VariableTypeRule {
	return &VariableTypeRule{
		BaseRule: types.NewBaseRule(
			"VARIABLE_TYPE",
			"Variable Missing Type Constraint",
			"Variables should have an explicit type constraint",
			types.SeverityInfo,
			types.CategoryBestPractice,
		),
	}
}

func (r *VariableTypeRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, variable := range ctx.Variables {
		if r.ShouldIgnore(ctx, variable.Range.Start.Line) {
			continue
		}

		if variable.Type == "" {
			findings = append(findings, r.NewFinding(
				ctx,
				variable.Range.Start.Line,
				variable.Range.Start.Column,
				"Variable '"+variable.Name+"' does not have an explicit type constraint",
				"variable",
				variable.Name,
			))
		}
	}

	return findings
}
