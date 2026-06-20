package bestpractice

import (
	
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type VariableDescriptionRule struct {
	types.BaseRule
}

func NewVariableDescriptionRule() *VariableDescriptionRule {
	return &VariableDescriptionRule{
		BaseRule: types.NewBaseRule(
			"VARIABLE_DESCRIPTION",
			"Variable Missing Description",
			"Each variable should have a description field",
			types.SeverityInfo,
			types.CategoryBestPractice,
		),
	}
}

func (r *VariableDescriptionRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, variable := range ctx.Variables {
		if r.ShouldIgnore(ctx, variable.Range.Start.Line) {
			continue
		}

		if variable.Description == "" {
			findings = append(findings, r.NewFinding(
				ctx,
				variable.Range.Start.Line,
				variable.Range.Start.Column,
				"Variable '"+variable.Name+"' is missing a description",
				"variable",
				variable.Name,
			))
		}
	}

	return findings
}
