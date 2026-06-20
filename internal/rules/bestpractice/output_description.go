package bestpractice

import (
	
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type OutputDescriptionRule struct {
	types.BaseRule
}

func NewOutputDescriptionRule() *OutputDescriptionRule {
	return &OutputDescriptionRule{
		BaseRule: types.NewBaseRule(
			"OUTPUT_DESCRIPTION",
			"Output Missing Description",
			"Each output should have a description field",
			types.SeverityInfo,
			types.CategoryBestPractice,
		),
	}
}

func (r *OutputDescriptionRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, output := range ctx.Outputs {
		if r.ShouldIgnore(ctx, output.Range.Start.Line) {
			continue
		}

		if output.Description == "" {
			findings = append(findings, r.NewFinding(
				ctx,
				output.Range.Start.Line,
				output.Range.Start.Column,
				"Output '"+output.Name+"' is missing a description",
				"output",
				output.Name,
			))
		}
	}

	return findings
}
