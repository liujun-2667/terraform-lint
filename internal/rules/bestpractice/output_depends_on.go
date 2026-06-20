package bestpractice

import (
	"github.com/terraform-lint/terraform-lint/internal/rules"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type OutputDependsOnRule struct {
	rules.BaseRule
}

func NewOutputDependsOnRule() *OutputDependsOnRule {
	return &OutputDependsOnRule{
		BaseRule: rules.NewBaseRule(
			"OUTPUT_DEPENDS_ON",
			"Output Uses depends_on",
			"Outputs should not use depends_on; let Terraform handle dependencies automatically",
			types.SeverityInfo,
			types.CategoryBestPractice,
		),
	}
}

func (r *OutputDependsOnRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, output := range ctx.Outputs {
		if r.ShouldIgnore(ctx, output.Range.Start.Line) {
			continue
		}
	}

	return findings
}
