package bestpractice

import (
	
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type EmptyResourceRule struct {
	types.BaseRule
}

func NewEmptyResourceRule() *EmptyResourceRule {
	return &EmptyResourceRule{
		BaseRule: types.NewBaseRule(
			"EMPTY_RESOURCE",
			"Empty Resource Block",
			"Resource block has no attributes or blocks defined",
			types.SeverityInfo,
			types.CategoryBestPractice,
		),
	}
}

func (r *EmptyResourceRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, resource := range ctx.Resources {
		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		if len(resource.Attributes) == 0 && len(resource.Blocks) == 0 {
			findings = append(findings, r.NewFinding(
				ctx,
				resource.Range.Start.Line,
				resource.Range.Start.Column,
				"Resource '"+resource.Name+"' has no attributes or blocks defined",
				resource.Type,
				resource.Name,
			))
		}
	}

	return findings
}
