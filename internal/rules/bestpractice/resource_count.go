package bestpractice

import (
	"github.com/terraform-lint/terraform-lint/internal/ast"
	"github.com/terraform-lint/terraform-lint/internal/rules"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type ResourceCountRule struct {
	rules.BaseRule
}

func NewResourceCountRule() *ResourceCountRule {
	return &ResourceCountRule{
		BaseRule: rules.NewBaseRule(
			"RESOURCE_COUNT",
			"Consider Using for_each Instead of count",
			"For resources that may need individual management, consider using for_each instead of count",
			types.SeverityInfo,
			types.CategoryBestPractice,
		),
	}
}

func (r *ResourceCountRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, resource := range ctx.Resources {
		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		if _, ok := resource.Attributes["count"]; ok {
			if _, hasForEach := resource.Attributes["for_each"]; !hasForEach {
				findings = append(findings, r.NewFinding(
					ctx,
					resource.Range.Start.Line,
					resource.Range.Start.Column,
					"Resource '"+resource.Name+"' uses count, consider for_each for better management",
					resource.Type,
					resource.Name,
				))
			}
		}
	}

	return findings
}
