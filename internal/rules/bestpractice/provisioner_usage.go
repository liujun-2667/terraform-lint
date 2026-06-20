package bestpractice

import (
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type ProvisionerUsageRule struct {
	types.BaseRule
}

func NewProvisionerUsageRule() *ProvisionerUsageRule {
	return &ProvisionerUsageRule{
		BaseRule: types.NewBaseRule(
			"PROVISIONER_USAGE",
			"Provisioner Usage Detected",
			"Consider using configuration management tools instead of provisioners when possible",
			types.SeverityInfo,
			types.CategoryBestPractice,
		),
	}
}

func (r *ProvisionerUsageRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, resource := range ctx.Resources {
		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		for _, block := range resource.Blocks {
			if block.Type == "provisioner" {
				if r.ShouldIgnore(ctx, block.Range.Start.Line) {
					continue
				}
				findings = append(findings, r.NewFinding(
					ctx,
					block.Range.Start.Line,
					block.Range.Start.Column,
					"Provisioner usage detected - consider alternatives like configuration management tools",
					resource.Type,
					resource.Name,
				))
			}
		}
	}

	return findings
}
