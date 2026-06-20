package bestpractice

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/terraform-lint/terraform-lint/internal/rules"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type ProvisionerUsageRule struct {
	rules.BaseRule
}

func NewProvisionerUsageRule() *ProvisionerUsageRule {
	return &ProvisionerUsageRule{
		BaseRule: rules.NewBaseRule(
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
				if r.ShouldIgnore(ctx, block.DefRange.Start.Line) {
					continue
				}
				findings = append(findings, r.NewFinding(
					ctx,
					block.DefRange.Start.Line,
					block.DefRange.Start.Column,
					"Provisioner usage detected - consider alternatives like configuration management tools",
					resource.Type,
					resource.Name,
				))
			}
		}
	}

	return findings
}
