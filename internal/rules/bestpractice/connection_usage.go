package bestpractice

import (
	"github.com/hashicorp/hcl/v2"
	
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type ConnectionUsageRule struct {
	types.BaseRule
}

func NewConnectionUsageRule() *ConnectionUsageRule {
	return &ConnectionUsageRule{
		BaseRule: types.NewBaseRule(
			"CONNECTION_USAGE",
			"Connection Block Detected",
			"Connection blocks may expose sensitive credentials - use SSH keys or other secure methods",
			types.SeverityWarning,
			types.CategoryBestPractice,
		),
	}
}

func (r *ConnectionUsageRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, resource := range ctx.Resources {
		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		for _, block := range resource.Blocks {
			if block.Type == "connection" {
				if r.ShouldIgnore(ctx, block.DefRange.Start.Line) {
					continue
				}
				findings = append(findings, r.NewFinding(
					ctx,
					block.DefRange.Start.Line,
					block.DefRange.Start.Column,
					"Connection block detected - ensure credentials are not hardcoded",
					resource.Type,
					resource.Name,
				))
			}
		}
	}

	return findings
}
