package bestpractice

import (
	"strings"

	"github.com/terraform-lint/terraform-lint/internal/rules"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type ResourcePrefixRule struct {
	rules.BaseRule
}

func NewResourcePrefixRule() *ResourcePrefixRule {
	return &ResourcePrefixRule{
		BaseRule: rules.NewBaseRule(
			"RESOURCE_PREFIX",
			"Resource Name Has Redundant Prefix",
			"Resource names should not include the resource type prefix (e.g., aws_)",
			types.SeverityInfo,
			types.CategoryBestPractice,
		),
	}
}

func (r *ResourcePrefixRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, resource := range ctx.Resources {
		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		resType := resource.Type
		resName := resource.Name

		prefixParts := strings.Split(resType, "_")
		if len(prefixParts) >= 2 {
			prefix := strings.Join(prefixParts[:2], "_") + "_"
			if strings.HasPrefix(resName, prefix) {
				findings = append(findings, r.NewFinding(
					ctx,
					resource.Range.Start.Line,
					resource.Range.Start.Column,
					"Resource name '"+resName+"' has redundant prefix '"+prefix+"'",
					resource.Type,
					resource.Name,
				))
			}
		}

		if strings.HasPrefix(resName, "aws_") && !strings.HasPrefix(resType, "aws_") {
			findings = append(findings, r.NewFinding(
				ctx,
				resource.Range.Start.Line,
				resource.Range.Start.Column,
				"Resource name '"+resName+"' has redundant 'aws_' prefix",
				resource.Type,
				resource.Name,
			))
		}
	}

	return findings
}
