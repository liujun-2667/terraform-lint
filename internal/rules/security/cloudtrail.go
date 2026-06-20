package security

import (
	"github.com/terraform-lint/terraform-lint/internal/ast"
	
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type CloudTrailEnabledRule struct {
	types.BaseRule
}

func NewCloudTrailEnabledRule() *CloudTrailEnabledRule {
	return &CloudTrailEnabledRule{
		BaseRule: types.NewBaseRule(
			"CLOUDTRAIL_ENABLED",
			"CloudTrail Not Enabled",
			"CloudTrail should be enabled for API activity logging",
			types.SeverityWarning,
			types.CategorySecurity,
		),
	}
}

func (r *CloudTrailEnabledRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, resource := range ctx.Resources {
		if resource.Type != "aws_cloudtrail" {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		enabledAttr, ok := resource.Attributes["enable_log_file_validation"]
		if !ok {
			findings = append(findings, r.NewFinding(
				ctx,
				resource.Range.Start.Line,
				resource.Range.Start.Column,
				"CloudTrail does not have log file validation enabled",
				resource.Type,
				resource.Name,
			))
			continue
		}

		val, _, err := ast.GetAttributeValue(enabledAttr, nil)
		if err != nil {
			continue
		}

		if enabled, ok := val.(bool); ok && !enabled {
			findings = append(findings, r.NewFinding(
				ctx,
				resource.Range.Start.Line,
				resource.Range.Start.Column,
				"CloudTrail log file validation is disabled",
				resource.Type,
				resource.Name,
			))
		}
	}

	return findings
}
