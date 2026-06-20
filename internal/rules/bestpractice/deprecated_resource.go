package bestpractice

import (
	"github.com/terraform-lint/terraform-lint/internal/rules"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

var deprecatedResources = map[string]string{
	"aws_security_group_rule": "Consider using aws_vpc_security_group_ingress_rule or aws_vpc_security_group_egress_rule instead",
	"aws_s3_bucket_policy":    "Consider using aws_s3_bucket_policy with aws_s3_bucket instead of inline policies",
}

type DeprecatedResourceRule struct {
	rules.BaseRule
}

func NewDeprecatedResourceRule() *DeprecatedResourceRule {
	return &DeprecatedResourceRule{
		BaseRule: rules.NewBaseRule(
			"DEPRECATED_RESOURCE",
			"Deprecated Resource Type",
			"Resource type is deprecated, consider using the recommended alternative",
			types.SeverityWarning,
			types.CategoryBestPractice,
		),
	}
}

func (r *DeprecatedResourceRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, resource := range ctx.Resources {
		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		if suggestion, ok := deprecatedResources[resource.Type]; ok {
			findings = append(findings, r.NewFinding(
				ctx,
				resource.Range.Start.Line,
				resource.Range.Start.Column,
				"Resource type '"+resource.Type+"' is deprecated. "+suggestion,
				resource.Type,
				resource.Name,
			))
		}
	}

	return findings
}
