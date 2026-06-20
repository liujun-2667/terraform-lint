package security

import (
	"github.com/terraform-lint/terraform-lint/internal/rules"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type IAMUserAccessKeyRule struct {
	rules.BaseRule
}

func NewIAMUserAccessKeyRule() *IAMUserAccessKeyRule {
	return &IAMUserAccessKeyRule{
		BaseRule: rules.NewBaseRule(
			"IAM_USER_ACCESS_KEY",
			"IAM User Has Access Key",
			"IAM users should not have access keys - use roles instead",
			types.SeverityWarning,
			types.CategorySecurity,
		),
	}
}

func (r *IAMUserAccessKeyRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, resource := range ctx.Resources {
		if resource.Type != "aws_iam_access_key" {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		findings = append(findings, r.NewFinding(
			ctx,
			resource.Range.Start.Line,
			resource.Range.Start.Column,
			"IAM user access key created - consider using roles instead",
			resource.Type,
			resource.Name,
		))
	}

	return findings
}
