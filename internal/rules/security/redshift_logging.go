package security

import (
	"github.com/terraform-lint/terraform-lint/internal/rules"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type RedshiftAuditLoggingRule struct {
	rules.BaseRule
}

func NewRedshiftAuditLoggingRule() *RedshiftAuditLoggingRule {
	return &RedshiftAuditLoggingRule{
		BaseRule: rules.NewBaseRule(
			"REDSHIFT_AUDIT_LOGGING",
			"Redshift Cluster Audit Logging Not Enabled",
			"Redshift clusters should have audit logging enabled",
			types.SeverityInfo,
			types.CategorySecurity,
		),
	}
}

func (r *RedshiftAuditLoggingRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, resource := range ctx.Resources {
		if resource.Type != "aws_redshift_cluster" {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		hasLogging := false
		for _, block := range resource.Blocks {
			if block.Type == "logging" {
				hasLogging = true
				break
			}
		}

		if !hasLogging {
			findings = append(findings, r.NewFinding(
				ctx,
				resource.Range.Start.Line,
				resource.Range.Start.Column,
				"Redshift cluster does not have audit logging enabled",
				resource.Type,
				resource.Name,
			))
		}
	}

	return findings
}
