package security

import (
	"github.com/terraform-lint/terraform-lint/internal/rules"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type S3LoggingRule struct {
	rules.BaseRule
}

func NewS3LoggingRule() *S3LoggingRule {
	return &S3LoggingRule{
		BaseRule: rules.NewBaseRule(
			"S3_BUCKET_LOGGING",
			"S3 Bucket Access Logging Not Enabled",
			"S3 buckets should have access logging enabled for security auditing",
			types.SeverityInfo,
			types.CategorySecurity,
		),
	}
}

func (r *S3LoggingRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, resource := range ctx.Resources {
		if resource.Type != "aws_s3_bucket" {
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
				"S3 bucket does not have access logging enabled",
				resource.Type,
				resource.Name,
			))
		}
	}

	return findings
}
