package security

import (
	"github.com/terraform-lint/terraform-lint/internal/rules"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type S3VersioningRule struct {
	rules.BaseRule
}

func NewS3VersioningRule() *S3VersioningRule {
	return &S3VersioningRule{
		BaseRule: rules.NewBaseRule(
			"S3_BUCKET_VERSIONING",
			"S3 Bucket Versioning Not Enabled",
			"S3 buckets should have versioning enabled to prevent accidental data loss",
			types.SeverityInfo,
			types.CategorySecurity,
		),
	}
}

func (r *S3VersioningRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, resource := range ctx.Resources {
		if resource.Type != "aws_s3_bucket" {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		hasVersioning := false

		if _, ok := resource.Attributes["versioning"]; ok {
			hasVersioning = true
		}

		for _, block := range resource.Blocks {
			if block.Type == "versioning" {
				hasVersioning = true
				break
			}
		}

		if !hasVersioning {
			findings = append(findings, r.NewFinding(
				ctx,
				resource.Range.Start.Line,
				resource.Range.Start.Column,
				"S3 bucket does not have versioning enabled",
				resource.Type,
				resource.Name,
			))
		}
	}

	return findings
}
