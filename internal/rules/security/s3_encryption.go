package security

import (
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type S3BucketEncryptionRule struct {
	types.BaseRule
}

func NewS3BucketEncryptionRule() *S3BucketEncryptionRule {
	return &S3BucketEncryptionRule{
		BaseRule: types.NewBaseRule(
			"S3_BUCKET_ENCRYPTION",
			"S3 Bucket Encryption Not Enabled",
			"S3 buckets should have server-side encryption enabled to protect data at rest",
			types.SeverityWarning,
			types.CategorySecurity,
		),
	}
}

func (r *S3BucketEncryptionRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, resource := range ctx.Resources {
		if resource.Type != "aws_s3_bucket" {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		hasEncryption := false

		if _, ok := resource.Attributes["server_side_encryption_configuration"]; ok {
			hasEncryption = true
		}

		for _, block := range resource.Blocks {
			if block.Type == "server_side_encryption_configuration" {
				hasEncryption = true
				break
			}
		}

		if !hasEncryption {
			findings = append(findings, r.NewFinding(
				ctx,
				resource.Range.Start.Line,
				resource.Range.Start.Column,
				"S3 bucket does not have server-side encryption enabled",
				resource.Type,
				resource.Name,
			))
		}
	}

	return findings
}

func (r *S3BucketEncryptionRule) CanFix() bool {
	return true
}

func (r *S3BucketEncryptionRule) GenerateFix(ctx *types.RuleContext, finding *types.Finding) ([]types.FixInstruction, error) {
	encryptionBlock := `server_side_encryption_configuration {
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}`

	return []types.FixInstruction{
		{
			Action:       types.FixActionAppendBlock,
			ResourceType: finding.ResourceType,
			ResourceName: finding.ResourceName,
			Content:      encryptionBlock,
			Line:         finding.Line,
			Column:       finding.Column,
		},
	}, nil
}
