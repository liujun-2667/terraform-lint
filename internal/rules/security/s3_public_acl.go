package security

import (
	"github.com/terraform-lint/terraform-lint/internal/ast"
	
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type S3BucketPublicACLRule struct {
	types.BaseRule
}

func NewS3BucketPublicACLRule() *S3BucketPublicACLRule {
	return &S3BucketPublicACLRule{
		BaseRule: types.NewBaseRule(
			"S3_BUCKET_PUBLIC_ACL",
			"S3 Bucket Public ACL Detected",
			"S3 buckets should not use public-read or public-read-write ACLs",
			types.SeverityError,
			types.CategorySecurity,
		),
	}
}

func (r *S3BucketPublicACLRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, resource := range ctx.Resources {
		if resource.Type != "aws_s3_bucket_acl" && resource.Type != "aws_s3_bucket" {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		aclAttr, ok := resource.Attributes["acl"]
		if !ok {
			continue
		}

		val, _, err := ast.GetAttributeValue(aclAttr, nil)
		if err != nil {
			continue
		}

		if aclStr, ok := val.(string); ok {
			if aclStr == "public-read" || aclStr == "public-read-write" {
				findings = append(findings, r.NewFinding(
					ctx,
					resource.Range.Start.Line,
					resource.Range.Start.Column,
					"S3 bucket uses public ACL: "+aclStr,
					resource.Type,
					resource.Name,
				))
			}
		}
	}

	return findings
}
