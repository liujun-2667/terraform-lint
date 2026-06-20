package security

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/terraform-lint/terraform-lint/internal/ast"
	"github.com/terraform-lint/terraform-lint/internal/rules"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type DynamoDBEncryptionRule struct {
	rules.BaseRule
}

func NewDynamoDBEncryptionRule() *DynamoDBEncryptionRule {
	return &DynamoDBEncryptionRule{
		BaseRule: rules.NewBaseRule(
			"DYNAMODB_ENCRYPTION",
			"DynamoDB Table Encryption Not Enabled",
			"DynamoDB tables should have encryption at rest enabled",
			types.SeverityWarning,
			types.CategorySecurity,
		),
	}
}

func (r *DynamoDBEncryptionRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, resource := range ctx.Resources {
		if resource.Type != "aws_dynamodb_table" {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		_, hasServerSide := resource.Attributes["server_side_encryption"]
		hasEnabled := false

		for _, block := range resource.Blocks {
			if block.Type == "server_side_encryption" {
				attrContent, _, _ := block.Body.PartialContent(&hcl.BodySchema{
					Attributes: []string{"enabled"},
				})
				if enabledAttr, ok := attrContent.Attributes["enabled"]; ok {
					val, _, err := ast.GetAttributeValue(enabledAttr, nil)
					if err == nil {
						if enabled, ok := val.(bool); ok && enabled {
							hasEnabled = true
						}
					}
				}
				break
			}
		}

		if !hasServerSide && !hasEnabled {
			findings = append(findings, r.NewFinding(
				ctx,
				resource.Range.Start.Line,
				resource.Range.Start.Column,
				"DynamoDB table does not have encryption at rest enabled",
				resource.Type,
				resource.Name,
			))
		}
	}

	return findings
}
