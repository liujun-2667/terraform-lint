package security

import (
	"github.com/terraform-lint/terraform-lint/internal/ast"
	
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type EBSEncryptionRule struct {
	types.BaseRule
}

func NewEBSEncryptionRule() *EBSEncryptionRule {
	return &EBSEncryptionRule{
		BaseRule: types.NewBaseRule(
			"EBS_ENCRYPTION",
			"EBS Volume Encryption Not Enabled",
			"EBS volumes should have encryption enabled",
			types.SeverityWarning,
			types.CategorySecurity,
		),
	}
}

func (r *EBSEncryptionRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding
	ebsTypes := []string{"aws_ebs_volume", "aws_ebs_default_kms_key", "aws_instance"}

	for _, resource := range ctx.Resources {
		isEBS := false
		for _, t := range ebsTypes {
			if resource.Type == t {
				isEBS = true
				break
			}
		}
		if !isEBS {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		if resource.Type == "aws_ebs_volume" {
			encAttr, ok := resource.Attributes["encrypted"]
			if !ok {
				findings = append(findings, r.NewFinding(
					ctx,
					resource.Range.Start.Line,
					resource.Range.Start.Column,
					"EBS volume does not have encryption enabled",
					resource.Type,
					resource.Name,
				))
				continue
			}

			val, _, err := ast.GetAttributeValue(encAttr, nil)
			if err != nil {
				continue
			}

			if encrypted, ok := val.(bool); ok && !encrypted {
				findings = append(findings, r.NewFinding(
					ctx,
					resource.Range.Start.Line,
					resource.Range.Start.Column,
					"EBS volume encryption is disabled",
					resource.Type,
					resource.Name,
				))
			}
		} else if resource.Type == "aws_instance" {
			for _, block := range resource.Blocks {
				if block.Type == "root_block_device" || block.Type == "ebs_block_device" {
					if encAttr, ok := block.Attributes["encrypted"]; ok {
						val, _, err := ast.GetAttributeValue(encAttr, nil)
						if err == nil {
							if encrypted, ok := val.(bool); ok && !encrypted {
								findings = append(findings, r.NewFinding(
									ctx,
									block.Range.Start.Line,
									block.Range.Start.Column,
									"EC2 instance block device encryption is disabled",
									resource.Type,
									resource.Name,
								))
							}
						}
					}
				}
			}
		}
	}

	return findings
}
