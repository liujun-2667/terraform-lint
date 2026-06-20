package security

import (
	"github.com/terraform-lint/terraform-lint/internal/ast"
	
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type SecurityGroupOpenRule struct {
	types.BaseRule
}

func NewSecurityGroupOpenRule() *SecurityGroupOpenRule {
	return &SecurityGroupOpenRule{
		BaseRule: types.NewBaseRule(
			"SECURITY_GROUP_OPEN",
			"Security Group Open to World",
			"Security group ingress rules should not allow 0.0.0.0/0 for sensitive ports",
			types.SeverityError,
			types.CategorySecurity,
		),
	}
}

func (r *SecurityGroupOpenRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, resource := range ctx.Resources {
		if resource.Type != "aws_security_group" && resource.Type != "aws_security_group_rule" {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		if resource.Type == "aws_security_group" {
			for _, block := range resource.Blocks {
				if block.Type == "ingress" {
					findings = append(findings, r.checkIngressBlock(ctx, block, resource)...)
				}
			}
		} else if resource.Type == "aws_security_group_rule" {
			if typeAttr, ok := resource.Attributes["type"]; ok {
				val, _, err := ast.GetAttributeValue(typeAttr, nil)
				if err == nil {
					if typeStr, ok := val.(string); ok && typeStr == "ingress" {
						findings = append(findings, r.checkResourceIngress(ctx, resource)...)
					}
				}
			}
		}
	}

	return findings
}

func (r *SecurityGroupOpenRule) checkIngressBlock(ctx *types.RuleContext, block *types.Block, resource types.Resource) []types.Finding {
	var findings []types.Finding

	if cidrAttr, ok := block.Attributes["cidr_blocks"]; ok {
		val, _, err := ast.GetAttributeValue(cidrAttr, nil)
		if err != nil {
			return findings
		}

		if cidrs, ok := val.([]string); ok {
			for _, cidr := range cidrs {
				if cidr == "0.0.0.0/0" || cidr == "::/0" {
					if r.ShouldIgnore(ctx, block.Range.Start.Line) {
						continue
					}
					findings = append(findings, r.NewFinding(
						ctx,
						block.Range.Start.Line,
						block.Range.Start.Column,
						"Security group ingress rule allows traffic from 0.0.0.0/0",
						resource.Type,
						resource.Name,
					))
				}
			}
		}
	}

	return findings
}

func (r *SecurityGroupOpenRule) checkResourceIngress(ctx *types.RuleContext, resource types.Resource) []types.Finding {
	var findings []types.Finding

	if cidrAttr, ok := resource.Attributes["cidr_blocks"]; ok {
		val, _, err := ast.GetAttributeValue(cidrAttr, nil)
		if err != nil {
			return findings
		}

		if cidrs, ok := val.([]string); ok {
			for _, cidr := range cidrs {
				if cidr == "0.0.0.0/0" || cidr == "::/0" {
					findings = append(findings, r.NewFinding(
						ctx,
						resource.Range.Start.Line,
						resource.Range.Start.Column,
						"Security group rule allows traffic from 0.0.0.0/0",
						resource.Type,
						resource.Name,
					))
				}
			}
		}
	}

	return findings
}
