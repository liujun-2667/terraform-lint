package security

import (
	"github.com/terraform-lint/terraform-lint/internal/ast"
	
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type SecurityGroupEgressAllRule struct {
	types.BaseRule
}

func NewSecurityGroupEgressAllRule() *SecurityGroupEgressAllRule {
	return &SecurityGroupEgressAllRule{
		BaseRule: types.NewBaseRule(
			"SECURITY_GROUP_EGRESS_ALL",
			"Security Group Allows All Egress Traffic",
			"Security groups should restrict egress traffic to necessary destinations",
			types.SeverityInfo,
			types.CategorySecurity,
		),
	}
}

func (r *SecurityGroupEgressAllRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, resource := range ctx.Resources {
		if resource.Type != "aws_security_group" {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		for _, block := range resource.Blocks {
			if block.Type == "egress" {
				if cidrAttr, ok := block.Attributes["cidr_blocks"]; ok {
					val, _, err := ast.GetAttributeValue(cidrAttr, nil)
					if err == nil {
						if cidrs, ok := val.([]string); ok {
							for _, cidr := range cidrs {
								if cidr == "0.0.0.0/0" {
									if !r.ShouldIgnore(ctx, block.Range.Start.Line) {
										findings = append(findings, r.NewFinding(
											ctx,
											block.Range.Start.Line,
											block.Range.Start.Column,
											"Security group allows all egress traffic to 0.0.0.0/0",
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
		}
	}

	return findings
}
