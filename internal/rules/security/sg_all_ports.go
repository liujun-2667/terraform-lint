package security

import (
	"github.com/terraform-lint/terraform-lint/internal/ast"
	
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type SecurityGroupAllPortsRule struct {
	types.BaseRule
}

func NewSecurityGroupAllPortsRule() *SecurityGroupAllPortsRule {
	return &SecurityGroupAllPortsRule{
		BaseRule: types.NewBaseRule(
			"SECURITY_GROUP_ALL_PORTS",
			"Security Group Allows All Ports",
			"Security group rules should not allow all ports (0-65535)",
			types.SeverityWarning,
			types.CategorySecurity,
		),
	}
}

func (r *SecurityGroupAllPortsRule) Check(ctx *types.RuleContext) []types.Finding {
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
					findings = append(findings, r.checkPortsBlock(ctx, block, resource)...)
				}
			}
		} else if resource.Type == "aws_security_group_rule" {
			findings = append(findings, r.checkPortsResource(ctx, resource)...)
		}
	}

	return findings
}

func (r *SecurityGroupAllPortsRule) checkPortsBlock(ctx *types.RuleContext, block *types.Block, resource types.Resource) []types.Finding {
	var findings []types.Finding

	fromPort := -1
	toPort := -1

	if attr, ok := block.Attributes["from_port"]; ok {
		val, _, err := ast.GetAttributeValue(attr, nil)
		if err == nil {
			if port, ok := val.(float64); ok {
				fromPort = int(port)
			}
		}
	}

	if attr, ok := block.Attributes["to_port"]; ok {
		val, _, err := ast.GetAttributeValue(attr, nil)
		if err == nil {
			if port, ok := val.(float64); ok {
				toPort = int(port)
			}
		}
	}

	if fromPort == 0 && toPort == 65535 {
		if !r.ShouldIgnore(ctx, block.Range.Start.Line) {
			findings = append(findings, r.NewFinding(
				ctx,
				block.Range.Start.Line,
				block.Range.Start.Column,
				"Security group rule allows all ports (0-65535)",
				resource.Type,
				resource.Name,
			))
		}
	}

	return findings
}

func (r *SecurityGroupAllPortsRule) checkPortsResource(ctx *types.RuleContext, resource types.Resource) []types.Finding {
	var findings []types.Finding

	fromPort := -1
	toPort := -1

	if attr, ok := resource.Attributes["from_port"]; ok {
		val, _, err := ast.GetAttributeValue(attr, nil)
		if err == nil {
			if port, ok := val.(float64); ok {
				fromPort = int(port)
			}
		}
	}

	if attr, ok := resource.Attributes["to_port"]; ok {
		val, _, err := ast.GetAttributeValue(attr, nil)
		if err == nil {
			if port, ok := val.(float64); ok {
				toPort = int(port)
			}
		}
	}

	if fromPort == 0 && toPort == 65535 {
		findings = append(findings, r.NewFinding(
			ctx,
			resource.Range.Start.Line,
			resource.Range.Start.Column,
			"Security group rule allows all ports (0-65535)",
			resource.Type,
			resource.Name,
		))
	}

	return findings
}
