package cost

import (
	"github.com/terraform-lint/terraform-lint/internal/ast"
	"github.com/terraform-lint/terraform-lint/internal/rules"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type UnusedEIPRule struct {
	rules.BaseRule
}

func NewUnusedEIPRule() *UnusedEIPRule {
	return &UnusedEIPRule{
		BaseRule: rules.NewBaseRule(
			"UNUSED_EIP",
			"Potential Unused Elastic IP",
			"Elastic IPs that are not associated with instances incur costs",
			types.SeverityInfo,
			types.CategoryCost,
		),
	}
}

func (r *UnusedEIPRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	eipAddresses := make(map[string]bool)
	associatedIPs := make(map[string]bool)

	for _, resource := range ctx.Resources {
		if resource.Type == "aws_eip" {
			eipAddresses[resource.Address] = true
		}

		if resource.Type == "aws_eip_association" {
			if eipAttr, ok := resource.Attributes["allocation_id"]; ok {
				val, _, err := ast.GetAttributeValue(eipAttr, nil)
				if err == nil {
					if eipID, ok := val.(string); ok {
						associatedIPs[eipID] = true
					}
				}
			}
		}

		if resource.Type == "aws_instance" {
			if eipAttr, ok := resource.Attributes["public_ip"]; ok {
				val, _, err := ast.GetAttributeValue(eipAttr, nil)
				if err == nil {
					if eip, ok := val.(string); ok {
						associatedIPs[eip] = true
					}
				}
			}
			if eipAttr, ok := resource.Attributes["associate_public_ip_address"]; ok {
				val, _, err := ast.GetAttributeValue(eipAttr, nil)
				if err == nil {
					if associate, ok := val.(bool); ok && associate {
						associatedIPs[resource.Address] = true
					}
				}
			}
		}

		if resource.Type == "aws_nat_gateway" {
			if eipAttr, ok := resource.Attributes["allocation_id"]; ok {
				val, _, err := ast.GetAttributeValue(eipAttr, nil)
				if err == nil {
					if eipID, ok := val.(string); ok {
						associatedIPs[eipID] = true
					}
				}
			}
		}
	}

	for _, resource := range ctx.Resources {
		if resource.Type != "aws_eip" {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		instanceAttr, ok := resource.Attributes["instance"]
		associated := false
		if ok {
			val, _, err := ast.GetAttributeValue(instanceAttr, nil)
			if err == nil {
				if instance, ok := val.(string); ok && instance != "" {
					associated = true
				}
			}
		}

		networkAttr, ok := resource.Attributes["network_interface"]
		if ok && !associated {
			val, _, err := ast.GetAttributeValue(networkAttr, nil)
			if err == nil {
				if nic, ok := val.(string); ok && nic != "" {
					associated = true
				}
			}
		}

		if !associated && !associatedIPs[resource.Address] {
			findings = append(findings, r.NewFinding(
				ctx,
				resource.Range.Start.Line,
				resource.Range.Start.Column,
				"Elastic IP '"+resource.Name+"' does not appear to be associated with any resource",
				resource.Type,
				resource.Name,
			))
		}
	}

	return findings
}
