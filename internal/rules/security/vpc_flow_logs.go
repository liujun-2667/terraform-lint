package security

import (
	"github.com/terraform-lint/terraform-lint/internal/ast"
	
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type VPCFlowLogsRule struct {
	types.BaseRule
}

func NewVPCFlowLogsRule() *VPCFlowLogsRule {
	return &VPCFlowLogsRule{
		BaseRule: types.NewBaseRule(
			"VPC_FLOW_LOGS",
			"VPC Flow Logs Not Enabled",
			"VPCs should have flow logs enabled for network traffic monitoring",
			types.SeverityInfo,
			types.CategorySecurity,
		),
	}
}

func (r *VPCFlowLogsRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	hasFlowLog := make(map[string]bool)
	for _, resource := range ctx.Resources {
		if resource.Type == "aws_flow_log" {
			if vpcAttr, ok := resource.Attributes["vpc_id"]; ok {
				val, _, err := ast.GetAttributeValue(vpcAttr, nil)
				if err == nil {
					if vpcID, ok := val.(string); ok {
						hasFlowLog[vpcID] = true
					}
				}
			}
		}
	}

	for _, resource := range ctx.Resources {
		if resource.Type != "aws_vpc" {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		vpcID := resource.Address
		if !hasFlowLog[vpcID] {
			findings = append(findings, r.NewFinding(
				ctx,
				resource.Range.Start.Line,
				resource.Range.Start.Column,
				"VPC does not have flow logs enabled",
				resource.Type,
				resource.Name,
			))
		}
	}

	return findings
}
