package cost

import (
	"github.com/terraform-lint/terraform-lint/internal/ast"
	"github.com/terraform-lint/terraform-lint/internal/rules"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type UnusedElasticIPRule struct {
	rules.BaseRule
}

func NewUnusedElasticIPRule() *UnusedElasticIPRule {
	return &UnusedElasticIPRule{
		BaseRule: rules.NewBaseRule(
			"UNUSED_ELASTIC_IP",
			"Unused Elastic IP Address",
			"Elastic IP address is not associated with any resource and will incur costs",
			types.SeverityInfo,
			types.CategoryCost,
		),
	}
}

func (r *UnusedElasticIPRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, resource := range ctx.Resources {
		if resource.Type != "aws_eip" {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		instanceAttr, hasInstance := resource.Attributes["instance"]
		networkInterfaceAttr, hasNetworkInterface := resource.Attributes["network_interface"]
		associationWithPrivateIP := false

		for _, block := range resource.Blocks {
			if block.Type == "associate_with_private_ip" {
				associationWithPrivateIP = true
				break
			}
		}

		isAssociated := false

		if hasInstance {
			val, _, err := ast.GetAttributeValue(instanceAttr, nil)
			if err == nil {
				if instanceID, ok := val.(string); ok && instanceID != "" {
					isAssociated = true
				}
			} else {
				isAssociated = true
			}
		}

		if hasNetworkInterface && !isAssociated {
			val, _, err := ast.GetAttributeValue(networkInterfaceAttr, nil)
			if err == nil {
				if eniID, ok := val.(string); ok && eniID != "" {
					isAssociated = true
				}
			} else {
				isAssociated = true
			}
		}

		if associationWithPrivateIP {
			isAssociated = true
		}

		if !isAssociated {
			findings = append(findings, r.NewFinding(
				ctx,
				resource.Range.Start.Line,
				resource.Range.Start.Column,
				"Elastic IP address is not associated with any instance or network interface - unused EIPs incur costs",
				resource.Type,
				resource.Name,
			))
		}
	}

	return findings
}
