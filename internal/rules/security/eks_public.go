package security

import (
	"github.com/terraform-lint/terraform-lint/internal/ast"
	
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type EKSPublicEndpointRule struct {
	types.BaseRule
}

func NewEKSPublicEndpointRule() *EKSPublicEndpointRule {
	return &EKSPublicEndpointRule{
		BaseRule: types.NewBaseRule(
			"EKS_PUBLIC_ENDPOINT",
			"EKS Cluster Public Endpoint Access Enabled",
			"EKS clusters should have public endpoint access restricted or disabled",
			types.SeverityWarning,
			types.CategorySecurity,
		),
	}
}

func (r *EKSPublicEndpointRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, resource := range ctx.Resources {
		if resource.Type != "aws_eks_cluster" {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		for _, block := range resource.Blocks {
			if block.Type == "vpc_config" {
				if publicAttr, ok := block.Attributes["endpoint_public_access"]; ok {
					val, _, err := ast.GetAttributeValue(publicAttr, nil)
					if err == nil {
						if public, ok := val.(bool); ok && public {
							findings = append(findings, r.NewFinding(
								ctx,
								block.Range.Start.Line,
								block.Range.Start.Column,
								"EKS cluster has public endpoint access enabled",
								resource.Type,
								resource.Name,
							))
						}
					}
				}
				break
			}
		}
	}

	return findings
}
