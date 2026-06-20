package security

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/terraform-lint/terraform-lint/internal/ast"
	"github.com/terraform-lint/terraform-lint/internal/rules"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type ECRScanningRule struct {
	rules.BaseRule
}

func NewECRScanningRule() *ECRScanningRule {
	return &ECRScanningRule{
		BaseRule: rules.NewBaseRule(
			"ECR_SCANNING",
			"ECR Repository Image Scanning Not Enabled",
			"ECR repositories should have image scanning enabled to detect vulnerabilities",
			types.SeverityWarning,
			types.CategorySecurity,
		),
	}
}

func (r *ECRScanningRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, resource := range ctx.Resources {
		if resource.Type != "aws_ecr_repository" {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		hasScanning := false
		for _, block := range resource.Blocks {
			if block.Type == "image_scanning_configuration" {
				attrContent, _, _ := block.Body.PartialContent(&hcl.BodySchema{
					Attributes: []string{"scan_on_push"},
				})
				if scanAttr, ok := attrContent.Attributes["scan_on_push"]; ok {
					val, _, err := ast.GetAttributeValue(scanAttr, nil)
					if err == nil {
						if enabled, ok := val.(bool); ok && enabled {
							hasScanning = true
						}
					}
				}
				break
			}
		}

		if !hasScanning {
			findings = append(findings, r.NewFinding(
				ctx,
				resource.Range.Start.Line,
				resource.Range.Start.Column,
				"ECR repository does not have image scanning enabled",
				resource.Type,
				resource.Name,
			))
		}
	}

	return findings
}
