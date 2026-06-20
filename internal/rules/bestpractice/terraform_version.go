package bestpractice

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/terraform-lint/terraform-lint/internal/ast"
	
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type TerraformVersionRule struct {
	types.BaseRule
}

func NewTerraformVersionRule() *TerraformVersionRule {
	return &TerraformVersionRule{
		BaseRule: types.NewBaseRule(
			"TERRAFORM_VERSION",
			"Terraform Version Not Constrained",
			"Terraform configuration should specify a required_version constraint",
			types.SeverityWarning,
			types.CategoryBestPractice,
		),
	}
}

func (r *TerraformVersionRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	terraformContent, _, diags := ctx.File.Body.PartialContent(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "terraform"},
		},
	})
	if diags.HasErrors() {
		return findings
	}

	hasVersionConstraint := false
	for _, block := range terraformContent.Blocks {
		if block.Type == "terraform" {
			attrContent, _, _ := block.Body.PartialContent(&hcl.BodySchema{
				Attributes: []hcl.AttributeSchema{{Name: "required_version"}},
			})
			if _, ok := attrContent.Attributes["required_version"]; ok {
				hasVersionConstraint = true
				break
			}
		}
	}

	if !hasVersionConstraint && len(terraformContent.Blocks) > 0 {
		for _, block := range terraformContent.Blocks {
			if block.Type == "terraform" {
				if r.ShouldIgnore(ctx, block.DefRange.Start.Line) {
					continue
				}
				findings = append(findings, r.NewFinding(
					ctx,
					block.DefRange.Start.Line,
					block.DefRange.Start.Column,
					"Terraform configuration does not specify required_version constraint",
					"terraform",
					"version",
				))
				break
			}
		}
	}

	return findings
}
