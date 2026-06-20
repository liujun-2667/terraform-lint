package security

import (
	"github.com/terraform-lint/terraform-lint/internal/ast"
	
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type RDSEncryptionRule struct {
	types.BaseRule
}

func NewRDSEncryptionRule() *RDSEncryptionRule {
	return &RDSEncryptionRule{
		BaseRule: types.NewBaseRule(
			"RDS_ENCRYPTION",
			"RDS Storage Encryption Not Enabled",
			"RDS instances should have storage encryption enabled",
			types.SeverityWarning,
			types.CategorySecurity,
		),
	}
}

func (r *RDSEncryptionRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding
	rdsTypes := []string{"aws_db_instance", "aws_rds_cluster"}

	for _, resource := range ctx.Resources {
		isRDS := false
		for _, t := range rdsTypes {
			if resource.Type == t {
				isRDS = true
				break
			}
		}
		if !isRDS {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		encAttr, ok := resource.Attributes["storage_encrypted"]
		if !ok {
			findings = append(findings, r.NewFinding(
				ctx,
				resource.Range.Start.Line,
				resource.Range.Start.Column,
				"RDS instance does not have storage encryption enabled",
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
				"RDS instance storage encryption is disabled",
				resource.Type,
				resource.Name,
			))
		}
	}

	return findings
}
