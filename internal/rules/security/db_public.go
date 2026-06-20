package security

import (
	"github.com/terraform-lint/terraform-lint/internal/ast"
	
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type DBPubliclyAccessibleRule struct {
	types.BaseRule
}

func NewDBPubliclyAccessibleRule() *DBPubliclyAccessibleRule {
	return &DBPubliclyAccessibleRule{
		BaseRule: types.NewBaseRule(
			"DB_PUBLICLY_ACCESSIBLE",
			"Database Publicly Accessible",
			"Database instances should not be publicly accessible",
			types.SeverityError,
			types.CategorySecurity,
		),
	}
}

func (r *DBPubliclyAccessibleRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding
	dbTypes := []string{"aws_db_instance", "aws_rds_cluster_instance", "aws_redshift_cluster"}

	for _, resource := range ctx.Resources {
		isDB := false
		for _, t := range dbTypes {
			if resource.Type == t {
				isDB = true
				break
			}
		}
		if !isDB {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		publicAttr, ok := resource.Attributes["publicly_accessible"]
		if !ok {
			continue
		}

		val, _, err := ast.GetAttributeValue(publicAttr, nil)
		if err != nil {
			continue
		}

		if public, ok := val.(bool); ok && public {
			attrRange := publicAttr.Range()
			findings = append(findings, r.NewFinding(
				ctx,
				attrRange.Start.Line,
				attrRange.Start.Column,
				"Database instance is publicly accessible",
				resource.Type,
				resource.Name,
			))
		}
	}

	return findings
}

func (r *DBPubliclyAccessibleRule) CanFix() bool {
	return true
}

func (r *DBPubliclyAccessibleRule) GenerateFix(ctx *types.RuleContext, finding *types.Finding) ([]types.FixInstruction, error) {
	return []types.FixInstruction{
		{
			Action:       types.FixActionReplaceValue,
			ResourceType: finding.ResourceType,
			ResourceName: finding.ResourceName,
			Attribute:    "publicly_accessible",
			OldValue:     "true",
			NewValue:     "false",
			Line:         finding.Line,
			Column:       finding.Column,
		},
	}, nil
}
