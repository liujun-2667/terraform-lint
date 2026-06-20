package security

import (
	"encoding/json"
	"github.com/terraform-lint/terraform-lint/internal/ast"
	
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type SQSPublicAccessRule struct {
	types.BaseRule
}

func NewSQSPublicAccessRule() *SQSPublicAccessRule {
	return &SQSPublicAccessRule{
		BaseRule: types.NewBaseRule(
			"SQS_PUBLIC_ACCESS",
			"SQS Queue Allows Public Access",
			"SQS queue policies should not allow public access",
			types.SeverityWarning,
			types.CategorySecurity,
		),
	}
}

func (r *SQSPublicAccessRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, resource := range ctx.Resources {
		if resource.Type != "aws_sqs_queue_policy" {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		policyAttr, ok := resource.Attributes["policy"]
		if !ok {
			continue
		}

		val, _, err := ast.GetAttributeValue(policyAttr, nil)
		if err != nil {
			continue
		}

		if policyStr, ok := val.(string); ok {
			if r.hasPublicAccess(policyStr) {
				findings = append(findings, r.NewFinding(
					ctx,
					resource.Range.Start.Line,
					resource.Range.Start.Column,
					"SQS queue policy allows public access",
					resource.Type,
					resource.Name,
				))
			}
		}
	}

	return findings
}

func (r *SQSPublicAccessRule) hasPublicAccess(policy string) bool {
	var policyDoc map[string]interface{}
	if err := json.Unmarshal([]byte(policy), &policyDoc); err != nil {
		return false
	}

	statements, ok := policyDoc["Statement"]
	if !ok {
		return false
	}

	var stmts []interface{}
	switch s := statements.(type) {
	case []interface{}:
		stmts = s
	case map[string]interface{}:
		stmts = []interface{}{s}
	default:
		return false
	}

	for _, stmt := range stmts {
		stmtMap, ok := stmt.(map[string]interface{})
		if !ok {
			continue
		}

		principal, ok := stmtMap["Principal"]
		if !ok {
			continue
		}

		if principal == "*" {
			return true
		}

		if pMap, ok := principal.(map[string]interface{}); ok {
			if aws, ok := pMap["AWS"]; ok && aws == "*" {
				return true
			}
		}
	}

	return false
}
