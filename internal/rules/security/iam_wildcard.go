package security

import (
	"encoding/json"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/terraform-lint/terraform-lint/internal/ast"
	"github.com/terraform-lint/terraform-lint/internal/rules"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type IAMWildcardActionRule struct {
	rules.BaseRule
}

func NewIAMWildcardActionRule() *IAMWildcardActionRule {
	return &IAMWildcardActionRule{
		BaseRule: rules.NewBaseRule(
			"IAM_WILDCARD_ACTION",
			"IAM Policy Wildcard Action",
			"IAM policies should not use wildcard (*) actions",
			types.SeverityWarning,
			types.CategorySecurity,
		),
	}
}

func (r *IAMWildcardActionRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, resource := range ctx.Resources {
		if resource.Type != "aws_iam_policy" && resource.Type != "aws_iam_role_policy" && resource.Type != "aws_iam_user_policy" {
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
			hasWildcard := r.checkPolicyForWildcard(policyStr)
			if hasWildcard {
				findings = append(findings, r.NewFinding(
					ctx,
					resource.Range.Start.Line,
					resource.Range.Start.Column,
					"IAM policy contains wildcard (*) action",
					resource.Type,
					resource.Name,
				))
			}
		}
	}

	return findings
}

func (r *IAMWildcardActionRule) checkPolicyForWildcard(policy string) bool {
	var policyDoc map[string]interface{}
	if err := json.Unmarshal([]byte(policy), &policyDoc); err != nil {
		if strings.Contains(policy, "\"Action\":\"*\"") || strings.Contains(policy, "\"Action\": \"*\"") {
			return true
		}
		if strings.Contains(policy, "\"*\"") && strings.Contains(policy, "Action") {
			return true
		}
		return false
	}

	statements, ok := policyDoc["Statement"]
	if !ok {
		return false
	}

	switch stmt := statements.(type) {
	case []interface{}:
		for _, s := range stmt {
			if r.checkStatement(s) {
				return true
			}
		}
	case map[string]interface{}:
		return r.checkStatement(stmt)
	}

	return false
}

func (r *IAMWildcardActionRule) checkStatement(stmt interface{}) bool {
	stmtMap, ok := stmt.(map[string]interface{})
	if !ok {
		return false
	}

	action, ok := stmtMap["Action"]
	if !ok {
		return false
	}

	switch a := action.(type) {
	case string:
		return a == "*" || strings.HasSuffix(a, ":*")
	case []interface{}:
		for _, act := range a {
			if actStr, ok := act.(string); ok {
				if actStr == "*" || strings.HasSuffix(actStr, ":*") {
					return true
				}
			}
		}
	}

	return false
}
