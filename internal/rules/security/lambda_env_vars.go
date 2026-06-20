package security

import (
	"github.com/terraform-lint/terraform-lint/internal/ast"
	
	"github.com/terraform-lint/terraform-lint/internal/types"
	"github.com/terraform-lint/terraform-lint/internal/utils"
)

type LambdaEnvVarsRule struct {
	types.BaseRule
}

func NewLambdaEnvVarsRule() *LambdaEnvVarsRule {
	return &LambdaEnvVarsRule{
		BaseRule: types.NewBaseRule(
			"LAMBDA_ENV_VARS",
			"Lambda Environment Variables Contain Sensitive Data",
			"Lambda function environment variables should not contain sensitive data in plaintext",
			types.SeverityError,
			types.CategorySecurity,
		),
	}
}

func (r *LambdaEnvVarsRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, resource := range ctx.Resources {
		if resource.Type != "aws_lambda_function" {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		for _, block := range resource.Blocks {
			if block.Type == "environment" {
				if varsAttr, ok := block.Attributes["variables"]; ok {
					val, _, err := ast.GetAttributeValue(varsAttr, nil)
					if err == nil {
						if valMap, ok := val.(map[string]interface{}); ok {
							for k, v := range valMap {
								if vStr, ok := v.(string); ok {
									if utils.LooksLikeSecret(vStr) {
										findings = append(findings, r.NewFinding(
											ctx,
											block.Range.Start.Line,
											block.Range.Start.Column,
											"Lambda environment variable '"+k+"' contains potential sensitive data",
											resource.Type,
											resource.Name,
										))
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return findings
}
