package bestpractice

import (
	"github.com/terraform-lint/terraform-lint/internal/ast"
	
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type ProviderVersionRule struct {
	types.BaseRule
}

func NewProviderVersionRule() *ProviderVersionRule {
	return &ProviderVersionRule{
		BaseRule: types.NewBaseRule(
			"PROVIDER_VERSION",
			"Provider Missing Version Constraint",
			"Providers should have explicit version constraints in required_providers",
			types.SeverityWarning,
			types.CategoryBestPractice,
		),
	}
}

func (r *ProviderVersionRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	requiredProviders := ast.ExtractRequiredProviders(ctx.File)
	configuredProviders := make(map[string]bool)
	for name := range requiredProviders {
		configuredProviders[name] = true
	}

	for _, provider := range ctx.ProviderConfigs {
		if r.ShouldIgnore(ctx, provider.Range.Start.Line) {
			continue
		}

		if !configuredProviders[provider.Name] {
			findings = append(findings, r.NewFinding(
				ctx,
				provider.Range.Start.Line,
				provider.Range.Start.Column,
				"Provider '"+provider.Name+"' does not have a version constraint in required_providers",
				"provider",
				provider.Name,
			))
		}
	}

	return findings
}
