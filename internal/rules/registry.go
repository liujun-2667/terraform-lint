package rules

import (
	"github.com/terraform-lint/terraform-lint/internal/rules/security"
	"github.com/terraform-lint/terraform-lint/internal/rules/bestpractice"
	"github.com/terraform-lint/terraform-lint/internal/rules/cost"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type RuleRegistry struct {
	rules map[string]types.Rule
}

func NewRuleRegistry() *RuleRegistry {
	return &RuleRegistry{
		rules: make(map[string]types.Rule),
	}
}

func (r *RuleRegistry) Register(rule types.Rule) {
	r.rules[rule.ID()] = rule
}

func (r *RuleRegistry) GetAll() []types.Rule {
	rules := make([]types.Rule, 0, len(r.rules))
	for _, rule := range r.rules {
		rules = append(rules, rule)
	}
	return rules
}

func (r *RuleRegistry) GetEnabled() []types.Rule {
	rules := make([]types.Rule, 0)
	for _, rule := range r.rules {
		if rule.Enabled() {
			rules = append(rules, rule)
		}
	}
	return rules
}

func (r *RuleRegistry) GetByID(id string) (types.Rule, bool) {
	rule, ok := r.rules[id]
	return rule, ok
}

func (r *RuleRegistry) ApplyConfig(config *types.Config) {
	if config == nil {
		return
	}

	for ruleID, ruleConfig := range config.Rules {
		if rule, ok := r.rules[ruleID]; ok {
			if ruleConfig.Enabled != nil {
				rule.SetEnabled(*ruleConfig.Enabled)
			}
			if ruleConfig.Severity != nil {
				rule.SetSeverity(*ruleConfig.Severity)
			}
			if baseRule, ok := rule.(interface{ SetParams(map[string]interface{}) }); ok {
				baseRule.SetParams(ruleConfig.Params)
			}
		}
	}
}

func NewDefaultRuleRegistry() *RuleRegistry {
	registry := NewRuleRegistry()

	registry.Register(security.NewS3BucketEncryptionRule())
	registry.Register(security.NewS3BucketPublicACLRule())
	registry.Register(security.NewSecurityGroupOpenRule())
	registry.Register(security.NewDBPubliclyAccessibleRule())
	registry.Register(security.NewIAMWildcardActionRule())
	registry.Register(security.NewInstanceNoVPCRule())
	registry.Register(security.NewSensitiveDataRule())
	registry.Register(security.NewOutputSensitiveRule())
	registry.Register(security.NewLocalBackendRule())
	registry.Register(security.NewS3VersioningRule())
	registry.Register(security.NewS3LoggingRule())
	registry.Register(security.NewSecurityGroupAllPortsRule())
	registry.Register(security.NewRDSEncryptionRule())
	registry.Register(security.NewEBSEncryptionRule())
	registry.Register(security.NewALBHTTPSRule())
	registry.Register(security.NewLambdaEnvVarsRule())
	registry.Register(security.NewKMSRotationRule())
	registry.Register(security.NewDynamoDBEncryptionRule())
	registry.Register(security.NewECRScanningRule())
	registry.Register(security.NewEKSPublicEndpointRule())
	registry.Register(security.NewSQSPublicAccessRule())
	registry.Register(security.NewSNSPublicAccessRule())
	registry.Register(security.NewIAMUserAccessKeyRule())
	registry.Register(security.NewSecurityGroupEgressAllRule())
	registry.Register(security.NewS3BucketPolicyPublicRule())
	registry.Register(security.NewElasticsearchVPCRule())
	registry.Register(security.NewRedshiftAuditLoggingRule())
	registry.Register(security.NewCloudTrailEnabledRule())
	registry.Register(security.NewVPCFlowLogsRule())
	registry.Register(security.NewECSPrivilegedRule())

	registry.Register(bestpractice.NewNamingConventionRule())
	registry.Register(bestpractice.NewResourceTagsRule())
	registry.Register(bestpractice.NewVariableDescriptionRule())
	registry.Register(bestpractice.NewOutputDescriptionRule())
	registry.Register(bestpractice.NewProviderVersionRule())
	registry.Register(bestpractice.NewResourcePrefixRule())
	registry.Register(bestpractice.NewTerraformVersionRule())
	registry.Register(bestpractice.NewModuleSourceRule())
	registry.Register(bestpractice.NewVariableTypeRule())
	registry.Register(bestpractice.NewOutputSensitiveRule())
	registry.Register(bestpractice.NewResourceCountRule())
	registry.Register(bestpractice.NewDataSourceUsageRule())
	registry.Register(bestpractice.NewEmptyResourceRule())
	registry.Register(bestpractice.NewDeprecatedResourceRule())
	registry.Register(bestpractice.NewVariableDefaultRule())
	registry.Register(bestpractice.NewOutputDependsOnRule())
	registry.Register(bestpractice.NewProvisionerUsageRule())
	registry.Register(bestpractice.NewConnectionUsageRule())
	registry.Register(bestpractice.NewResourceDescriptionRule())
	registry.Register(bestpractice.NewModuleVersionRule())

	registry.Register(cost.NewExpensiveInstanceTypeRule())
	registry.Register(cost.NewRDSMultiAZSmallRule())
	registry.Register(cost.NewUnusedEIPRule())
	registry.Register(cost.NewNATGatewayCountRule())
	registry.Register(cost.NewLargeVolumeSizeRule())
	registry.Register(cost.NewExcessiveProvisionedIOPSRule())
	registry.Register(cost.NewLongRunningInstanceRule())
	registry.Register(cost.NewUnusedLoadBalancerRule())
	registry.Register(cost.NewS3IntelligentTieringRule())
	registry.Register(cost.NewCloudFrontCompressionRule())
	registry.Register(cost.NewUnusedElasticIPRule())

	return registry
}
