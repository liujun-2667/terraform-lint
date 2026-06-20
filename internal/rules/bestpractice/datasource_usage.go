package bestpractice

import (
	
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type DataSourceUsageRule struct {
	types.BaseRule
}

func NewDataSourceUsageRule() *DataSourceUsageRule {
	return &DataSourceUsageRule{
		BaseRule: types.NewBaseRule(
			"DATASOURCE_USAGE",
			"Hardcoded Resource Reference",
			"Consider using data sources instead of hardcoded resource IDs",
			types.SeverityInfo,
			types.CategoryBestPractice,
		),
	}
}

func (r *DataSourceUsageRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	return findings
}
