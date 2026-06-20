package types

import (
	"github.com/hashicorp/hcl/v2"
)

type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
	SeverityInfo    Severity = "info"
)

type RuleCategory string

const (
	CategorySecurity     RuleCategory = "security"
	CategoryBestPractice RuleCategory = "best_practice"
	CategoryCost         RuleCategory = "cost"
)

type Finding struct {
	File        string      `json:"file"`
	Line        int         `json:"line"`
	Column      int         `json:"column"`
	RuleID      string      `json:"rule_id"`
	Severity    Severity    `json:"severity"`
	Category    RuleCategory `json:"category"`
	Message     string      `json:"message"`
	Description string      `json:"description,omitempty"`
	FixSuggestion string    `json:"fix_suggestion,omitempty"`
	ResourceType string     `json:"resource_type,omitempty"`
	ResourceName string     `json:"resource_name,omitempty"`
	Range       hcl.Range   `json:"-"`
}

type Rule interface {
	ID() string
	Name() string
	Description() string
	Severity() Severity
	Category() RuleCategory
	Enabled() bool
	SetEnabled(bool)
	SetSeverity(Severity)
	Check(ctx *RuleContext) []Finding
	CanFix() bool
	Fix(ctx *RuleContext, finding *Finding) error
	IsPlugin() bool
}

type RuleContext struct {
	File         *ParsedFile
	Resources    []Resource
	Variables    map[string]Variable
	Locals       map[string]interface{}
	Outputs      []Output
	ModuleCalls  []ModuleCall
	ProviderConfigs []ProviderConfig
	Backend      *BackendConfig
	IgnoreRules  map[int][]string
}

type ParsedFile struct {
	Path      string
	Content   []byte
	Body      hcl.Body
	Diagnostics hcl.Diagnostics
	Resources []Resource
}

type Block struct {
	Type       string
	Labels     []string
	Attributes map[string]hcl.Expression
	Blocks     []*Block
	Range      hcl.Range
}

type Resource struct {
	Type       string
	Name       string
	Config     hcl.Body
	Address    string
	Range      hcl.Range
	Attributes map[string]hcl.Expression
	Blocks     []*Block
}

type Variable struct {
	Name        string
	Description string
	Type        string
	Default     interface{}
	Sensitive   bool
	Range       hcl.Range
}

type Output struct {
	Name        string
	Description string
	Value       hcl.Expression
	Sensitive   bool
	Range       hcl.Range
}

type ModuleCall struct {
	Name    string
	Source  string
	Version string
	Config  hcl.Body
	Range   hcl.Range
}

type ProviderConfig struct {
	Name   string
	Config hcl.Body
	Range  hcl.Range
}

type BackendConfig struct {
	Type   string
	Config hcl.Body
	Range  hcl.Range
}

type Config struct {
	Rules       map[string]RuleConfig `yaml:"rules"`
	IgnorePaths []string              `yaml:"ignore_paths"`
	Global      GlobalConfig          `yaml:"global"`
}

type RuleConfig struct {
	Enabled  *bool              `yaml:"enabled"`
	Severity *Severity          `yaml:"severity"`
	Params   map[string]interface{} `yaml:"params"`
}

type GlobalConfig struct {
	RequiredTags      []string `yaml:"required_tags"`
	NamingRegex       string   `yaml:"naming_regex"`
	MaxConcurrency    int      `yaml:"max_concurrency"`
}

type ScanOptions struct {
	Dir         string
	ConfigFile  string
	Format      string
	OutputFile  string
	FailOn      Severity
	ChangedOnly bool
	Fix         bool
}

type ScanResult struct {
	FilesScanned int       `json:"files_scanned"`
	Findings     []Finding `json:"findings"`
	Summary      Summary   `json:"summary"`
	Duration     string    `json:"duration"`
}

type Summary struct {
	Errors   int `json:"errors"`
	Warnings int `json:"warnings"`
	Infos    int `json:"infos"`
}

func (s Severity) Value() int {
	switch s {
	case SeverityError:
		return 3
	case SeverityWarning:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// BaseRule provides a default implementation for the Rule interface.
type BaseRule struct {
	RuleID          string
	RuleName        string
	RuleDescription string
	RuleSeverity    Severity
	RuleCategory    RuleCategory
	RuleEnabled     bool
	Params          map[string]interface{}
	IsPluginRule    bool
}

func NewBaseRule(
	id, name, description string,
	severity Severity,
	category RuleCategory,
) BaseRule {
	return BaseRule{
		RuleID:          id,
		RuleName:        name,
		RuleDescription: description,
		RuleSeverity:    severity,
		RuleCategory:    category,
		RuleEnabled:     true,
	}
}

func (r *BaseRule) ID() string            { return r.RuleID }
func (r *BaseRule) Name() string           { return r.RuleName }
func (r *BaseRule) Description() string    { return r.RuleDescription }
func (r *BaseRule) Severity() Severity     { return r.RuleSeverity }
func (r *BaseRule) Category() RuleCategory { return r.RuleCategory }
func (r *BaseRule) Enabled() bool          { return r.RuleEnabled }
func (r *BaseRule) SetEnabled(enabled bool) { r.RuleEnabled = enabled }
func (r *BaseRule) SetSeverity(severity Severity) { r.RuleSeverity = severity }
func (r *BaseRule) SetID(id string) { r.RuleID = id }
func (r *BaseRule) SetName(name string) { r.RuleName = name }
func (r *BaseRule) SetDescription(desc string) { r.RuleDescription = desc }
func (r *BaseRule) SetCategory(cat RuleCategory) { r.RuleCategory = cat }

func (r *BaseRule) SetParams(params map[string]interface{}) {
	r.Params = params
}

func (r *BaseRule) GetParam(key string, defaultValue interface{}) interface{} {
	if r.Params == nil {
		return defaultValue
	}
	if val, ok := r.Params[key]; ok {
		return val
	}
	return defaultValue
}

func (r *BaseRule) CanFix() bool { return false }

func (r *BaseRule) Fix(ctx *RuleContext, finding *Finding) error { return nil }

func (r *BaseRule) IsPlugin() bool { return r.IsPluginRule }

func (r *BaseRule) SetIsPlugin(isPlugin bool) { r.IsPluginRule = isPlugin }

func (r *BaseRule) NewFinding(
	ctx *RuleContext,
	line, column int,
	message string,
	resourceType, resourceName string,
) Finding {
	return Finding{
		File:         ctx.File.Path,
		Line:         line,
		Column:       column,
		RuleID:       r.RuleID,
		Severity:     r.RuleSeverity,
		Category:     r.RuleCategory,
		Message:      message,
		Description:  r.RuleDescription,
		ResourceType: resourceType,
		ResourceName: resourceName,
	}
}

func (r *BaseRule) ShouldIgnore(ctx *RuleContext, line int) bool {
	if rules, ok := ctx.IgnoreRules[line]; ok {
		for _, ruleID := range rules {
			if ruleID == r.RuleID || ruleID == "all" {
				return true
			}
		}
	}
	return false
}
