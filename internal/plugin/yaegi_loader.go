package plugin

import (
	"fmt"
	"os"
	"reflect"

	"github.com/traefik/yaegi/interp"
	"github.com/traefik/yaegi/stdlib"

	"github.com/terraform-lint/terraform-lint/internal/ast"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

func loadRuleWithYaegi(filePath string, meta *RuleMetadata) (types.Rule, error) {
	source, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	i := interp.New(interp.Options{})

	if err := i.Use(stdlib.Symbols); err != nil {
		return nil, fmt.Errorf("loading stdlib symbols: %w", err)
	}

	if err := registerTypesSymbols(i); err != nil {
		return nil, fmt.Errorf("registering types symbols: %w", err)
	}

	_, err = i.Eval(string(source))
	if err != nil {
		return nil, fmt.Errorf("evaluating rule source: %w", err)
	}

	newRuleVal, err := i.Eval("NewRule")
	if err != nil {
		return nil, fmt.Errorf("finding NewRule function: %w", err)
	}

	newRuleFunc := newRuleVal.Interface()
	newRuleFuncVal := reflect.ValueOf(newRuleFunc)

	if newRuleFuncVal.Kind() != reflect.Func {
		return nil, fmt.Errorf("NewRule is not a function")
	}

	results := newRuleFuncVal.Call(nil)
	if len(results) != 1 {
		return nil, fmt.Errorf("NewRule must return exactly one value")
	}

	ruleVal := results[0].Interface()

	rule, ok := ruleVal.(types.Rule)
	if !ok {
		return nil, fmt.Errorf("NewRule return value does not implement Rule interface")
	}

	setPluginFlag(rule)
	applyMetadata(rule, meta)

	return rule, nil
}

func applyMetadata(rule types.Rule, meta *RuleMetadata) {
	if settable, ok := rule.(interface{ SetID(string) }); ok {
		settable.SetID(meta.ID)
	}
	if settable, ok := rule.(interface{ SetName(string) }); ok {
		settable.SetName(meta.Name)
	}
	if meta.Description != "" {
		if settable, ok := rule.(interface{ SetDescription(string) }); ok {
			settable.SetDescription(meta.Description)
		}
	}
	if settable, ok := rule.(interface{ SetCategory(types.RuleCategory) }); ok {
		settable.SetCategory(meta.Category)
	}
	if settable, ok := rule.(interface{ SetSeverity(types.Severity) }); ok {
		settable.SetSeverity(meta.Severity)
	}
	if settable, ok := rule.(interface{ SetEnabled(bool) }); ok {
		settable.SetEnabled(meta.Enabled)
	}
}

func setPluginFlag(rule types.Rule) {
	if baseRule, ok := rule.(interface{ SetIsPlugin(bool) }); ok {
		baseRule.SetIsPlugin(true)
	}
}

func registerTypesSymbols(i *interp.Interpreter) error {
	typesPkg := map[string]reflect.Value{
		"SeverityError":        reflect.ValueOf(types.SeverityError),
		"SeverityWarning":      reflect.ValueOf(types.SeverityWarning),
		"SeverityInfo":         reflect.ValueOf(types.SeverityInfo),
		"CategorySecurity":     reflect.ValueOf(types.CategorySecurity),
		"CategoryBestPractice": reflect.ValueOf(types.CategoryBestPractice),
		"CategoryCost":         reflect.ValueOf(types.CategoryCost),
		"NewBaseRule":          reflect.ValueOf(types.NewBaseRule),
		"BaseRule":             reflect.ValueOf(reflect.TypeOf((*types.BaseRule)(nil)).Elem()),
		"RuleContext":          reflect.ValueOf(reflect.TypeOf((*types.RuleContext)(nil)).Elem()),
		"Finding":              reflect.ValueOf(reflect.TypeOf((*types.Finding)(nil)).Elem()),
		"Resource":             reflect.ValueOf(reflect.TypeOf((*types.Resource)(nil)).Elem()),
		"Variable":             reflect.ValueOf(reflect.TypeOf((*types.Variable)(nil)).Elem()),
		"Output":               reflect.ValueOf(reflect.TypeOf((*types.Output)(nil)).Elem()),
		"ModuleCall":           reflect.ValueOf(reflect.TypeOf((*types.ModuleCall)(nil)).Elem()),
		"ProviderConfig":       reflect.ValueOf(reflect.TypeOf((*types.ProviderConfig)(nil)).Elem()),
		"ParsedFile":           reflect.ValueOf(reflect.TypeOf((*types.ParsedFile)(nil)).Elem()),
		"Block":                reflect.ValueOf(reflect.TypeOf((*types.Block)(nil)).Elem()),
		"Severity":             reflect.ValueOf(reflect.TypeOf((*types.Severity)(nil)).Elem()),
		"RuleCategory":         reflect.ValueOf(reflect.TypeOf((*types.RuleCategory)(nil)).Elem()),
	}

	astPkg := map[string]reflect.Value{
		"GetAttributeValue": reflect.ValueOf(ast.GetAttributeValue),
	}

	return i.Use(interp.Exports{
		"github.com/terraform-lint/terraform-lint/internal/types": typesPkg,
		"github.com/terraform-lint/terraform-lint/internal/ast":   astPkg,
	})
}
