package plugin

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/terraform-lint/terraform-lint/internal/types"
)

type PluginLoader struct {
	pluginDir string
	rules     []types.Rule
}

func NewPluginLoader(pluginDir string) *PluginLoader {
	return &PluginLoader{
		pluginDir: pluginDir,
		rules:     make([]types.Rule, 0),
	}
}

func (pl *PluginLoader) Load() ([]types.Rule, error) {
	if _, err := os.Stat(pl.pluginDir); os.IsNotExist(err) {
		return pl.rules, nil
	}

	files, err := filepath.Glob(filepath.Join(pl.pluginDir, "*.go"))
	if err != nil {
		return nil, fmt.Errorf("finding plugin files: %w", err)
	}

	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}

		rule, err := pl.loadRuleFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to load plugin rule %s: %v\n", filepath.Base(file), err)
			continue
		}

		pl.rules = append(pl.rules, rule)
	}

	return pl.rules, nil
}

func (pl *PluginLoader) loadRuleFile(filePath string) (types.Rule, error) {
	meta, err := ParseMetadata(filePath)
	if err != nil {
		return nil, fmt.Errorf("parsing metadata: %w", err)
	}

	rule, err := loadRuleWithYaegi(filePath, meta)
	if err != nil {
		return nil, fmt.Errorf("loading rule: %w", err)
	}

	return rule, nil
}
