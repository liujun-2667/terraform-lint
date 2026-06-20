package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"

	"github.com/terraform-lint/terraform-lint/internal/config"
	"github.com/terraform-lint/terraform-lint/internal/rules"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

func NewRulesCommand() *cobra.Command {
	var configFile string
	var category string
	var pluginDir string

	cmd := &cobra.Command{
		Use:   "rules",
		Short: "List all available rules",
		Long:  `List all available rules with their current status (enabled/disabled), severity, and description.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			configLoader := config.NewConfigLoader()
			cfg, err := configLoader.Load(configFile)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			ruleRegistry := rules.NewDefaultRuleRegistry()

			if err := ruleRegistry.LoadPlugins(pluginDir); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to load plugin rules: %v\n", err)
			}

			if cfg != nil {
				ruleRegistry.ApplyConfig(cfg)
			}

			allRules := ruleRegistry.GetAll()
			sort.Slice(allRules, func(i, j int) bool {
				if allRules[i].Category() != allRules[j].Category() {
					return allRules[i].Category() < allRules[j].Category()
				}
				if allRules[i].IsPlugin() != allRules[j].IsPlugin() {
					return !allRules[i].IsPlugin()
				}
				return allRules[i].ID() < allRules[j].ID()
			})

			table := tablewriter.NewWriter(os.Stdout)
			table.SetHeader([]string{"Rule ID", "Category", "Severity", "Status", "Name"})
			table.SetAutoWrapText(false)
			table.SetAutoFormatHeaders(true)
			table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
			table.SetAlignment(tablewriter.ALIGN_LEFT)
			table.SetCenterSeparator("")
			table.SetColumnSeparator("")
			table.SetRowSeparator("")
			table.SetHeaderLine(false)
			table.SetTablePadding("  ")
			table.SetNoWhiteSpace(true)

			var totalEnabled, totalDisabled int
			var totalPlugin int
			categoryCount := make(map[string]int)

			for _, rule := range allRules {
				if category != "" && string(rule.Category()) != category {
					continue
				}

				status := color.GreenString("enabled")
				if !rule.Enabled() {
					status = color.RedString("disabled")
				}

				severityStr := string(rule.Severity())
				switch rule.Severity() {
				case types.SeverityError:
					severityStr = color.RedString(severityStr)
				case types.SeverityWarning:
					severityStr = color.YellowString(severityStr)
				case types.SeverityInfo:
					severityStr = color.BlueString(severityStr)
				}

				categoryStr := string(rule.Category())
				categoryCount[categoryStr]++

				if rule.Enabled() {
					totalEnabled++
				} else {
					totalDisabled++
				}

				if rule.IsPlugin() {
					totalPlugin++
				}

				ruleID := rule.ID()
				if rule.IsPlugin() {
					ruleID = ruleID + " " + color.MagentaString("[plugin]")
				}

				table.Append([]string{
					color.CyanString(ruleID),
					categoryStr,
					severityStr,
					status,
					rule.Name(),
				})
			}

			table.Render()

			fmt.Println()
			fmt.Printf("Total rules: %d (%s, %s)\n",
				len(allRules),
				color.GreenString("%d enabled", totalEnabled),
				color.RedString("%d disabled", totalDisabled),
			)
			if totalPlugin > 0 {
				fmt.Printf("  %s: %d\n", color.MagentaString("plugin rules"), totalPlugin)
			}

			for cat, count := range categoryCount {
				fmt.Printf("  %s: %d\n", strings.Title(strings.ReplaceAll(cat, "_", " ")), count)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&configFile, "config", "", "Path to configuration file")
	cmd.Flags().StringVarP(&category, "category", "c", "", "Filter by category (security, best_practice, cost)")
	cmd.Flags().StringVar(&pluginDir, "plugin-dir", "rules", "Directory containing custom rule plugins")

	return cmd
}
