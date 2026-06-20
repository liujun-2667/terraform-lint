package cli

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/terraform-lint/terraform-lint/internal/testframework"
)

func NewTestCommand() *cobra.Command {
	var pluginDir string

	cmd := &cobra.Command{
		Use:   "test",
		Short: "Run custom rule tests",
		Long:  `Run tests for custom rules. Test files should be named <RULE_ID>_test.tf and placed in the plugin directory.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			runner := testframework.NewTestRunner(pluginDir)

			fmt.Printf("Running tests from: %s\n", pluginDir)
			fmt.Println()

			results, err := runner.RunTests()
			if err != nil {
				return fmt.Errorf("running tests: %w", err)
			}

			if len(results) == 0 {
				fmt.Println(color.YellowString("No test files found. Test files should be named <RULE_ID>_test.tf and placed in the plugin directory."))
				return nil
			}

			totalTests := len(results)
			passedTests := 0
			failedTests := 0

			for _, result := range results {
				if result.Passed {
					passedTests++
					fmt.Printf("  %s %s\n", color.GreenString("PASS"), result.RuleID)
				} else {
					failedTests++
					fmt.Printf("  %s %s\n", color.RedString("FAIL"), result.RuleID)
					for _, failure := range result.Failures {
						fmt.Printf("    - %s\n", failure)
					}
				}
			}

			fmt.Println()
			fmt.Printf("Test summary: %d total, %s, %s\n",
				totalTests,
				color.GreenString("%d passed", passedTests),
				color.RedString("%d failed", failedTests),
			)

			if failedTests > 0 {
				os.Exit(1)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&pluginDir, "plugin-dir", "rules", "Directory containing custom rule plugins and tests")

	return cmd
}
