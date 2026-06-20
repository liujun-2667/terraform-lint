package cli

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/terraform-lint/terraform-lint/internal/config"
	"github.com/terraform-lint/terraform-lint/internal/fixer"
	"github.com/terraform-lint/terraform-lint/internal/git"
	"github.com/terraform-lint/terraform-lint/internal/output"
	"github.com/terraform-lint/terraform-lint/internal/parser"
	"github.com/terraform-lint/terraform-lint/internal/rules"
	"github.com/terraform-lint/terraform-lint/internal/scanner"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type scanOptions struct {
	dir         string
	configFile  string
	format      string
	outputFile  string
	failOn      string
	changedOnly bool
	fix         bool
	concurrency int
}

func NewScanCommand() *cobra.Command {
	opts := &scanOptions{}

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan Terraform files for issues",
		Long:  `Scan Terraform configuration files for security risks, best practice violations, and cost optimization opportunities.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(opts)
		},
	}

	cmd.Flags().StringVar(&opts.dir, "dir", ".", "Directory to scan")
	cmd.Flags().StringVar(&opts.configFile, "config", "", "Path to configuration file")
	cmd.Flags().StringVar(&opts.format, "format", "terminal", "Output format (terminal, json, sarif, junit, markdown)")
	cmd.Flags().StringVar(&opts.outputFile, "output", "", "Output file path (default: stdout)")
	cmd.Flags().StringVar(&opts.failOn, "fail-on", "error", "Fail on (error, warning, info)")
	cmd.Flags().BoolVar(&opts.changedOnly, "changed-only", false, "Only scan changed files (git diff)")
	cmd.Flags().BoolVar(&opts.fix, "fix", false, "Automatically fix issues when possible")
	cmd.Flags().IntVar(&opts.concurrency, "concurrency", 4, "Number of concurrent workers")

	return cmd
}

func runScan(opts *scanOptions) error {
	configLoader := config.NewConfigLoader()
	cfg, err := configLoader.Load(opts.configFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	ruleRegistry := rules.NewDefaultRuleRegistry()
	if cfg != nil {
		ruleRegistry.ApplyConfig(cfg)
	}

	maxWorkers := opts.concurrency
	if cfg != nil && cfg.Global.MaxConcurrency > 0 {
		maxWorkers = cfg.Global.MaxConcurrency
	}

	s := scanner.NewScanner(ruleRegistry, cfg, maxWorkers)

	var result *types.ScanResult
	var parseErrors []parser.ParseError

	if opts.changedOnly {
		if !git.IsGitRepository(opts.dir) {
			return fmt.Errorf("--changed-only requires a git repository")
		}

		files, err := git.GetChangedFiles(opts.dir)
		if err != nil {
			return fmt.Errorf("getting changed files: %w", err)
		}

		if len(files) == 0 {
			fmt.Println(color.GreenString("✓ No changed Terraform files to scan"))
			return nil
		}

		fmt.Printf("Scanning %d changed files...\n", len(files))
		result, parseErrors, err = s.ScanFiles(files)
	} else {
		fmt.Printf("Scanning directory: %s\n", opts.dir)
		result, parseErrors, err = s.Scan(opts.dir)
	}

	if err != nil {
		return fmt.Errorf("scanning: %w", err)
	}

	if len(parseErrors) > 0 {
		fmt.Fprintln(os.Stderr, color.YellowString("\nParse errors:"))
		for _, pe := range parseErrors {
			if pe.Line > 0 {
				fmt.Fprintf(os.Stderr, "  %s:%d: %s\n", pe.File, pe.Line, pe.Error)
			} else {
				fmt.Fprintf(os.Stderr, "  %s: %s\n", pe.File, pe.Error)
			}
		}
	}

	if opts.fix && len(result.Findings) > 0 {
		f := fixer.NewFixer()
		fixedCount, err := f.Fix(result.Findings, ruleRegistry)
		if err != nil {
			return fmt.Errorf("fixing issues: %w", err)
		}
		if fixedCount > 0 {
			fmt.Printf(color.GreenString("\n✓ Fixed %d issues\n"), fixedCount)
		}
	}

	formatter, err := output.GetFormatter(opts.format)
	if err != nil {
		return err
	}

	if err := output.WriteOutput(formatter, result, opts.outputFile); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}

	exitCode := output.DetermineExitCode(result, opts.failOn)
	if exitCode != 0 {
		os.Exit(exitCode)
	}

	return nil
}
