package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
	dryRun      bool
	concurrency int
	pluginDir   string
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
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "Preview fixes without applying them (requires --fix)")
	cmd.Flags().IntVar(&opts.concurrency, "concurrency", 4, "Number of concurrent workers")
	cmd.Flags().StringVar(&opts.pluginDir, "plugin-dir", "rules", "Directory containing custom rule plugins")

	return cmd
}

func runScan(opts *scanOptions) error {
	if opts.dryRun && !opts.fix {
		return fmt.Errorf(color.RedString("--dry-run requires --fix flag. Usage: scan --fix --dry-run"))
	}

	configLoader := config.NewConfigLoader()
	cfg, err := configLoader.Load(opts.configFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	ruleRegistry := rules.NewDefaultRuleRegistry()

	if err := ruleRegistry.LoadPlugins(opts.pluginDir); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to load plugin rules: %v\n", err)
	}

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

	var fixSummary *types.FixSummary
	if opts.fix && len(result.Findings) > 0 {
		var err error
		fixSummary, result, err = runFixAndVerify(opts, result, ruleRegistry, cfg, maxWorkers)
		if err != nil {
			return fmt.Errorf("fixing issues: %w", err)
		}
		printFixSummary(fixSummary)
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

func runFixAndVerify(
	opts *scanOptions,
	initialResult *types.ScanResult,
	ruleRegistry *rules.RuleRegistry,
	cfg *types.Config,
	maxWorkers int,
) (*types.FixSummary, *types.ScanResult, error) {
	f := fixer.NewFixer()

	ctxCache := make(map[string]*types.RuleContext)
	ignorePaths := []string{}
	if cfg != nil {
		ignorePaths = cfg.IgnorePaths
	}

	getRuleContext := func(filePath string) *types.RuleContext {
		if ctx, ok := ctxCache[filePath]; ok {
			return ctx
		}
		p := parser.NewParser(filepath.Dir(filePath), ignorePaths, maxWorkers)
		contexts, _ := p.ParseFiles([]string{filePath})
		if len(contexts) > 0 {
			ctxCache[filePath] = contexts[0]
			return contexts[0]
		}
		return nil
	}

	fixSummary, err := f.Fix(initialResult.Findings, ruleRegistry, getRuleContext, opts.dryRun)
	if err != nil {
		return nil, initialResult, err
	}

	fixSummary.DryRun = opts.dryRun

	if fixSummary.FilesFixed == 0 || opts.dryRun {
		return fixSummary, initialResult, nil
	}

	s := scanner.NewScanner(ruleRegistry, cfg, maxWorkers)
	var verifiedResult *types.ScanResult
	var parseErrors []parser.ParseError

	if opts.changedOnly {
		files := getFixedFiles(fixSummary)
		verifiedResult, parseErrors, err = s.ScanFiles(files)
	} else {
		verifiedResult, parseErrors, err = s.Scan(opts.dir)
	}
	if err != nil {
		return fixSummary, initialResult, fmt.Errorf("verification scan: %w", err)
	}

	if len(parseErrors) > 0 {
		fmt.Fprintln(os.Stderr, color.YellowString("\nParse errors after fix:"))
		for _, pe := range parseErrors {
			if pe.Line > 0 {
				fmt.Fprintf(os.Stderr, "  %s:%d: %s\n", pe.File, pe.Line, pe.Error)
			} else {
				fmt.Fprintf(os.Stderr, "  %s: %s\n", pe.File, pe.Error)
			}
		}
	}

	rollbackFiles(fixSummary, initialResult.Findings, verifiedResult.Findings, f)

	finalFindings := make([]types.Finding, 0)
	rolledBackFiles := make(map[string]bool)
	for _, fs := range fixSummary.FileSummaries {
		if fs.RolledBack {
			rolledBackFiles[fs.File] = true
		}
	}
	for _, finding := range verifiedResult.Findings {
		if rolledBackFiles[finding.File] {
			continue
		}
		finalFindings = append(finalFindings, finding)
	}
	for _, finding := range initialResult.Findings {
		if rolledBackFiles[finding.File] {
			finalFindings = append(finalFindings, finding)
		}
	}

	finalSummary := types.Summary{}
	for _, finding := range finalFindings {
		switch finding.Severity {
		case types.SeverityError:
			finalSummary.Errors++
		case types.SeverityWarning:
			finalSummary.Warnings++
		case types.SeverityInfo:
			finalSummary.Infos++
		}
	}

	finalResult := &types.ScanResult{
		FilesScanned: verifiedResult.FilesScanned,
		Findings:     finalFindings,
		Summary:      finalSummary,
		Duration:     verifiedResult.Duration,
	}

	return fixSummary, finalResult, nil
}

func getFixedFiles(summary *types.FixSummary) []string {
	files := make([]string, 0, len(summary.FileSummaries))
	for _, fs := range summary.FileSummaries {
		if fs.FindingsFixed > 0 {
			files = append(files, fs.File)
		}
	}
	return files
}

func rollbackFiles(fixSummary *types.FixSummary, initialFindings, verifiedFindings []types.Finding, f *fixer.Fixer) {
	initialCountByFile := make(map[string]int)
	for _, finding := range initialFindings {
		initialCountByFile[finding.File]++
	}

	verifiedCountByFile := make(map[string]int)
	verifiedFindingsByFile := make(map[string][]types.Finding)
	for _, finding := range verifiedFindings {
		verifiedCountByFile[finding.File]++
		verifiedFindingsByFile[finding.File] = append(verifiedFindingsByFile[finding.File], finding)
	}

	fixedCountByFile := make(map[string]int)
	for _, fs := range fixSummary.FileSummaries {
		fixedCountByFile[fs.File] = fs.FindingsFixed
	}

	for i := range fixSummary.FileSummaries {
		fs := &fixSummary.FileSummaries[i]
		if fs.FindingsFixed == 0 {
			continue
		}

		initialCount := initialCountByFile[fs.File]
		verifiedCount := verifiedCountByFile[fs.File]
		expectedCount := initialCount - fixedCountByFile[fs.File]
		if expectedCount < 0 {
			expectedCount = 0
		}

		if verifiedCount > expectedCount {
			fs.RolledBack = true
			newIssues := verifiedCount - expectedCount
			if newIssues < 0 {
				newIssues = 0
			}
			fs.RollbackReason = fmt.Sprintf("%d new issue(s) introduced after fix", newIssues)
			fs.NewFindings = verifiedFindingsByFile[fs.File]

			if fs.BackupPath != "" {
				if err := f.RestoreBackup(fs.BackupPath); err != nil {
					fs.RollbackReason += fmt.Sprintf(" (rollback failed: %v)", err)
				}
			}
		}
	}
}

func printFixSummary(summary *types.FixSummary) {
	if summary == nil {
		return
	}

	hasChanges := summary.FilesFixed > 0 || summary.TotalSkipped > 0 || summary.FilesRolledBack > 0
	if !hasChanges {
		return
	}

	fmt.Println()
	if summary.DryRun {
		fmt.Println(color.CyanString("=== Dry-Run Fix Preview ==="))
		fmt.Println(color.YellowString("No changes will be applied. Review below and run without --dry-run to apply."))
	} else {
		fmt.Println(color.CyanString("=== Fix Summary ==="))
	}
	fmt.Printf("Files to be fixed: %d\n", summary.FilesFixed)
	fmt.Printf("Total fixes to be applied: %d\n", summary.TotalFixed)
	if summary.TotalSkipped > 0 {
		fmt.Printf(color.YellowString("Total fixes skipped: %d\n"), summary.TotalSkipped)
	}
	if summary.SkippedByConflict > 0 {
		fmt.Printf(color.YellowString("  Skipped due to conflict: %d\n"), summary.SkippedByConflict)
	}
	if summary.SkippedByValidation > 0 {
		fmt.Printf(color.RedString("  Skipped due to validation failure: %d\n"), summary.SkippedByValidation)
	}
	if summary.FilesRolledBack > 0 {
		fmt.Printf(color.YellowString("Files rolled back: %d\n"), summary.FilesRolledBack)
	}
	fmt.Println()

	for _, fs := range summary.FileSummaries {
		hasFileChanges := fs.FindingsFixed > 0 || fs.FindingsSkipped > 0 || fs.RolledBack
		if !hasFileChanges {
			continue
		}

		fmt.Printf("  %s: %d fixes, %d skipped\n", fs.File, fs.FindingsFixed, fs.FindingsSkipped)

		for _, r := range fs.Results {
			action := string(r.Action)
			if r.Applied {
				status := color.GreenString("will be applied")
				if !summary.DryRun {
					status = color.GreenString("applied")
				}
				fmt.Printf("    [%s] %s (line %d) - %s\n", r.RuleID, action, r.Line, status)
				if r.OriginalLine != "" {
					fmt.Printf("      %s\n", color.RedString("- "+r.OriginalLine))
				}
				if r.FixedLine != "" {
					fixedLines := strings.Split(r.FixedLine, "\n")
					for _, fl := range fixedLines {
						fmt.Printf("      %s\n", color.GreenString("+ "+fl))
					}
				}
			} else if r.Skipped {
				switch r.SkipReason {
				case types.SkipReasonConflict:
					fmt.Printf("    [%s] %s (line %d) - %s: %s\n",
						r.RuleID, action, r.Line,
						color.YellowString("skipped (conflict)"), r.SkipMessage)
				case types.SkipReasonValidation:
					fmt.Printf("    [%s] %s (line %d) - %s: %s\n",
						r.RuleID, action, r.Line,
						color.RedString("skipped (validation)"), r.SkipMessage)
				case types.SkipReasonDuplicate:
					fmt.Printf("    [%s] %s (line %d) - %s: %s\n",
						r.RuleID, action, r.Line,
						color.YellowString("skipped (duplicate)"), r.SkipMessage)
				}
			} else if r.Error != "" {
				fmt.Printf("    [%s] %s (line %d) - %s: %s\n",
					r.RuleID, action, r.Line, color.RedString("failed"), r.Error)
			}
		}

		if fs.OriginalContent != "" && fs.FixedContent != "" && fs.OriginalContent != fs.FixedContent {
			diff := fixer.GenerateDiff(fs.OriginalContent, fs.FixedContent)
			if diff != "" {
				fmt.Println()
				fmt.Println("    Diff preview:")
				diffLines := strings.Split(diff, "\n")
				for _, dl := range diffLines {
					if strings.HasPrefix(dl, "-") {
						fmt.Printf("    %s\n", color.RedString(dl))
					} else if strings.HasPrefix(dl, "+") {
						fmt.Printf("    %s\n", color.GreenString(dl))
					} else {
						fmt.Printf("    %s\n", dl)
					}
				}
			}
		}

		if fs.RolledBack {
			fmt.Printf("    %s: %s\n", color.YellowString("ROLLBACK"), fs.RollbackReason)
		}
		fmt.Println()
	}

	if summary.DryRun {
		fmt.Println(color.YellowString("Summary: %d fix(es) will be applied, %d skipped due to conflict, %d skipped due to validation failure.",
			summary.TotalFixed, summary.SkippedByConflict, summary.SkippedByValidation))
		fmt.Println(color.YellowString("Run 'scan --fix' without --dry-run to apply these changes."))
	} else {
		fmt.Printf("Summary: %d fix(es) applied, %d skipped due to conflict, %d skipped due to validation failure.\n",
			summary.TotalFixed, summary.SkippedByConflict, summary.SkippedByValidation)
	}
}
