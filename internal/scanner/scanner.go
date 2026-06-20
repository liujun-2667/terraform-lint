package scanner

import (
	"sync"
	"time"

	"github.com/terraform-lint/terraform-lint/internal/parser"
	"github.com/terraform-lint/terraform-lint/internal/rules"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type Scanner struct {
	ruleRegistry *rules.RuleRegistry
	config       *types.Config
	maxWorkers   int
}

func NewScanner(ruleRegistry *rules.RuleRegistry, config *types.Config, maxWorkers int) *Scanner {
	if maxWorkers <= 0 {
		maxWorkers = 4
	}
	return &Scanner{
		ruleRegistry: ruleRegistry,
		config:       config,
		maxWorkers:   maxWorkers,
	}
}

func (s *Scanner) Scan(dir string) (*types.ScanResult, []parser.ParseError, error) {
	startTime := time.Now()

	ignorePaths := []string{}
	if s.config != nil {
		ignorePaths = s.config.IgnorePaths
	}

	p := parser.NewParser(dir, ignorePaths, s.maxWorkers)
	contexts, parseErrors := p.ParseAll()

	var findings []types.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, s.maxWorkers)

	enabledRules := s.ruleRegistry.GetEnabled()

	for _, ctx := range contexts {
		wg.Add(1)
		semaphore <- struct{}{}
		go func(c *types.RuleContext) {
			defer wg.Done()
			defer func() { <-semaphore }()

			for _, rule := range enabledRules {
				ruleFindings := rule.Check(c)
				if len(ruleFindings) > 0 {
					mu.Lock()
					findings = append(findings, ruleFindings...)
					mu.Unlock()
				}
			}
		}(ctx)
	}

	wg.Wait()

	summary := types.Summary{}
	for _, finding := range findings {
		switch finding.Severity {
		case types.SeverityError:
			summary.Errors++
		case types.SeverityWarning:
			summary.Warnings++
		case types.SeverityInfo:
			summary.Infos++
		}
	}

	duration := time.Since(startTime)

	result := &types.ScanResult{
		FilesScanned: len(contexts),
		Findings:     findings,
		Summary:      summary,
		Duration:     duration.String(),
	}

	return result, parseErrors, nil
}

func (s *Scanner) ScanFiles(files []string) (*types.ScanResult, []parser.ParseError, error) {
	startTime := time.Now()

	ignorePaths := []string{}
	if s.config != nil {
		ignorePaths = s.config.IgnorePaths
	}

	p := parser.NewParser(".", ignorePaths, s.maxWorkers)
	contexts, parseErrors := p.ParseFiles(files)

	var findings []types.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, s.maxWorkers)

	enabledRules := s.ruleRegistry.GetEnabled()

	for _, ctx := range contexts {
		wg.Add(1)
		semaphore <- struct{}{}
		go func(c *types.RuleContext) {
			defer wg.Done()
			defer func() { <-semaphore }()

			for _, rule := range enabledRules {
				ruleFindings := rule.Check(c)
				if len(ruleFindings) > 0 {
					mu.Lock()
					findings = append(findings, ruleFindings...)
					mu.Unlock()
				}
			}
		}(ctx)
	}

	wg.Wait()

	summary := types.Summary{}
	for _, finding := range findings {
		switch finding.Severity {
		case types.SeverityError:
			summary.Errors++
		case types.SeverityWarning:
			summary.Warnings++
		case types.SeverityInfo:
			summary.Infos++
		}
	}

	duration := time.Since(startTime)

	result := &types.ScanResult{
		FilesScanned: len(contexts),
		Findings:     findings,
		Summary:      summary,
		Duration:     duration.String(),
	}

	return result, parseErrors, nil
}
