package parser

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/terraform-lint/terraform-lint/internal/ast"
	"github.com/terraform-lint/terraform-lint/internal/types"
	"github.com/terraform-lint/terraform-lint/internal/utils"
)

type Parser struct {
	rootDir      string
	ignorePaths  []string
	maxWorkers   int
	parseErrors  []ParseError
	mu           sync.Mutex
}

type ParseError struct {
	File  string
	Line  int
	Error string
}

func NewParser(rootDir string, ignorePaths []string, maxWorkers int) *Parser {
	if maxWorkers <= 0 {
		maxWorkers = 4
	}
	return &Parser{
		rootDir:     rootDir,
		ignorePaths: ignorePaths,
		maxWorkers:  maxWorkers,
	}
}

func (p *Parser) ParseAll() ([]*types.RuleContext, []ParseError) {
	files, err := utils.FindTerraformFiles(p.rootDir, p.ignorePaths)
	if err != nil {
		return nil, []ParseError{{File: p.rootDir, Error: err.Error()}}
	}

	fileContexts := make([]*types.RuleContext, 0)
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, p.maxWorkers)
	results := make(chan *parseResult, len(files))

	for _, file := range files {
		wg.Add(1)
		semaphore <- struct{}{}
		go func(f string) {
			defer wg.Done()
			defer func() { <-semaphore }()
			results <- p.parseFile(f)
		}(file)
	}

	wg.Wait()
	close(results)

	for result := range results {
		if result.Err != nil {
			p.mu.Lock()
			p.parseErrors = append(p.parseErrors, *result.Err)
			p.mu.Unlock()
			continue
		}
		if result.Context != nil {
			fileContexts = append(fileContexts, result.Context)
		}
	}

	return fileContexts, p.parseErrors
}

type parseResult struct {
	Context *types.RuleContext
	Err     *ParseError
}

func (p *Parser) parseFile(filePath string) *parseResult {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return &parseResult{
			Err: &ParseError{File: filePath, Error: err.Error()},
		}
	}

	parsedFile, diags := ast.ParseFile(filePath, content)
	if diags.HasErrors() {
		var errMsg strings.Builder
		line := 0
		for _, d := range diags {
			if d.Severity == 1 {
				errMsg.WriteString(d.Error())
				errMsg.WriteString("; ")
				if d.Subject != nil {
					line = d.Subject.Start.Line
				}
			}
		}
		return &parseResult{
			Err: &ParseError{
				File:  filePath,
				Line:  line,
				Error: errMsg.String(),
			},
		}
	}

	parsedFile.Resources = ast.ExtractResources(parsedFile)

	ctx := &types.RuleContext{
		File:            parsedFile,
		Resources:       parsedFile.Resources,
		Variables:       ast.ExtractVariables(parsedFile),
		Locals:          ast.ExtractLocals(parsedFile),
		Outputs:         ast.ExtractOutputs(parsedFile),
		ModuleCalls:     ast.ExtractModuleCalls(parsedFile),
		ProviderConfigs: ast.ExtractProviderConfigs(parsedFile),
		Backend:         ast.ExtractBackendConfig(parsedFile),
		IgnoreRules:     utils.ParseIgnoreComments(content),
	}

	p.parseModuleDependencies(ctx)

	return &parseResult{Context: ctx}
}

func (p *Parser) parseModuleDependencies(ctx *types.RuleContext) {
	for _, mod := range ctx.ModuleCalls {
		if mod.Source == "" {
			continue
		}

		modDir := filepath.Join(p.rootDir, mod.Source)
		if _, err := os.Stat(modDir); os.IsNotExist(err) {
			continue
		}

		absModDir, _ := filepath.Abs(modDir)
		modParser := NewParser(absModDir, p.ignorePaths, p.maxWorkers)
		modContexts, modErrors := modParser.ParseAll()

		p.mu.Lock()
		p.parseErrors = append(p.parseErrors, modErrors...)
		p.mu.Unlock()

		for _, modCtx := range modContexts {
			ctx.Resources = append(ctx.Resources, modCtx.Resources...)
			for k, v := range modCtx.Variables {
				ctx.Variables[k] = v
			}
			for k, v := range modCtx.Locals {
				ctx.Locals[k] = v
			}
			ctx.Outputs = append(ctx.Outputs, modCtx.Outputs...)
		}
	}
}

func (p *Parser) GetParseErrors() []ParseError {
	return p.parseErrors
}
