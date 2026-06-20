package testframework

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/terraform-lint/terraform-lint/internal/parser"
	"github.com/terraform-lint/terraform-lint/internal/rules"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type ExpectedFinding struct {
	Line     int
	Severity types.Severity
	RuleID   string
	Message  string
}

type TestCase struct {
	RuleID   string
	TestFile string
	Expected []ExpectedFinding
}

type TestResult struct {
	RuleID   string
	TestFile string
	Passed   bool
	Failures []string
	Actual   []types.Finding
	Expected []ExpectedFinding
}

type TestRunner struct {
	pluginDir string
}

func NewTestRunner(pluginDir string) *TestRunner {
	return &TestRunner{
		pluginDir: pluginDir,
	}
}

func (tr *TestRunner) RunTests() ([]TestResult, error) {
	testCases, err := tr.findTestCases()
	if err != nil {
		return nil, fmt.Errorf("finding test cases: %w", err)
	}

	if len(testCases) == 0 {
		return []TestResult{}, nil
	}

	ruleRegistry := rules.NewDefaultRuleRegistry()
	if err := ruleRegistry.LoadPlugins(tr.pluginDir); err != nil {
		return nil, fmt.Errorf("loading plugins: %w", err)
	}

	var results []TestResult

	for _, tc := range testCases {
		result := tr.runTestCase(tc, ruleRegistry)
		results = append(results, result)
	}

	return results, nil
}

func (tr *TestRunner) findTestCases() ([]TestCase, error) {
	if _, err := os.Stat(tr.pluginDir); os.IsNotExist(err) {
		return []TestCase{}, nil
	}

	files, err := filepath.Glob(filepath.Join(tr.pluginDir, "*_test.tf"))
	if err != nil {
		return nil, fmt.Errorf("finding test files: %w", err)
	}

	var testCases []TestCase

	for _, file := range files {
		tc, err := tr.parseTestCase(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to parse test case %s: %v\n", filepath.Base(file), err)
			continue
		}
		testCases = append(testCases, tc)
	}

	return testCases, nil
}

func (tr *TestRunner) parseTestCase(filePath string) (TestCase, error) {
	baseName := filepath.Base(filePath)
	ruleID := strings.TrimSuffix(baseName, "_test.tf")

	expected, err := parseExpectedFindings(filePath)
	if err != nil {
		return TestCase{}, fmt.Errorf("parsing expected findings: %w", err)
	}

	return TestCase{
		RuleID:   ruleID,
		TestFile: filePath,
		Expected: expected,
	}, nil
}

func parseExpectedFindings(filePath string) ([]ExpectedFinding, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	defer file.Close()

	var expected []ExpectedFinding
	lineNum := 0

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if !strings.HasPrefix(line, "//") {
			continue
		}

		comment := strings.TrimSpace(strings.TrimPrefix(line, "//"))
		if !strings.HasPrefix(comment, "expect:") {
			continue
		}

		expectLine := strings.TrimPrefix(comment, "expect:")
		expectLine = strings.TrimSpace(expectLine)

		finding, err := parseExpectLine(expectLine, lineNum)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNum, err)
		}

		expected = append(expected, finding)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	return expected, nil
}

func parseExpectLine(line string, commentLine int) (ExpectedFinding, error) {
	finding := ExpectedFinding{
		Line: commentLine + 1,
	}

	parts := strings.Fields(line)
	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}

		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])

		switch key {
		case "line":
			lineNum, err := strconv.Atoi(value)
			if err != nil {
				return ExpectedFinding{}, fmt.Errorf("invalid line number: %s", value)
			}
			finding.Line = lineNum
		case "severity":
			finding.Severity = types.Severity(value)
		case "rule":
			finding.RuleID = value
		case "message":
			finding.Message = value
		}
	}

	return finding, nil
}

func (tr *TestRunner) runTestCase(tc TestCase, registry *rules.RuleRegistry) TestResult {
	result := TestResult{
		RuleID:   tc.RuleID,
		TestFile: tc.TestFile,
		Expected: tc.Expected,
	}

	rule, ok := registry.GetByID(tc.RuleID)
	if !ok {
		result.Passed = false
		result.Failures = append(result.Failures, fmt.Sprintf("rule %s not found", tc.RuleID))
		return result
	}

	wasEnabled := rule.Enabled()
	originalSeverity := rule.Severity()

	rule.SetEnabled(true)

	defer func() {
		rule.SetEnabled(wasEnabled)
		rule.SetSeverity(originalSeverity)
	}()

	tempDir := filepath.Dir(tc.TestFile)
	p := parser.NewParser(tempDir, []string{}, 1)

	contexts, parseErrors := p.ParseFiles([]string{tc.TestFile})

	if len(parseErrors) > 0 {
		result.Passed = false
		for _, pe := range parseErrors {
			result.Failures = append(result.Failures, fmt.Sprintf("parse error: %s", pe.Error))
		}
		return result
	}

	var actualFindings []types.Finding
	for _, ctx := range contexts {
		findings := rule.Check(ctx)
		actualFindings = append(actualFindings, findings...)
	}

	result.Actual = actualFindings

	result.Passed, result.Failures = compareFindings(tc.Expected, actualFindings, tc.RuleID)

	return result
}

func compareFindings(expected []ExpectedFinding, actual []types.Finding, ruleID string) (bool, []string) {
	var failures []string

	matched := make(map[int]bool)

	for i, exp := range expected {
		found := false
		for _, act := range actual {
			if ruleID != "" && act.RuleID != ruleID && exp.RuleID == "" {
				continue
			}
			if exp.RuleID != "" && act.RuleID != exp.RuleID {
				continue
			}
			if act.Line == exp.Line {
				if exp.Severity != "" && act.Severity != exp.Severity {
					continue
				}
				if exp.Message != "" && !strings.Contains(act.Message, exp.Message) {
					continue
				}
				found = true
				break
			}
		}
		if !found {
			matched[i] = false
			failures = append(failures, fmt.Sprintf("Expected finding at line %d (severity=%s) not found", exp.Line, exp.Severity))
		} else {
			matched[i] = true
		}
	}

	for _, act := range actual {
		if ruleID != "" && act.RuleID != ruleID {
			continue
		}
		found := false
		for _, exp := range expected {
			if act.Line == exp.Line {
				if exp.Severity != "" && act.Severity != exp.Severity {
					continue
				}
				if exp.RuleID != "" && act.RuleID != exp.RuleID {
					continue
				}
				found = true
				break
			}
		}
		if !found {
			failures = append(failures, fmt.Sprintf("Unexpected finding at line %d: %s (severity=%s)", act.Line, act.Message, act.Severity))
		}
	}

	return len(failures) == 0, failures
}

func PrintTestResults(results []TestResult) {
	totalTests := len(results)
	passedTests := 0
	failedTests := 0

	for _, result := range results {
		if result.Passed {
			passedTests++
			fmt.Printf("  PASS: %s\n", result.RuleID)
		} else {
			failedTests++
			fmt.Printf("  FAIL: %s\n", result.RuleID)
			for _, failure := range result.Failures {
				fmt.Printf("    - %s\n", failure)
			}
		}
	}

	fmt.Println()
	fmt.Printf("Test summary: %d total, %d passed, %d failed\n", totalTests, passedTests, failedTests)
}
