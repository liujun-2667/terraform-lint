package output

import (
	"encoding/xml"
	"fmt"

	"github.com/terraform-lint/terraform-lint/internal/types"
)

type JUnitFormatter struct{}

func NewJUnitFormatter() *JUnitFormatter {
	return &JUnitFormatter{}
}

func (f *JUnitFormatter) Name() string {
	return "junit"
}

func (f *JUnitFormatter) Format(result *types.ScanResult) (string, error) {
	testSuites := TestSuites{
		Tests: result.Summary.Errors + result.Summary.Warnings + result.Summary.Infos,
		Failures: result.Summary.Errors + result.Summary.Warnings,
	}

	testSuite := TestSuite{
		Name:     "terraform-lint",
		Tests:    result.Summary.Errors + result.Summary.Warnings + result.Summary.Infos,
		Failures: result.Summary.Errors + result.Summary.Warnings,
		Errors:   result.Summary.Errors,
	}

	for _, finding := range result.Findings {
		testCase := TestCase{
			Name:      fmt.Sprintf("%s - %s:%d", finding.RuleID, finding.File, finding.Line),
			Classname: "terraform-lint." + string(finding.Category),
			File:      finding.File,
			Line:      finding.Line,
		}

		if finding.Severity == types.SeverityError {
			testCase.Failure = &Failure{
				Message: finding.Message,
				Type:    string(finding.Severity),
				Content: fmt.Sprintf(
					"Rule: %s\nSeverity: %s\nFile: %s\nLine: %d\n\n%s\n\n%s",
					finding.RuleID,
					finding.Severity,
					finding.File,
					finding.Line,
					finding.Message,
					finding.Description,
				),
			}
		} else if finding.Severity == types.SeverityWarning {
			testCase.Failure = &Failure{
				Message: finding.Message,
				Type:    string(finding.Severity),
				Content: fmt.Sprintf(
					"Rule: %s\nSeverity: %s\nFile: %s\nLine: %d\n\n%s\n\n%s",
					finding.RuleID,
					finding.Severity,
					finding.File,
					finding.Line,
					finding.Message,
					finding.Description,
				),
			}
		}

		testSuite.TestCases = append(testSuite.TestCases, testCase)
	}

	testSuites.TestSuites = append(testSuites.TestSuites, testSuite)

	data, err := xml.MarshalIndent(testSuites, "", "  ")
	if err != nil {
		return "", err
	}

	return xml.Header + string(data) + "\n", nil
}

type TestSuites struct {
	XMLName   xml.Name    `xml:"testsuites"`
	Tests     int         `xml:"tests,attr"`
	Failures  int         `xml:"failures,attr"`
	TestSuites []TestSuite `xml:"testsuite"`
}

type TestSuite struct {
	Name      string     `xml:"name,attr"`
	Tests     int        `xml:"tests,attr"`
	Failures  int        `xml:"failures,attr"`
	Errors    int        `xml:"errors,attr"`
	TestCases []TestCase `xml:"testcase"`
}

type TestCase struct {
	Name      string   `xml:"name,attr"`
	Classname string   `xml:"classname,attr"`
	File      string   `xml:"file,attr"`
	Line      int      `xml:"line,attr"`
	Failure   *Failure `xml:"failure,omitempty"`
}

type Failure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Content string `xml:",chardata"`
}
