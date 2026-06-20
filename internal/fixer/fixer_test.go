package fixer

import (
	"strings"
	"testing"

	"github.com/terraform-lint/terraform-lint/internal/types"
)

func TestDetectIndentStyle_Tabs(t *testing.T) {
	lines := []string{
		`resource "aws_s3_bucket" "example" {`,
		"\tbucket = \"example\"",
		`}`,
	}
	indent, depth := detectIndentStyle(lines)
	if indent != "\t" {
		t.Errorf("expected tab indent, got %q", indent)
	}
	if depth != 1 {
		t.Errorf("expected depth 1, got %d", depth)
	}
}

func TestDetectIndentStyle_TwoSpaces(t *testing.T) {
	lines := []string{
		`resource "aws_s3_bucket" "example" {`,
		"  bucket = \"example\"",
		`}`,
	}
	indent, depth := detectIndentStyle(lines)
	if indent != "  " {
		t.Errorf("expected 2-space indent, got %q", indent)
	}
	if depth != 2 {
		t.Errorf("expected depth 2, got %d", depth)
	}
}

func TestDetectIndentStyle_FourSpaces(t *testing.T) {
	lines := []string{
		`resource "aws_s3_bucket" "example" {`,
		"    bucket = \"example\"",
		`}`,
	}
	indent, depth := detectIndentStyle(lines)
	if indent != "    " {
		t.Errorf("expected 4-space indent, got %q", indent)
	}
	if depth != 4 {
		t.Errorf("expected depth 4, got %d", depth)
	}
}

func TestReindentContent_TwoSpacesToTabs(t *testing.T) {
	content := "tags = {\n  Environment = \"dev\"\n  Owner       = \"team\"\n}"
	expected := "tags = {\n\tEnvironment = \"dev\"\n\tOwner       = \"team\"\n}"
	result := reindentContent(content, "\t")
	if result != expected {
		t.Errorf("expected:\n%s\ngot:\n%s", expected, result)
	}
}

func TestReindentContent_TwoSpacesToFourSpaces(t *testing.T) {
	content := "tags = {\n  Environment = \"dev\"\n  Owner       = \"team\"\n}"
	expected := "tags = {\n    Environment = \"dev\"\n    Owner       = \"team\"\n}"
	result := reindentContent(content, "    ")
	if result != expected {
		t.Errorf("expected:\n%s\ngot:\n%s", expected, result)
	}
}

func TestReindentContent_SingleLine(t *testing.T) {
	content := `Owner = "team"`
	result := reindentContent(content, "\t")
	if result != content {
		t.Errorf("expected %q, got %q", content, result)
	}
}

func TestApplyAppendAttribute_TabIndent(t *testing.T) {
	f := NewFixer()
	lines := []string{
		`resource "aws_s3_bucket" "example" {`,
		"\tbucket = \"example\"",
		`}`,
	}

	f.indentUnit, _ = detectIndentStyle(lines)

	inst := types.FixInstruction{
		Action:       types.FixActionAppendAttribute,
		ResourceType: "aws_s3_bucket",
		ResourceName: "example",
		Attribute:    "tags",
		Content:      "tags = {\n  Environment = \"dev\"\n  Owner       = \"team\"\n}",
		Line:         1,
		Column:       1,
	}

	result := f.applyAppendAttribute(&lines, inst)
	if !result.Applied {
		t.Fatalf("fix was not applied: %s", result.Error)
	}

	fixedText := strings.Join(lines, "\n")
	if strings.Contains(fixedText, "    ") {
		t.Errorf("expected tab indentation, but found 4-space indentation in:\n%s", fixedText)
	}
	if !strings.Contains(fixedText, "\t\tEnvironment = \"dev\"") {
		t.Errorf("expected double-tab indented tag content, got:\n%s", fixedText)
	}
}

func TestApplyAppendAttribute_FourSpaceIndent(t *testing.T) {
	f := NewFixer()
	lines := []string{
		`resource "aws_s3_bucket" "example" {`,
		"    bucket = \"example\"",
		`}`,
	}

	f.indentUnit, _ = detectIndentStyle(lines)

	inst := types.FixInstruction{
		Action:       types.FixActionAppendAttribute,
		ResourceType: "aws_s3_bucket",
		ResourceName: "example",
		Attribute:    "tags",
		Content:      "tags = {\n  Environment = \"dev\"\n  Owner       = \"team\"\n}",
		Line:         1,
		Column:       1,
	}

	result := f.applyAppendAttribute(&lines, inst)
	if !result.Applied {
		t.Fatalf("fix was not applied: %s", result.Error)
	}

	fixedText := strings.Join(lines, "\n")
	if !strings.Contains(fixedText, "        Environment = \"dev\"") {
		t.Errorf("expected 8-space indented tag content (4+4), got:\n%s", fixedText)
	}
	if strings.Contains(fixedText, "\t") {
		t.Errorf("expected no tab indentation in:\n%s", fixedText)
	}
}
