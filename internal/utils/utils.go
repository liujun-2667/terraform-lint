package utils

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	awsAccessKeyPattern = regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16})`)
	awsSecretKeyPattern = regexp.MustCompile(`(?i)(aws_secret_access_key|aws_secret_key)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?`)
	passwordPattern     = regexp.MustCompile(`(?i)password\s*[=:]\s*["']?([^"'\s]{8,})["']?`)
	longRandomPattern   = regexp.MustCompile(`[A-Za-z0-9/+=]{32,}`)
	snakeCasePattern    = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)
	terraformPrefixPattern = regexp.MustCompile(`^aws_`)
)

func LooksLikeSecret(s string) bool {
	if awsAccessKeyPattern.MatchString(s) {
		return true
	}
	if awsSecretKeyPattern.MatchString(s) {
		return true
	}
	if passwordPattern.MatchString(s) {
		return true
	}
	if longRandomPattern.MatchString(s) && strings.ContainsAny(s, "+/=") {
		return true
	}
	return false
}

func IsSnakeCase(s string) bool {
	return snakeCasePattern.MatchString(s)
}

func HasTerraformPrefix(s string) bool {
	return terraformPrefixPattern.MatchString(s)
}

func FindTerraformFiles(rootDir string, ignorePaths []string) ([]string, error) {
	var files []string
	ignoreMap := make(map[string]bool)
	for _, p := range ignorePaths {
		ignoreMap[p] = true
	}

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, _ := filepath.Rel(rootDir, path)
		for ignore := range ignoreMap {
			if strings.HasPrefix(relPath, ignore) || strings.Contains(relPath, ignore) {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}

		if !info.IsDir() {
			ext := filepath.Ext(path)
			if ext == ".tf" || ext == ".tfvars" {
				absPath, _ := filepath.Abs(path)
				files = append(files, absPath)
			}
		}
		return nil
	})

	return files, err
}

func GetLineFromContent(content []byte, line int) string {
	lines := strings.Split(string(content), "\n")
	if line < 1 || line > len(lines) {
		return ""
	}
	return lines[line-1]
}

func ParseIgnoreComments(content []byte) map[int][]string {
	ignores := make(map[int][]string)
	lines := strings.Split(string(content), "\n")
	pattern := regexp.MustCompile(`#\s*tflint:ignore:([A-Za-z0-9_,]+)`)

	for i, line := range lines {
		matches := pattern.FindStringSubmatch(line)
		if len(matches) > 1 {
			rules := strings.Split(matches[1], ",")
			for j := range rules {
				rules[j] = strings.TrimSpace(rules[j])
			}
			ignores[i+1] = rules
		}
	}
	return ignores
}

func IsDynamicValue(expr interface{}) bool {
	if expr == nil {
		return false
	}
	str := strings.ToLower(expr.(string))
	return strings.Contains(str, "var.") ||
		strings.Contains(str, "local.") ||
		strings.Contains(str, "count.") ||
		strings.Contains(str, "each.") ||
		strings.Contains(str, "?") ||
		strings.Contains(str, "for_each") ||
		strings.Contains(str, "module.") ||
		strings.Contains(str, "${")
}
