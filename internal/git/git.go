package git

import (
	"os/exec"
	"strings"
)

func GetChangedFiles(dir string) ([]string, error) {
	files, err := getGitDiffFiles(dir)
	if err != nil {
		return nil, err
	}

	var tfFiles []string
	for _, file := range files {
		if strings.HasSuffix(file, ".tf") || strings.HasSuffix(file, ".tfvars") {
			tfFiles = append(tfFiles, file)
		}
	}

	return tfFiles, nil
}

func getGitDiffFiles(dir string) ([]string, error) {
	cmd := exec.Command("git", "diff", "--name-only", "--diff-filter=ACM")
	cmd.Dir = dir
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var files []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			files = append(files, line)
		}
	}

	return files, nil
}

func GetStagedFiles(dir string) ([]string, error) {
	cmd := exec.Command("git", "diff", "--name-only", "--cached", "--diff-filter=ACM")
	cmd.Dir = dir
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var files []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			files = append(files, line)
		}
	}

	var tfFiles []string
	for _, file := range files {
		if strings.HasSuffix(file, ".tf") || strings.HasSuffix(file, ".tfvars") {
			tfFiles = append(tfFiles, file)
		}
	}

	return tfFiles, nil
}

func IsGitRepository(dir string) bool {
	cmd := exec.Command("git", "rev-parse", "--is-inside-work-tree")
	cmd.Dir = dir
	err := cmd.Run()
	return err == nil
}
