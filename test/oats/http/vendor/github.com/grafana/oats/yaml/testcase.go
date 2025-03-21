package yaml

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

var oatsFileRegex = regexp.MustCompile("oats.*\\.yaml")

func ReadTestCases() ([]*TestCase, string) {
	var cases []*TestCase

	base := TestCaseBashPath()
	if base != "" {
		base = absolutePath(base)
		timeout := os.Getenv("TESTCASE_TIMEOUT")
		if timeout == "" {
			timeout = "30s"
		}
		duration, err := time.ParseDuration(timeout)
		if err != nil {
			panic(err)
		}

		err = filepath.WalkDir(base, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !oatsFileRegex.MatchString(d.Name()) || strings.Contains(d.Name(), "-template.yaml") {
				return nil
			}
			testCase, err := readTestCase(base, p, duration)
			if err != nil {
				return err
			}
			if testCase.Definition.Matrix != nil {
				for _, matrix := range testCase.Definition.Matrix {
					newCase := testCase
					newCase.Definition = testCase.Definition
					newCase.Definition.DockerCompose = matrix.DockerCompose
					newCase.Name = fmt.Sprintf("%s-%s", testCase.Name, matrix.Name)
					newCase.MatrixTestCaseName = matrix.Name
					cases = append(cases, &newCase)
				}
				return nil
			}
			cases = append(cases, &testCase)
			return nil
		})
		if err != nil {
			panic(err)
		}
	}

	return cases, base
}

func absolutePath(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		panic(err)
	}
	return abs
}

func readTestCase(testBase, filePath string, duration time.Duration) (TestCase, error) {
	def, err := readTestCaseDefinition(filePath)
	if err != nil {
		return TestCase{}, err
	}

	dir := filepath.Dir(absolutePath(filePath))
	name := strings.TrimPrefix(dir, absolutePath(testBase)) + "-" + strings.TrimSuffix(filepath.Base(filePath), filepath.Ext(filePath))
	sep := string(filepath.Separator)
	name = strings.TrimPrefix(name, sep)
	name = strings.ReplaceAll(name, sep, "-")
	name = "run" + name
	testCase := TestCase{
		Name:       name,
		Dir:        dir,
		Definition: def,
		Timeout:    duration,
	}
	return testCase, nil
}

func readTestCaseDefinition(filePath string) (TestCaseDefinition, error) {
	filePath = absolutePath(filePath)
	def := TestCaseDefinition{}
	content, err := os.ReadFile(filePath)
	if err != nil {
		return TestCaseDefinition{}, err
	}

	err = yaml.Unmarshal(content, &def)
	if err != nil {
		return TestCaseDefinition{}, err
	}

	for _, s := range def.Include {
		p := includePath(filePath, s)
		other, err := readTestCaseDefinition(p)
		if err != nil {
			return TestCaseDefinition{}, err
		}
		def.Merge(other)
	}
	def.Include = []string{}

	return def, nil
}

func includePath(filePath string, include string) string {
	dir := filepath.Dir(filePath)
	fromSlash := filepath.FromSlash(include)
	return filepath.Join(dir, fromSlash)
}

func TestCaseBashPath() string {
	return os.Getenv("TESTCASE_BASE_PATH")
}

func AssumeNoYamlTest(t *testing.T) {
	if TestCaseBashPath() != "" {
		t.Skip("skipping because we run yaml tests")
	}
}
