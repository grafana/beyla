package yaml

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/grafana/dashboard-linter/lint"
	. "github.com/onsi/gomega"
	"gopkg.in/yaml.v3"
)

// relative to docker-compose.yml
var generatedDashboard = filepath.FromSlash("./dashboard.json")

func (c *TestCase) CreateDockerComposeFile() string {
	p := filepath.Join(c.OutputDir, "docker-compose.yml")
	content := c.getContent(c.Definition.DockerCompose)
	err := os.WriteFile(p, content, 0644)
	Expect(err).ToNot(HaveOccurred())
	return p
}

func (c *TestCase) getContent(compose *DockerCompose) []byte {
	if compose.Generator != "" {
		return c.generateDockerComposeFile()
	} else {
		// TODO: allow for template vars on docker-compose files, similar to generator
		var buf []byte
		for _, filename := range compose.Files {
			var err error
			buf, err = joinComposeFiles(buf, readComposeFile(compose, filename))
			Expect(err).ToNot(HaveOccurred())
		}
		return buf
	}
}

func readComposeFile(compose *DockerCompose, file string) []byte {
	b, err := os.ReadFile(file)
	Expect(err).ToNot(HaveOccurred())
	return replaceRefs(compose, b)
}

func replaceRefs(compose *DockerCompose, bytes []byte) []byte {
	baseDir := filepath.Dir(compose.Files[0]) // TODO: more direct way of getting baseDir?
	lines := strings.Split(string(bytes), "\n")
	for i, line := range lines {
		for _, resource := range compose.Resources {
			lines[i] = strings.ReplaceAll(line, "./"+resource, filepath.Join(baseDir, resource))
		}
	}
	return []byte(strings.Join(lines, "\n"))
}

func (c *TestCase) generateDockerComposeFile() []byte {
	dashboard := ""
	if c.Dashboard != nil {
		dashboard = c.readDashboardFile()
	} else {
		configDir, err := filepath.Abs("configs")
		Expect(err).ToNot(HaveOccurred())
		dashboard = filepath.Join(configDir, "grafana-test-dashboard.json")
	}
	configDir, err := filepath.Abs("configs")
	Expect(err).ToNot(HaveOccurred())

	name, vars := c.getTemplateVars()
	vars["Dashboard"] = filepath.ToSlash(dashboard)
	vars["ConfigDir"] = filepath.ToSlash(configDir)
	vars["ApplicationPort"] = c.PortConfig.ApplicationPort
	vars["GrafanaHTTPPort"] = c.PortConfig.GrafanaHTTPPort
	vars["PrometheusHTTPPort"] = c.PortConfig.PrometheusHTTPPort
	vars["LokiHTTPPort"] = c.PortConfig.LokiHTTPPort
	vars["TempoHTTPPort"] = c.PortConfig.TempoHTTPPort

	env := os.Environ()

	for k, v := range vars {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}

	for _, v := range c.Definition.DockerCompose.Environment {
		env = append(env, v)
	}

	t := template.Must(template.ParseFiles(name))

	buf := bytes.NewBufferString("")
	err = t.Execute(buf, vars)
	Expect(err).ToNot(HaveOccurred())
	generated, err := filepath.Abs(strings.TrimSuffix(name, filepath.Ext(name)) + "-generated.yml")
	os.WriteFile(generated, buf.Bytes(), 0644)
	defer os.Remove(generated)
	compose := c.Definition.DockerCompose
	files := []string{generated}
	for _, filename := range compose.Files {
		t = template.Must(template.ParseFiles(filename))
		addbuf := bytes.NewBufferString("")
		err = t.Execute(addbuf, vars)
		Expect(err).ToNot(HaveOccurred())
		name := strings.TrimSuffix(filename, filepath.Ext(filename)) + "-generated.yml"
		err = os.WriteFile(name, addbuf.Bytes(), 0644)
		Expect(err).ToNot(HaveOccurred())
		defer os.Remove(name)
		files = append(files, name)
	}

	base := filepath.FromSlash("./docker-compose-include-base.yml")
	t = template.Must(template.ParseFiles(base))
	buf = bytes.NewBufferString("")
	vars = map[string]any{}
	vars["files"] = files
	err = t.Execute(buf, vars)
	Expect(err).ToNot(HaveOccurred())
	f, err := os.CreateTemp("", "docker-compose-base.yml")
	Expect(err).ToNot(HaveOccurred())
	_, err = f.Write(buf.Bytes())
	Expect(err).ToNot(HaveOccurred())
	defer os.Remove(f.Name())

	// uses docker compose to merge templates
	args := []string{"compose", "-f", f.Name(), "config"}
	cmd := exec.Command("docker", args...)
	cmd.Env = env
	content, err := cmd.Output()
	Expect(err).ToNot(HaveOccurred())
	return content
}

func (c *TestCase) getTemplateVars() (string, map[string]any) {
	generator := c.Definition.DockerCompose.Generator
	switch generator {
	case "java":
		return c.javaTemplateVars()
	default:
		return filepath.FromSlash("./docker-compose-" + generator + "-template.yml"), map[string]any{}
	}
}

func joinComposeFiles(template []byte, addition []byte) ([]byte, error) {
	base := map[string]any{}
	add := map[string]any{}

	err := yaml.Unmarshal(template, &base)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(addition, &add)
	if err != nil {
		return nil, err
	}

	//not a generic solution, but works for our use case
	addFromBase(base, add, "services")
	addFromBase(base, add, "networks")

	return yaml.Marshal(add)
}

func addFromBase(base map[string]any, add map[string]any, key string) {
	addMap, ok := add[key].(map[string]any)
	if !ok {
		addMap = map[string]any{}
		add[key] = addMap
	}

	baseMap, ok := base[key].(map[string]any)
	if ok {
		for k, v := range baseMap {
			addMap[k] = v
		}
	}
}

func (c *TestCase) readDashboardFile() string {
	content, err := os.ReadFile(c.Dashboard.Path)
	Expect(err).ToNot(HaveOccurred())

	c.Dashboard.Content = c.parseDashboard(content)
	return c.replaceDatasource(content, err)
}

func (c *TestCase) parseDashboard(content []byte) lint.Dashboard {
	d := lint.Dashboard{}
	err := json.Unmarshal(content, &d)
	Expect(err).ToNot(HaveOccurred())
	return d
}

func (c *TestCase) replaceDatasource(content []byte, err error) string {
	newFile := filepath.Join(c.OutputDir, generatedDashboard)
	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		lines[i] = strings.ReplaceAll(line, "${DS_GRAFANACLOUD-GREGORZEITLINGER-PROM}", "prometheus")
	}
	err = os.WriteFile(newFile, []byte(strings.Join(lines, "\n")), 0644)
	Expect(err).ToNot(HaveOccurred())
	abs, err := filepath.Abs(newFile)
	Expect(err).ToNot(HaveOccurred())
	return abs
}
