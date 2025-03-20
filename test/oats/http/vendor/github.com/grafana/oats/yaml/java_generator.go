package yaml

import (
	"fmt"
	"github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func (c *TestCase) applicationJar() string {
	t := time.Now()
	build := os.Getenv("TESTCASE_SKIP_BUILD") != "true"
	if build {
		ginkgo.GinkgoWriter.Printf("building application jar in %s\n", c.Dir)
		// create a new app.jar - only needed for local testing - maybe add an option to skip this in CI
		cmd := exec.Command(filepath.FromSlash("../../../gradlew"), "clean", "build")
		cmd.Dir = c.Dir
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stdout

		err := cmd.Run()
		Expect(err).ToNot(HaveOccurred(), "could not build application jar")
	}

	pattern := c.Dir + filepath.FromSlash("/build/libs/*SNAPSHOT.jar")
	matches, err := filepath.Glob(pattern)
	Expect(err).ToNot(HaveOccurred(), "could not find application jar")
	Expect(matches).To(HaveLen(1))

	file := matches[0]

	if build {
		fileinfo, err := os.Stat(file)
		Expect(err).ToNot(HaveOccurred())
		Expect(fileinfo.ModTime()).To(BeTemporally(">=", t), "application jar was not built")
	}

	return file
}

func imageName(dir string) string {
	content, err := os.ReadFile(filepath.Join(dir, ".tool-versions"))
	Expect(err).ToNot(HaveOccurred(), "could not read .tool-versions")
	for _, line := range strings.Split(string(content), "\n") {
		if strings.HasPrefix(line, "java ") {
			// find major version in java temurin-8.0.372+7 using regex
			major := regexp.MustCompile("java temurin-(\\d+).*").FindStringSubmatch(line)[1]
			return fmt.Sprintf("eclipse-temurin:%s-jre", major)
		}
	}
	ginkgo.Fail("no java version found")
	return ""
}

func (c *TestCase) javaTemplateVars() (string, map[string]any) {
	projectDir := strings.Split(c.Dir, filepath.FromSlash("examples/"))[0]
	agent := filepath.Join(projectDir, filepath.FromSlash("agent/build/libs/grafana-opentelemetry-java.jar"))

	_, err := os.Stat(agent)
	if err != nil {
		buildAgent(projectDir)
	}

	image := imageName(c.Dir)
	params := c.Definition.DockerCompose.JavaGeneratorParams
	return filepath.FromSlash("./docker-compose-java-template.yml"), map[string]any{
		"Image":                  image,
		"JavaAgent":              filepath.ToSlash(agent),
		"ApplicationJar":         filepath.ToSlash(c.applicationJar()),
		"JmxConfig":              jmxConfig(c.Dir, params.OtelJmxConfig),
		"OldJvmMetrics":          params.OldJvmMetrics,
		"PromNaming":             params.PromNaming,
		"DisableDataSaver":       params.DisableDataSaver,
		"JvmDebug":               jvmDebug(image),
		"UseAllInstrumentations": os.Getenv("TESTCASE_INCLUDE_ALL_INSTRUMENTATIONS") == "true",
	}
}

func jvmDebug(image string) string {
	if os.Getenv("TESTCASE_JVM_DEBUG") != "true" {
		return ""
	}
	port := ""
	if image == "eclipse-temurin:8-jre" {
		port = "5005"
	} else {
		port = "*:5005"
	}
	ginkgo.GinkgoWriter.Printf("jvm debug port: %s\n", port)
	return fmt.Sprintf("-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=%s", port)
}

func buildAgent(projectDir string) {
	ginkgo.GinkgoWriter.Printf("building javaagent in %s\n", projectDir)
	cmd := exec.Command(filepath.FromSlash("./gradlew"), "clean", "build")
	cmd.Dir = projectDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stdout

	err := cmd.Run()
	Expect(err).ToNot(HaveOccurred(), "could not build javaagent jar")
}

func jmxConfig(dir string, jmxConfig string) string {
	if jmxConfig == "" {
		return ""
	}
	p := filepath.Join(dir, jmxConfig)
	Expect(p).To(BeAnExistingFile(), "jmx config file does not exist")
	return filepath.ToSlash(p)
}
