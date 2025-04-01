//go:generate go run beyla_genfiles.go

package main

import (
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/caarlos0/env/v9"
)

const envModuleRoot = "BEYLA_GENFILES_MODULE_ROOT"

type config struct {
	DebugEnabled    bool   `env:"BEYLA_GENFILES_DEBUG"            envDefault:"false"`
	RunLocally      bool   `env:"BEYLA_GENFILES_RUN_LOCALLY"      envDefault:"false"`
	ScanPath        string `env:"BEYLA_GENFILES_SCAN_PATH"        envDefault:"pkg"`
	ContainerPrefix string `env:"BEYLA_GENFILES_CONTAINER_PREFIX" envDefault:"/__w/"`
	HostPrefix      string `env:"BEYLA_GENFILES_HOST_PREFIX"      envDefault:"/home/runner/work/"`
	Package         string `env:"BEYLA_GENFILES_PKG"              envDefault:"github.com/grafana/beyla/v2/pkg/beyla"`
	OCIBin          string `env:"BEYLA_GENFILES_OCI_BIN"          envDefault:"docker"`
	GenImage        string `env:"BEYLA_GENFILES_GEN_IMG"          envDefault:"ghcr.io/grafana/beyla-ebpf-generator:main"`
}

var cfg config

type fileSet map[string]struct{}

func (f fileSet) toArray() []string {
	ret := make([]string, 0, len(f))

	for k := range f {
		ret = append(ret, k)
	}

	return ret
}

func mustGenerate(comment string) bool {
	// we only care about files containing //go-generate
	if !strings.HasPrefix(comment, "//go:generate") {
		return false
	}

	// if not a bpf2go generation, we always regenerate the file
	if !strings.Contains(comment, "$BPF2GO") {
		return true
	}

	// only regenerate bpf2go statements on Linux
	if runtime.GOOS != "linux" {
		return false
	}

	// on linux, we always regenerate the file
	return true
}

func handleDirEntry(path string, d fs.DirEntry, err error, filesToGenerate fileSet) error {
	if err != nil {
		return err
	}

	if !strings.HasSuffix(d.Name(), ".go") {
		return nil
	}

	file, err := os.Open(path)

	if err != nil {
		return err
	}

	defer file.Close()

	fs := token.NewFileSet()

	node, err := parser.ParseFile(fs, path, file, parser.ParseComments)

	if err != nil {
		return err
	}

	for _, commentGroup := range node.Comments {
		for _, comment := range commentGroup.List {
			if mustGenerate(comment.Text) {
				filesToGenerate[path] = struct{}{}
			}
		}
	}

	return nil
}

func gatherFilesToGenerate(moduleRoot string) ([]string, error) {
	rootDir := filepath.Join(moduleRoot, cfg.ScanPath)

	filesToGenerate := fileSet{}

	// Walk through the project directory
	err := filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, err error) error {
		return handleDirEntry(path, d, err, filesToGenerate)
	})

	if err != nil {
		return nil, fmt.Errorf("error walking through the directory: %w", err)
	}

	return filesToGenerate.toArray(), nil
}

func getPipes(cmd *exec.Cmd) (io.ReadCloser, io.ReadCloser, error) {
	stdout, err := cmd.StdoutPipe()

	if err != nil {
		return nil, nil, fmt.Errorf("error getting stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()

	if err != nil {
		stdout.Close()
		return nil, nil, fmt.Errorf("error getting stderr pipe: %w", err)
	}

	return stdout, stderr, nil
}

// when a GH action job is executed inside a container, the host workspace in
// the host gets mounted in the '/__w'  target directory. However, because the
// beyla-ebpf-generator image runs as a sibling container (it shares the same
// docker socket), we need to pass the host path to the '/src' volume rather
// than the detected container path
func adjustPathForGitHubActions(path string) string {
	_, isGithubWorkflow := os.LookupEnv("GITHUB_WORKSPACE")

	if isGithubWorkflow && strings.HasPrefix(path, cfg.ContainerPrefix) {
		return strings.Replace(path, cfg.ContainerPrefix, cfg.HostPrefix, 1)
	}

	return path
}

func beylaPackageDir() (string, error) {
	cmd := exec.Command("go", "list", "-f", "'{{.Dir}}'", cfg.Package)
	out, err := cmd.Output()

	if err != nil {
		return "", fmt.Errorf("cannot resolve beyla package dir: %w", err)
	}

	ret := strings.Trim(string(out), "'\n")

	return ret, nil
}

func moduleRoot() (string, error) {
	wd := os.Getenv(envModuleRoot)

	if wd != "" {
		info, err := os.Stat(wd)

		if err != nil {
			return "", err
		}

		if !info.IsDir() {
			return "", fmt.Errorf("specified module root '%s' is not a dir", wd)
		}

		return wd, nil
	}

	wd, err := beylaPackageDir()

	if err != nil {
		return "", err
	}

	for {
		if _, err := os.Stat(filepath.Join(wd, "LICENSE")); err == nil {
			// Found LICENSE, we are at the module root
			break
		}
		wd = filepath.Dir(wd)
		if wd == "/" || wd == "." {
			return "", fmt.Errorf("could not find module root")
		}
	}

	absPath, err := filepath.Abs(wd)

	if err != nil {
		return "", fmt.Errorf("error resolving absolute path: %w", err)
	}

	return absPath, nil
}

func ensureWritableImpl(path string, info os.FileInfo) error {
	mode := info.Mode()

	if mode&0200 != 0 {
		return nil
	}

	mode |= 0200

	return os.Chmod(path, mode)
}

func ensureWritable(path string) error {
	info, err := os.Stat(path)

	if err != nil {
		return fmt.Errorf("error stating file '%s': %w", path, err)
	}

	return ensureWritableImpl(path, info)
}

func ensureDirWritable(path string) error {
	info, err := os.Stat(path)

	if err != nil {
		return fmt.Errorf("error stating file '%s': %w", path, err)
	}

	if info.IsDir() {
		return ensureWritableImpl(path, info)
	}

	return ensureWritable(filepath.Dir(path))
}

func ensureDirsWritable(files []string) error {
	for _, f := range files {
		if err := ensureDirWritable(f); err != nil {
			return err
		}
	}

	return nil
}

func isModuleVendored(wd string) bool {
	return strings.Contains(wd, "/vendor/")
}

func cleanBuildCache() error {
	cmd := exec.Command("go", "clean", "-cache")

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to clean build cache: %w", err)
	}

	return nil
}

func bail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func runInContainer(wd string) {
	adjustedWD := adjustPathForGitHubActions(wd)

	if cfg.DebugEnabled {
		fmt.Println("wd:", wd)
		fmt.Println("adjusted wd:", adjustedWD)
	}

	currentUser, err := user.Current()

	if err != nil {
		bail(fmt.Errorf("error getting current user id: %w", err))
	}

	err = executeCommand(cfg.OCIBin, "run", "--rm",
		"--user", currentUser.Uid+":"+currentUser.Gid,
		"-v", adjustedWD+":/src",
		cfg.GenImage)

	if err != nil {
		bail(fmt.Errorf("error waiting for child process: %w", err))
	}
}

func executeCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)

	if cfg.DebugEnabled {
		fmt.Println("cmd:", cmd.String())
	}

	stdoutPipe, stderrPipe, err := getPipes(cmd)

	if err != nil {
		return err
	}

	defer stdoutPipe.Close()
	defer stderrPipe.Close()

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start program: %w", err)
	}

	go io.Copy(os.Stdout, stdoutPipe) //nolint:errcheck
	go io.Copy(os.Stderr, stderrPipe) //nolint:errcheck

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("error waiting for child process: %w", err)
	}

	return nil
}

func genFiles(files []string) error {
	var wg sync.WaitGroup
	var mu sync.Mutex

	wg.Add(len(files))

	var errors []error

	for _, file := range files {
		go func() {
			err := executeCommand("go", "generate", file)

			if err != nil {
				mu.Lock()
				errors = append(errors, fmt.Errorf("%s: %w", file, err))
				mu.Unlock()
			}

			wg.Done()
		}()
	}

	wg.Wait()

	if len(errors) > 0 {
		fmt.Fprintln(os.Stderr, "The following errors have occurred:")

		for _, err := range errors {
			fmt.Fprintln(os.Stderr, err)
		}

		return fmt.Errorf("failed to generate files")
	}

	return nil
}

func runLocally(wd string) {
	files, err := gatherFilesToGenerate(wd)

	if err != nil {
		bail(err)
	}

	if len(files) == 0 {
		os.Exit(0)
	}

	if err = ensureDirsWritable(files); err != nil {
		bail(err)
	}

	if err = genFiles(files); err != nil {
		bail(err)
	}

	if !isModuleVendored(wd) {
		if err := cleanBuildCache(); err != nil {
			bail(err)
		}
	}
}

func main() {
	if err := env.Parse(&cfg); err != nil {
		bail(fmt.Errorf("error loading config: %w", err))
	}

	wd, err := moduleRoot()

	if err != nil {
		bail(err)
	}

	if err = ensureWritable(wd); err != nil {
		bail(err)
	}

	if cfg.RunLocally {
		runLocally(wd)
	} else {
		runInContainer(wd)
	}
}
