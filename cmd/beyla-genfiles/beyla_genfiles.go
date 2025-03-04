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
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/caarlos0/env/v9"
)

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

var targetsByGoArch = map[string]Target{
	"386":      {"bpfel", "x86"},
	"amd64":    {"bpfel", "x86"},
	"arm":      {"bpfel", "arm"},
	"arm64":    {"bpfel", "arm64"},
	"loong64":  {"bpfel", "loongarch"},
	"mips":     {"bpfeb", "mips"},
	"mipsle":   {"bpfel", ""},
	"mips64":   {"bpfeb", ""},
	"mips64le": {"bpfel", ""},
	"ppc64":    {"bpfeb", "powerpc"},
	"ppc64le":  {"bpfel", "powerpc"},
	"riscv64":  {"bpfel", "riscv"},
	"s390x":    {"bpfeb", "s390"},
}

type Target struct {
	clang string
	linux string
}

func (tgt *Target) Suffix() string {
	stem := tgt.clang

	if tgt.linux != "" {
		stem = fmt.Sprintf("%s_%s", tgt.linux, tgt.clang)
	}

	return stem
}

type argParser struct {
	cmdLine string
	index   int
}

func newargParser(cmdLine string) *argParser {
	return &argParser{
		cmdLine: cmdLine,
		index:   0,
	}
}

func (ap *argParser) shift() (string, bool) {
	for ap.index < len(ap.cmdLine) && unicode.IsSpace(rune(ap.cmdLine[ap.index])) {
		ap.index++
	}

	// If we've reached the end of the string, return false
	if ap.index >= len(ap.cmdLine) {
		return "", false
	}

	start := ap.index

	for ap.index < len(ap.cmdLine) && !unicode.IsSpace(rune(ap.cmdLine[ap.index])) {
		ap.index++
	}

	// Return the word
	return ap.cmdLine[start:ap.index], true
}

type bpf2goGenContext struct {
	goArchs []string
	stem    string // the ident stem passed to bpf2go
	outDir  string // the output directory passed to bpf2go
	srcFile string // the .c source file passed to bpf2go
	srcDir  string // the source directory of the .go file containing the generate directive
	goFile  string // the go file containing the generate directive
}

//nolint:cyclop
func parseBPF2GOGenLine(goFile string, line string) *bpf2goGenContext {
	ctx := &bpf2goGenContext{
		goArchs: []string{"bpfel", "bpfeb"}, // the defaults according to bpf2go
		goFile:  goFile,
		srcDir:  filepath.Dir(goFile),
	}

	parser := newargParser(line)

	// yank //go-generate
	parser.shift()

	// yank $BPF2GO
	parser.shift()

	for {
		arg, ok := parser.shift()

		if !ok {
			break
		}

		//nolint:gocritic
		if arg == "-target" {
			if arg, ok = parser.shift(); ok {
				ctx.goArchs = strings.Split(arg, ",")
			}
		} else if arg == "-output-stem" {
			if arg, ok = parser.shift(); ok {
				ctx.stem = strings.ToLower(arg)
			}
		} else if arg == "-output-dir" {
			if arg, ok = parser.shift(); ok {
				ctx.outDir = arg
			}
		} else if arg == "--" {
			break
		} else if arg[0] == '-' {
			parser.shift()
		} else if ctx.stem == "" {
			ctx.stem = strings.ToLower(arg)
		} else if ctx.srcFile == "" {
			ctx.srcFile = filepath.Join(ctx.srcDir, arg)
		}
	}

	if ctx.outDir == "" {
		ctx.outDir = ctx.srcDir
	}

	return ctx
}

func isFileStale(ts time.Time, file string) bool {
	info, err := os.Stat(file)

	if err != nil {
		return true
	}

	return ts.After(info.ModTime())
}

func bpf2goFileNeedsGenerate(ctx *bpf2goGenContext) (bool, error) {
	info, err := os.Stat(ctx.srcFile)

	if err != nil {
		return false, fmt.Errorf("cannot stat source file '%s': %w", ctx.srcFile, err)
	}

	ts := info.ModTime()

	for _, goArch := range ctx.goArchs {
		target, ok := targetsByGoArch[goArch]

		if !ok {
			continue
		}

		baseName := fmt.Sprintf("%s_%s", ctx.stem, target.Suffix())
		filePath := filepath.Join(ctx.outDir, baseName)

		if isFileStale(ts, filePath+".o") || isFileStale(ts, filePath+".go") {
			return true, nil
		}
	}

	return false, nil
}

type fileSet map[string]struct{}

func (f fileSet) toArray() []string {
	ret := make([]string, 0, len(f))

	for k := range f {
		ret = append(ret, k)
	}

	return ret
}

func mustGenerate(path string, comment string) (bool, error) {
	// we only care about files containing //go-generate
	if !strings.HasPrefix(comment, "//go:generate") {
		return false, nil
	}

	// if not a bpf2go generation, we always regenerate the file
	if !strings.Contains(comment, "$BPF2GO") {
		return true, nil
	}

	// only regenerate bpf2go statements on Linux
	if runtime.GOOS != "linux" {
		return false, nil
	}

	// bpf2go generation is a special case - we don't want to
	// regenerate files that haven't changed, so we need to resolve
	// the source .c file and the bpf2go artifacts (.o and .go files)
	// to work out whether they need to be regenerated
	return bpf2goFileNeedsGenerate(parseBPF2GOGenLine(path, comment))
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
			generate, err := mustGenerate(path, comment.Text)

			if err != nil {
				return err
			}

			if generate {
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

	return wd, nil
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

	err := executeCommand(cfg.OCIBin, "run", "--rm",
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
