package ocihook

import "path/filepath"

const (
	defaultInjectAnnotation = "beyla.grafana.com/inject"
	defaultInjectEnvVar     = "BEYLA_INJECT"
	defaultInternalMountDir = "/__otel_sdk_auto_instrumentation__"
)

type Mode string

const (
	ModePermissive Mode = "permissive"
	ModeStrict     Mode = "strict"
)

type ExistingLDPreloadAction string

const (
	LDPreloadSkip ExistingLDPreloadAction = "skip"
	LDPreloadFail ExistingLDPreloadAction = "fail"
)

type Language string

const (
	LanguageDotnet Language = "dotnet"
	LanguageJava   Language = "java"
	LanguageNodeJS Language = "nodejs"
	LanguagePython Language = "python"
)

type SelectionPolicy struct {
	// OptInAnnotation is checked first.
	// If it is present and truthy, the container is selected for mutation.
	OptInAnnotation string
	// OptInEnvVar is a fallback selector for plain Docker scenarios where
	// annotations are harder to control than process env values.
	// Example in OCI spec process.env: BEYLA_INJECT=true
	OptInEnvVar string
}

type Config struct {
	Mode                   Mode
	LogLevel               string
	DecisionReport         string
	Policy                 SelectionPolicy
	MutateCommands         []string
	ExistingLDPreload      ExistingLDPreloadAction
	OverrideOTEL           bool
	DryRun                 bool
	SDKPackageVersion      string
	HostInstrumentationDir string
	InternalMountDir       string
	DelegateRuntime        string
	OTLPEndpoint           string
	OTLPProtocol           string
	EnabledSDKs            []Language
}

func DefaultConfig() Config {
	return Config{
		Mode:              ModePermissive,
		LogLevel:          "info",
		DecisionReport:    "none",
		Policy:            SelectionPolicy{OptInAnnotation: defaultInjectAnnotation, OptInEnvVar: defaultInjectEnvVar},
		MutateCommands:    []string{"create"},
		ExistingLDPreload: LDPreloadSkip,
		OverrideOTEL:      false,
		DryRun:            false,
		InternalMountDir:  defaultInternalMountDir,
		DelegateRuntime:   "runc",
		EnabledSDKs:       []Language{LanguageJava, LanguageDotnet, LanguageNodeJS, LanguagePython},
	}
}

func (c Config) InjectSourceDir() string {
	return filepath.Join(c.HostInstrumentationDir, c.SDKPackageVersion)
}
