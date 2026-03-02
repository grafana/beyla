package ocihook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

type policyEvaluator func(command string, spec *Spec, cfg Config) Decision

type specMutator func(spec *Spec, cfg Config) (MutationResult, error)

type specLoader func(bundleDir string) (*Spec, error)

type specSaver func(bundleDir string, spec *Spec) error

type delegateRunner func(ctx context.Context, runtimePath string, args []string) error

type reportEmitter func(cfg Config, report *DecisionReport) error

type Wrapper struct {
	cfg      Config
	log      *slog.Logger
	loadSpec specLoader
	saveSpec specSaver
	eval     policyEvaluator
	mutate   specMutator
	run      delegateRunner
	report   reportEmitter
	getwd    func() (string, error)
}

type DecisionReport struct {
	Timestamp      time.Time `json:"timestamp"`
	Command        string    `json:"command"`
	Bundle         string    `json:"bundle"`
	Mode           Mode      `json:"mode"`
	DryRun         bool      `json:"dryRun"`
	Delegate       string    `json:"delegateRuntime"`
	PolicyMatched  bool      `json:"policyMatched"`
	PolicyReason   string    `json:"policyReason,omitempty"`
	Mutated        bool      `json:"mutated"`
	MutationReason string    `json:"mutationReason,omitempty"`
	Saved          bool      `json:"saved"`
	Delegated      bool      `json:"delegated"`
	FinalStatus    string    `json:"finalStatus"`
	Error          string    `json:"error,omitempty"`
}

func NewWrapper(cfg Config) *Wrapper {
	if cfg.DelegateRuntime == "" {
		cfg.DelegateRuntime = "runc"
	}
	return &Wrapper{
		cfg:      cfg,
		log:      slog.Default().With("component", "ocihook.wrapper"),
		loadSpec: LoadSpec,
		saveSpec: SaveSpec,
		eval:     EvaluatePolicy,
		mutate:   MutateSpec,
		run:      execDelegate,
		report:   emitDecisionReport,
		getwd:    os.Getwd,
	}
}

func (w *Wrapper) Execute(ctx context.Context, args []string) (execErr error) {
	report := &DecisionReport{
		Timestamp:   time.Now().UTC(),
		Mode:        w.cfg.Mode,
		DryRun:      w.cfg.DryRun,
		Delegate:    w.cfg.DelegateRuntime,
		FinalStatus: "unknown",
	}
	defer func() {
		if execErr != nil {
			report.Error = execErr.Error()
		}
		if err := w.report(w.cfg, report); err != nil {
			w.log.Warn("failed to emit decision report", "error", err)
		}
	}()

	command, bundleDir, err := w.resolveInvocation(args)
	if err != nil {
		execErr = err
		report.FinalStatus = "error"
		return execErr
	}
	report.Command = command
	report.Bundle = bundleDir
	w.log.Debug("resolved invocation", "command", command, "bundle", bundleDir)

	if !slices.Contains(w.cfg.MutateCommands, command) {
		w.log.Debug("skipping mutation for command", "command", command)
		report.PolicyReason = "command is not configured for mutation"
		report.Delegated = true
		report.FinalStatus = "delegated_without_mutation"
		execErr = w.run(ctx, w.cfg.DelegateRuntime, args)
		if execErr != nil {
			report.FinalStatus = "error"
		}
		return execErr
	}

	spec, err := w.loadSpec(bundleDir)
	if err != nil {
		if w.cfg.Mode == ModeStrict {
			execErr = fmt.Errorf("load OCI spec in strict mode: %w", err)
			report.FinalStatus = "error"
			return execErr
		}
		w.log.Warn("unable to load OCI spec, delegating without mutation", "error", err, "mode", w.cfg.Mode)
		report.PolicyReason = "spec load failed in permissive mode"
		report.Delegated = true
		report.FinalStatus = "delegated_without_mutation"
		execErr = w.run(ctx, w.cfg.DelegateRuntime, args)
		if execErr != nil {
			report.FinalStatus = "error"
		}
		return execErr
	}

	decision := w.eval(command, spec, w.cfg)
	report.PolicyMatched = decision.ShouldMutate
	report.PolicyReason = decision.Reason
	w.log.Debug("policy evaluation completed", "shouldMutate", decision.ShouldMutate, "reason", decision.Reason)
	if !decision.ShouldMutate {
		report.Delegated = true
		report.FinalStatus = "delegated_without_mutation"
		execErr = w.run(ctx, w.cfg.DelegateRuntime, args)
		if execErr != nil {
			report.FinalStatus = "error"
		}
		return execErr
	}

	mutation, err := w.mutate(spec, w.cfg)
	if err != nil {
		if w.cfg.Mode == ModeStrict {
			execErr = fmt.Errorf("mutate OCI spec in strict mode: %w", err)
			report.FinalStatus = "error"
			return execErr
		}
		w.log.Warn("unable to mutate OCI spec, delegating without mutation", "error", err, "mode", w.cfg.Mode)
		report.MutationReason = "mutation failed in permissive mode"
		report.Delegated = true
		report.FinalStatus = "delegated_without_mutation"
		execErr = w.run(ctx, w.cfg.DelegateRuntime, args)
		if execErr != nil {
			report.FinalStatus = "error"
		}
		return execErr
	}
	report.Mutated = mutation.Mutated
	report.MutationReason = mutation.Reason
	w.log.Debug("mutation completed", "mutated", mutation.Mutated, "reason", mutation.Reason)

	if mutation.Mutated {
		if w.cfg.DryRun {
			w.log.Info("dry-run enabled, skipping OCI spec write", "bundle", bundleDir)
			report.Saved = false
		} else if err := w.saveSpec(bundleDir, spec); err != nil {
			if w.cfg.Mode == ModeStrict {
				execErr = fmt.Errorf("save OCI spec in strict mode: %w", err)
				report.FinalStatus = "error"
				return execErr
			}
			w.log.Warn("unable to save mutated OCI spec, delegating without mutation", "error", err, "mode", w.cfg.Mode)
			report.MutationReason = "mutation was not persisted due to save failure in permissive mode"
			report.Delegated = true
			report.FinalStatus = "delegated_without_mutation"
			execErr = w.run(ctx, w.cfg.DelegateRuntime, args)
			if execErr != nil {
				report.FinalStatus = "error"
			}
			return execErr
		} else {
			report.Saved = true
		}
	}

	report.Delegated = true
	if mutation.Mutated {
		report.FinalStatus = "delegated_with_mutation"
	} else {
		report.FinalStatus = "delegated_without_mutation"
	}
	execErr = w.run(ctx, w.cfg.DelegateRuntime, args)
	if execErr != nil {
		report.FinalStatus = "error"
	}
	return execErr
}

func (w *Wrapper) resolveInvocation(args []string) (string, string, error) {
	if len(args) == 0 {
		return "", "", fmt.Errorf("missing OCI runtime command")
	}

	command := strings.TrimSpace(args[0])
	if command == "" {
		return "", "", fmt.Errorf("empty OCI runtime command")
	}

	bundleDir, err := parseBundleArg(args[1:])
	if err != nil {
		return "", "", err
	}
	if bundleDir == "" {
		bundleDir, err = w.getwd()
		if err != nil {
			return "", "", fmt.Errorf("resolve default bundle directory: %w", err)
		}
	}

	return command, filepath.Clean(bundleDir), nil
}

func parseBundleArg(args []string) (string, error) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--bundle" || arg == "-b":
			if i+1 >= len(args) {
				return "", fmt.Errorf("missing value for %s", arg)
			}
			return args[i+1], nil
		case strings.HasPrefix(arg, "--bundle="):
			return strings.TrimPrefix(arg, "--bundle="), nil
		case strings.HasPrefix(arg, "-b="):
			return strings.TrimPrefix(arg, "-b="), nil
		}
	}

	return "", nil
}

func execDelegate(ctx context.Context, runtimePath string, args []string) error {
	cmd := exec.CommandContext(ctx, runtimePath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return fmt.Errorf("delegate runtime %q exited with status %d: %w", runtimePath, exitErr.ExitCode(), err)
		}
		return fmt.Errorf("delegate runtime %q failed: %w", runtimePath, err)
	}

	return nil
}

func emitDecisionReport(cfg Config, report *DecisionReport) error {
	target := strings.ToLower(strings.TrimSpace(cfg.DecisionReport))
	if target == "" || target == "none" {
		return nil
	}

	var out io.Writer
	switch target {
	case "stdout":
		out = os.Stdout
	case "stderr":
		out = os.Stderr
	default:
		return fmt.Errorf("unsupported decision report target %q", target)
	}

	return json.NewEncoder(out).Encode(report)
}
