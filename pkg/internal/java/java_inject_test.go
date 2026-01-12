// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package javaagent

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/ebpf"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestJavaInjector_CopyAgent(t *testing.T) {
	tests := []struct {
		name          string
		setupAgent    func(t *testing.T) string
		setupTempDir  func(t *testing.T, pid int32) string
		envVars       map[string]string
		pid           int32
		expectError   bool
		errorContains string
		verifyFile    bool
	}{
		{
			name: "successful copy to /tmp",
			setupAgent: func(t *testing.T) string {
				tmpFile := filepath.Join(t.TempDir(), ObiJavaAgentFileName)
				require.NoError(t, os.WriteFile(tmpFile, []byte("test agent content"), 0o644))
				return tmpFile
			},
			setupTempDir: func(t *testing.T, _ int32) string {
				tmpDir := t.TempDir()
				procRoot := filepath.Join(tmpDir, "proc", "root")
				require.NoError(t, os.MkdirAll(filepath.Join(procRoot, "tmp"), 0o755))
				return tmpDir
			},
			envVars:     map[string]string{},
			pid:         1000,
			expectError: false,
			verifyFile:  true,
		},
		{
			name: "successful copy to TMPDIR from env",
			setupAgent: func(t *testing.T) string {
				tmpFile := filepath.Join(t.TempDir(), ObiJavaAgentFileName)
				require.NoError(t, os.WriteFile(tmpFile, []byte("test agent content"), 0o644))
				return tmpFile
			},
			setupTempDir: func(t *testing.T, _ int32) string {
				tmpDir := t.TempDir()
				procRoot := filepath.Join(tmpDir, "proc", "root")
				customTmpDir := filepath.Join(procRoot, "custom", "tmp")
				require.NoError(t, os.MkdirAll(customTmpDir, 0o755))
				return tmpDir
			},
			envVars: map[string]string{
				"TMPDIR": "/custom/tmp",
			},
			pid:         1000,
			expectError: false,
			verifyFile:  true,
		},
		{
			name: "fallback to /var/tmp when /tmp not available",
			setupAgent: func(t *testing.T) string {
				tmpFile := filepath.Join(t.TempDir(), ObiJavaAgentFileName)
				require.NoError(t, os.WriteFile(tmpFile, []byte("test agent content"), 0o644))
				return tmpFile
			},
			setupTempDir: func(t *testing.T, _ int32) string {
				tmpDir := t.TempDir()
				procRoot := filepath.Join(tmpDir, "proc", "root")
				require.NoError(t, os.MkdirAll(filepath.Join(procRoot, "var", "tmp"), 0o755))
				return tmpDir
			},
			envVars:     map[string]string{},
			pid:         1000,
			expectError: false,
			verifyFile:  true,
		},
		{
			name: "error when no temp directory available",
			setupAgent: func(t *testing.T) string {
				tmpFile := filepath.Join(t.TempDir(), ObiJavaAgentFileName)
				require.NoError(t, os.WriteFile(tmpFile, []byte("test agent content"), 0o644))
				return tmpFile
			},
			setupTempDir: func(t *testing.T, _ int32) string {
				tmpDir := t.TempDir()
				procRoot := filepath.Join(tmpDir, "proc", "root")
				require.NoError(t, os.MkdirAll(procRoot, 0o755))
				return tmpDir
			},
			envVars:       map[string]string{},
			pid:           1000,
			expectError:   true,
			errorContains: "error accessing temp directory",
			verifyFile:    false,
		},
		{
			name: "error when agent file not accessible",
			setupAgent: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "nonexistent", ObiJavaAgentFileName)
			},
			setupTempDir: func(t *testing.T, _ int32) string {
				tmpDir := t.TempDir()
				procRoot := filepath.Join(tmpDir, "proc", "root")
				require.NoError(t, os.MkdirAll(filepath.Join(procRoot, "tmp"), 0o755))
				return tmpDir
			},
			envVars:       map[string]string{},
			pid:           1000,
			expectError:   true,
			errorContains: "unable to access OBI java agent",
			verifyFile:    false,
		},
		{
			name: "error when target directory not writable",
			setupAgent: func(t *testing.T) string {
				tmpFile := filepath.Join(t.TempDir(), ObiJavaAgentFileName)
				require.NoError(t, os.WriteFile(tmpFile, []byte("test agent content"), 0o644))
				return tmpFile
			},
			setupTempDir: func(t *testing.T, _ int32) string {
				tmpDir := t.TempDir()
				procRoot := filepath.Join(tmpDir, "proc", "root")
				tmpPath := filepath.Join(procRoot, "tmp")
				require.NoError(t, os.MkdirAll(tmpPath, 0o755))
				require.NoError(t, os.Chmod(tmpPath, 0o555))
				return tmpDir
			},
			envVars:       map[string]string{},
			pid:           1000,
			expectError:   true,
			errorContains: "unable to create target OBI java agent",
			verifyFile:    false,
		},
		{
			name: "agent content correctly copied",
			setupAgent: func(t *testing.T) string {
				tmpFile := filepath.Join(t.TempDir(), ObiJavaAgentFileName)
				content := []byte("unique test agent content 12345")
				require.NoError(t, os.WriteFile(tmpFile, content, 0o644))
				return tmpFile
			},
			setupTempDir: func(t *testing.T, _ int32) string {
				tmpDir := t.TempDir()
				procRoot := filepath.Join(tmpDir, "proc", "root")
				require.NoError(t, os.MkdirAll(filepath.Join(procRoot, "tmp"), 0o755))
				return tmpDir
			},
			envVars:     map[string]string{},
			pid:         1000,
			expectError: false,
			verifyFile:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agentPath := tt.setupAgent(t)
			tmpDir := tt.setupTempDir(t, tt.pid)

			// Override the root directory function
			originalRootFunc := rootDirForPID
			defer func() { rootDirForPID = originalRootFunc }()
			rootDirForPID = func(_ int32) string {
				return filepath.Join(tmpDir, "proc", "root")
			}

			injector := &JavaInjector{
				cfg:       &obi.DefaultConfig,
				log:       slog.With("component", "javaagent.Injector"),
				agentPath: agentPath,
			}

			ie := &ebpf.Instrumentable{
				FileInfo: &exec.FileInfo{
					Pid: tt.pid,
					Service: svc.Attrs{
						EnvVars: tt.envVars,
					},
				},
				Type: svc.InstrumentableJava,
			}

			resultPath, err := injector.copyAgent(ie)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, resultPath)

				if tt.verifyFile {
					// Verify the file was created in the host filesystem
					procRoot := filepath.Join(tmpDir, "proc", "root")
					expectedHostPath := filepath.Join(procRoot, resultPath)

					info, err := os.Stat(expectedHostPath)
					require.NoError(t, err)
					assert.False(t, info.IsDir())
					assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())

					// Verify content matches
					originalContent, err := os.ReadFile(agentPath)
					require.NoError(t, err)
					copiedContent, err := os.ReadFile(expectedHostPath)
					require.NoError(t, err)
					assert.Equal(t, originalContent, copiedContent)
				}
			}
		})
	}
}

func TestJavaInjector_FindTempDir(t *testing.T) {
	tests := []struct {
		name        string
		setupDirs   func(t *testing.T, root string)
		envVars     map[string]string
		expectError bool
		expectedDir string
	}{
		{
			name: "prefer TMPDIR from env",
			setupDirs: func(t *testing.T, root string) {
				require.NoError(t, os.MkdirAll(filepath.Join(root, "custom", "tmp"), 0o755))
				require.NoError(t, os.MkdirAll(filepath.Join(root, "tmp"), 0o755))
			},
			envVars: map[string]string{
				"TMPDIR": "/custom/tmp",
			},
			expectError: false,
			expectedDir: "/custom/tmp",
		},
		{
			name: "fallback to /tmp",
			setupDirs: func(t *testing.T, root string) {
				require.NoError(t, os.MkdirAll(filepath.Join(root, "tmp"), 0o755))
			},
			envVars:     map[string]string{},
			expectError: false,
			expectedDir: "/tmp",
		},
		{
			name: "fallback to /var/tmp when /tmp missing",
			setupDirs: func(t *testing.T, root string) {
				require.NoError(t, os.MkdirAll(filepath.Join(root, "var", "tmp"), 0o755))
			},
			envVars:     map[string]string{},
			expectError: false,
			expectedDir: "/var/tmp",
		},
		{
			name: "error when no temp dir available",
			setupDirs: func(t *testing.T, root string) {
				require.NoError(t, os.MkdirAll(root, 0o755))
			},
			envVars:     map[string]string{},
			expectError: true,
		},
		{
			name: "ignore invalid TMPDIR from env",
			setupDirs: func(t *testing.T, root string) {
				require.NoError(t, os.MkdirAll(filepath.Join(root, "tmp"), 0o755))
			},
			envVars: map[string]string{
				"TMPDIR": "/nonexistent",
			},
			expectError: false,
			expectedDir: "/tmp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			tt.setupDirs(t, root)

			injector := &JavaInjector{
				cfg: &obi.Config{},
			}

			ie := &ebpf.Instrumentable{
				FileInfo: &exec.FileInfo{
					Service: svc.Attrs{
						EnvVars: tt.envVars,
					},
				},
			}

			tmpDir, err := injector.findTempDir(root, ie)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "couldn't find suitable temp directory")
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedDir, tmpDir)
			}
		})
	}
}

func TestDirOK(t *testing.T) {
	tests := []struct {
		name      string
		setupDirs func(t *testing.T) (root string, dir string)
		expected  bool
	}{
		{
			name: "valid directory exists",
			setupDirs: func(t *testing.T) (string, string) {
				root := t.TempDir()
				dir := "testdir"
				require.NoError(t, os.MkdirAll(filepath.Join(root, dir), 0o755))
				return root, dir
			},
			expected: true,
		},
		{
			name: "directory does not exist",
			setupDirs: func(t *testing.T) (string, string) {
				root := t.TempDir()
				return root, "nonexistent"
			},
			expected: false,
		},
		{
			name: "path is a file not a directory",
			setupDirs: func(t *testing.T) (string, string) {
				root := t.TempDir()
				file := "testfile"
				require.NoError(t, os.WriteFile(filepath.Join(root, file), []byte("content"), 0o644))
				return root, file
			},
			expected: false,
		},
		{
			name: "nested directory exists",
			setupDirs: func(t *testing.T) (string, string) {
				root := t.TempDir()
				dir := filepath.Join("nested", "path", "dir")
				require.NoError(t, os.MkdirAll(filepath.Join(root, dir), 0o755))
				return root, dir
			},
			expected: true,
		},
		{
			name: "empty root path",
			setupDirs: func(_ *testing.T) (string, string) {
				return "", "/tmp"
			},
			expected: true,
		},
		{
			name: "empty dir path",
			setupDirs: func(t *testing.T) (string, string) {
				root := t.TempDir()
				return root, ""
			},
			expected: true,
		},
		{
			name: "absolute path directory",
			setupDirs: func(t *testing.T) (string, string) {
				root := t.TempDir()
				dir := filepath.Join("abs", "path")
				require.NoError(t, os.MkdirAll(filepath.Join(root, dir), 0o755))
				return root, dir
			},
			expected: true,
		},
		{
			name: "directory with no permissions",
			setupDirs: func(t *testing.T) (string, string) {
				root := t.TempDir()
				dir := "noperm"
				dirPath := filepath.Join(root, dir)
				require.NoError(t, os.MkdirAll(dirPath, 0o755))
				require.NoError(t, os.Chmod(dirPath, 0o000))
				t.Cleanup(func() {
					err := os.Chmod(dirPath, 0o755)
					assert.NoError(t, err)
				})
				return root, dir
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root, dir := tt.setupDirs(t)
			result := dirOK(root, dir)
			assert.Equal(t, tt.expected, result)
		})
	}
}
