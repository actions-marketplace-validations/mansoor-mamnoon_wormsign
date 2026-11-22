package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func buildCLI(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "wormsign")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func TestCLI(t *testing.T) {
	bin := buildCLI(t)
	for _, tc := range []struct {
		name string
		args []string
		code int
		want string
	}{
		{"version", []string{"--version"}, 0, "wormsign"},
		{"help", []string{"--help"}, 0, "Usage:"},
		{"invalid", []string{"--unknown"}, 2, "flag provided but not defined"},
		{"missing", []string{"--offline", "--project", filepath.Join(t.TempDir(), "absent")}, 2, "wormsign:"},
		{"clean", []string{"--offline", "--project", "--json", t.TempDir()}, 0, "\""},
		{"demo", []string{"--demo", "--offline", "--json"}, 0, "\""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(bin, tc.args...)
			out, err := cmd.CombinedOutput()
			code := 0
			if err != nil {
				if e, ok := err.(*exec.ExitError); ok {
					code = e.ExitCode()
				} else {
					t.Fatal(err)
				}
			}
			if code != tc.code || !strings.Contains(string(out), tc.want) {
				t.Fatalf("exit %d, want %d; output: %s", code, tc.code, out)
			}
		})
	}
	t.Run("output failure", func(t *testing.T) {
		f, err := os.Open(bin)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		cmd := exec.Command(bin, "--offline", "--project", "--no-color", t.TempDir())
		cmd.Stdout = f // A real read-only descriptor, not a mocked writer.
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		err = cmd.Run()
		e, ok := err.(*exec.ExitError)
		if !ok || e.ExitCode() != 2 || !strings.Contains(stderr.String(), "wormsign:") {
			t.Fatalf("expected output failure exit 2, got %v: %s", err, &stderr)
		}
	})
}

func TestAction(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("composite action requires a POSIX runner")
	}
	bin := buildCLI(t)
	data, err := os.ReadFile("action.yml")
	if err != nil {
		t.Fatal(err)
	}
	_, body, ok := strings.Cut(string(data), "      run: |\n")
	if !ok {
		t.Fatal("missing action scan script")
	}
	var lines []string
	for _, line := range strings.Split(body, "\n") {
		lines = append(lines, strings.TrimPrefix(line, "        "))
	}
	script := strings.Join(lines, "\n")
	for _, tc := range []struct {
		name, path, args string
		code             int
		want             string
	}{
		{"dash path", "-project with spaces", "--offline", 0, "wormsign"},
		{"missing diagnostics", "missing", "--offline", 2, "wormsign:"},
		{"glob flags", ".", "--offline *", 2, "wormsign:"},
		{"multiline flags", ".", "--offline\n--strict", 0, "wormsign"},
		{"log failure", ".", "--offline", 2, "wormsign"},
		{"summary failure", ".", "--offline", 2, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			install := filepath.Join(dir, "wormsign")
			if err := os.Mkdir(install, 0755); err != nil {
				t.Fatal(err)
			}
			content, err := os.ReadFile(bin)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(install, "wormsign"), content, 0755); err != nil {
				t.Fatal(err)
			}
			if tc.name == "dash path" {
				if err := os.Mkdir(filepath.Join(dir, tc.path), 0755); err != nil {
					t.Fatal(err)
				}
			}
			if tc.name == "log failure" {
				if err := os.Mkdir(filepath.Join(dir, "wormsign.txt"), 0755); err != nil {
					t.Fatal(err)
				}
			}
			summary := filepath.Join(dir, "summary")
			if tc.name == "summary failure" {
				if err := os.Mkdir(summary, 0755); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "RUNNER_TEMP="+dir, "SCAN_PATH="+tc.path, "SCAN_ARGS="+tc.args, "GITHUB_STEP_SUMMARY="+summary)
			out, err := cmd.CombinedOutput()
			code := 0
			if err != nil {
				if e, ok := err.(*exec.ExitError); ok {
					code = e.ExitCode()
				} else {
					t.Fatal(err)
				}
			}
			report, readErr := os.ReadFile(summary)
			if tc.name == "summary failure" && code == tc.code {
				return
			}
			if code != tc.code || readErr != nil || !strings.Contains(string(report), tc.want) {
				t.Fatalf("exit %d want %d, summary %q (%v), output %s", code, tc.code, report, readErr, out)
			}
		})
	}
}
