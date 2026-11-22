// wormsign checks a developer machine for signs of npm/PyPI supply-chain
// worms: known-malicious package versions anywhere on disk, plus the
// persistence and exfiltration tricks those worms leave behind.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mansoor-mamnoon/wormsign/internal/demo"
	"github.com/mansoor-mamnoon/wormsign/internal/report"
	"github.com/mansoor-mamnoon/wormsign/internal/scan"
)

var version = "dev"

func init() {
	// `go install ...@v0.1.0` builds carry the module version in their build info;
	// release builds set it with ldflags.
	if version == "dev" {
		if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			version = strings.TrimPrefix(bi.Main.Version, "v")
		}
	}
}

const usage = `wormsign — did a supply-chain worm get this machine?

Usage:
  wormsign [flags] [path ...]

With no paths, scans your home directory. Checks every lockfile and installed
package tree against OSV.dev's malicious-package feed, then looks for worm
persistence in coding agents, editors, CI workflows and autostart entries.

Flags:
`

func main() {
	var (
		jsonOut   = flag.Bool("json", false, "print results as JSON")
		offline   = flag.Bool("offline", false, "skip the OSV.dev lookup (no network); local checks only")
		vulns     = flag.Bool("all-vulns", false, "also report ordinary vulnerabilities (CVEs)")
		noGlobals = flag.Bool("no-globals", false, "skip global installs and the npx cache")
		project   = flag.Bool("project", false, "scan only the given paths; skip machine-wide checks (for CI)")
		strict    = flag.Bool("strict", false, "exit non-zero on warnings too")
		noColor   = flag.Bool("no-color", false, "disable colored output")
		showVer   = flag.Bool("version", false, "print version")
		demoMode  = flag.Bool("demo", false, "scan a harmless fake infected project to see what a detection looks like")
	)
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
		fmt.Fprint(os.Stderr, "\nExit status: 0 clean, 1 something critical found, 2 usage/runtime error.\n")
	}
	flag.Parse()
	if *showVer {
		fmt.Println("wormsign", version)
		return
	}

	roots, home := scan.DefaultRoots()
	if flag.NArg() > 0 {
		roots = roots[:0]
		for _, a := range flag.Args() {
			abs, err := filepath.Abs(a)
			if err == nil {
				_, err = os.Stat(abs)
			}
			if err != nil {
				fmt.Fprintln(os.Stderr, "wormsign:", err)
				os.Exit(2)
			}
			roots = append(roots, abs)
		}
	}

	opts := scan.Options{Roots: roots, Home: home, Offline: *offline, IncludeVulns: *vulns, NoGlobals: *noGlobals, ProjectOnly: *project}
	if *demoMode {
		dir, err := demo.Create()
		if err != nil {
			fmt.Fprintln(os.Stderr, "wormsign: demo:", err)
			os.Exit(2)
		}
		defer os.RemoveAll(dir)
		// Demo checks must never inspect the real machine.
		opts.Roots, opts.Home, opts.NoGlobals = []string{dir}, dir, true
		opts.ProjectOnly = true
		home = dir
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	var progress atomic.Int64
	stopSpinner := spinner(&progress, !*jsonOut && report.ColorEnabled(os.Stderr))
	opts.Progress = &progress
	res := scan.Run(ctx, opts)
	stopSpinner()
	if *demoMode {
		res.Credentials = demo.Credentials()
	}

	if *jsonOut {
		if err := report.JSON(os.Stdout, res); err != nil {
			fmt.Fprintln(os.Stderr, "wormsign:", err)
			os.Exit(2)
		}
	} else {
		report.Text(os.Stdout, res, report.NewStyle(!*noColor && report.ColorEnabled(os.Stdout)), home, version)
	}
	if *demoMode {
		if !*jsonOut {
			fmt.Println("  (demo: this was a fake project in a temp directory. Run `wormsign` to scan this machine.)")
			fmt.Println()
		}
		return
	}
	os.Exit(res.ExitCode(*strict))
}

// spinner shows a live directory count on stderr while the walk runs.
func spinner(n *atomic.Int64, enabled bool) func() {
	if !enabled {
		return func() {}
	}
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		frames := []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
		t := time.NewTicker(80 * time.Millisecond)
		defer t.Stop()
		for i := 0; ; i++ {
			select {
			case <-done:
				fmt.Fprint(os.Stderr, "\r\033[K")
				return
			case <-t.C:
				fmt.Fprintf(os.Stderr, "\r\033[K%c scanning... %d dirs", frames[i%len(frames)], n.Load())
			}
		}
	}()
	return func() { close(done); <-stopped }
}
