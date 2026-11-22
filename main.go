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
	"sync/atomic"
	"time"

	"github.com/mansoor-mamnoon/wormsign/internal/report"
	"github.com/mansoor-mamnoon/wormsign/internal/scan"
)

var version = "dev"

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
		vulns     = flag.Bool("all-vulns", false, "also report ordinary vulnerabilities, not just malware")
		noGlobals = flag.Bool("no-globals", false, "skip global installs and the npx cache")
		strict    = flag.Bool("strict", false, "exit non-zero on warnings too")
		noColor   = flag.Bool("no-color", false, "disable colored output")
		showVer   = flag.Bool("version", false, "print version")
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

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	var progress atomic.Int64
	stopSpinner := spinner(&progress, !*jsonOut && report.ColorEnabled(os.Stderr))
	res := scan.Run(ctx, scan.Options{
		Roots: roots, Home: home, Offline: *offline, IncludeVulns: *vulns,
		NoGlobals: *noGlobals, Progress: &progress,
	})
	stopSpinner()

	if *jsonOut {
		if err := report.JSON(os.Stdout, res); err != nil {
			fmt.Fprintln(os.Stderr, "wormsign:", err)
			os.Exit(2)
		}
	} else {
		report.Text(os.Stdout, res, report.NewStyle(!*noColor && report.ColorEnabled(os.Stdout)), home, version)
	}
	if res.Critical() || (*strict && res.Warnings()) {
		os.Exit(1)
	}
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
				fmt.Fprintf(os.Stderr, "\r\033[K%c scanning… %d dirs", frames[i%len(frames)], n.Load())
			}
		}
	}()
	return func() { close(done); <-stopped }
}
