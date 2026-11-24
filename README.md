<p align="center"><img src="docs/logo.svg" alt="wormsign" width="112"></p>

<h1 align="center">wormsign</h1>

<p align="center">Checks your machine for npm and PyPI worms like Shai-Hulud and ChainDrop.</p>

<p align="center">
  <a href="https://github.com/mansoor-mamnoon/wormsign/actions/workflows/ci.yml"><img src="https://github.com/mansoor-mamnoon/wormsign/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/mansoor-mamnoon/wormsign/releases"><img src="https://img.shields.io/github/v/release/mansoor-mamnoon/wormsign" alt="release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT"></a>
</p>

wormsign checks lockfiles, installed packages and caches against OSV malware records.
It also checks editor hooks and startup entries for persistence. After a critical
finding, it lists local credentials to review for rotation.

```sh
brew install mansoor-mamnoon/tap/wormsign
wormsign
```

`wormsign --demo` scans a deliberately infected fixture in a temporary directory:

<p align="center"><img src="docs/demo.gif" alt="wormsign --demo output: DETECTED, the malicious keyv 6.0.0 release, a Claude Code hook, a VS Code task, and a list of credentials to rotate" width="900"></p>

## Install

The installer verifies the release archive’s SHA-256 checksum before installing the binary:

```sh
curl -fsSL https://raw.githubusercontent.com/mansoor-mamnoon/wormsign/main/install.sh | sh
```

Or build it with Go 1.26.11 or later:

```sh
go install github.com/mansoor-mamnoon/wormsign@latest
```

Windows binaries are on the [releases page](https://github.com/mansoor-mamnoon/wormsign/releases).
On Windows, package and project-config scanning works, but startup-entry checks are not yet
implemented.

## What it looks at

- **Packages:** npm, yarn, pnpm, Bun, pip, poetry, uv, and pipenv lockfiles;
  installed `node_modules` and `site-packages`; global installs; the npx cache; and pipx
  and uv tools. Each discovered version is checked against [OSV](https://osv.dev).
  For pip, this includes exact pins in `requirements*.txt`, `*-requirements.txt`,
  and `.txt` files directly inside a `requirements/` directory. For example,
  `wormsign --project .` checks both `dev-requirements.txt` and `requirements/production.txt`.
- **Persistence:** Claude Code hooks; MCP server configs; VS Code tasks; dev-container
  commands; GitHub workflows; LaunchAgents; systemd user units; crontab; shell startup
  files; and known payload filenames.

A known worm file, domain or malicious package version triggers a critical finding.
A command such as `curl | sh` in a startup task triggers a warning. Each report starts with CLEAN, REVIEW, DETECTED or PARTIAL. PARTIAL means part of
the scan failed or you used `--offline`.

A bad version in a lockfile doesn't prove the code ran, and a clean result only means nothing
known turned up.

## Privacy

Online scans send each package's name and version to api.osv.dev. That can include private
package names. Nothing else leaves your machine, and there's no telemetry. `--offline` skips
the lookup.

The terminal report shows the command behind a flagged hook or task with tokens and passwords
masked, so you can tell whether it's yours. JSON output and CI runs leave commands out.

## CI

```yaml
name: wormsign
on: [push, pull_request]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.26.11"
      - uses: mansoor-mamnoon/wormsign@v0.2.0
```

The action scans the repository only, fails on a critical finding, and writes the report to
the job summary. Pass `args: --strict` to fail on warnings. By default, it builds wormsign
from the referenced Action revision. Pin a release tag or commit SHA; set `version` to
download a release binary instead.

## Options

```text
--demo        scan a fake infected project
--project     scan only the given folders, skipping machine-wide checks (used by CI)
--offline     skip the OSV lookup
--json        print JSON
--strict      exit 1 on warnings too
--all-vulns   also report ordinary vulnerabilities
--no-globals  skip global installs and caches
```

Exit codes are 0 for a passing scan, 1 for a critical finding or a warning under
`--strict`, and 2 for a scan error such as an unreachable OSV endpoint.

## Limits

Coverage depends on OSV records and the detection rules in this repository.
Rules can flag legitimate tools and miss renamed payloads. To keep a home-directory scan bounded, wormsign skips caches,
VCS internals, toolchains, cloud-synced folders and directories deeper than 14 levels; use an
explicit path to scan a skipped project. Unreadable or depth-limited directories make the
result PARTIAL. Linked lockfiles and project configs also make the scan partial.
Installed npm manifest checks follow links only within the scanned `node_modules` tree. It doesn't parse Bun's binary `bun.lockb`, and it doesn't check Windows
startup entries yet. It scans once and doesn't remove anything. If something ran,
rotate your credentials from a different machine.

If it flags something harmless or misses something real, please
[open an issue](https://github.com/mansoor-mamnoon/wormsign/issues).

## Development

```sh
go test -race ./...
go run . --demo
```

CI checks formatting with the minimum supported Go version's `gofmt`. `scripts/render-demo.py` re-records
`docs/demo.gif` and needs [agg](https://github.com/asciinema/agg).

I wrote wormsign with help from Claude Code.
