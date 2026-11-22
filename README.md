<p align="center"><img src="docs/logo.svg" alt="wormsign" width="112"></p>

<h1 align="center">wormsign</h1>

<p align="center">Check your projects for known-malicious npm and PyPI packages,<br>plus suspicious hooks, editor tasks and autostart entries.</p>

<p align="center">
  <a href="https://github.com/mansoor-mamnoon/wormsign/actions/workflows/ci.yml"><img src="https://github.com/mansoor-mamnoon/wormsign/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/mansoor-mamnoon/wormsign/releases"><img src="https://img.shields.io/github/v/release/mansoor-mamnoon/wormsign" alt="release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT"></a>
</p>

```sh
brew install mansoor-mamnoon/tap/wormsign
wormsign
```

One Go binary, no third-party dependencies, no account or API key. By default it searches
supported locations under your home directory and runs machine-wide persistence checks.
It reads files without running package scripts or changing your configurations.

Try a harmless fixture first:

```sh
wormsign --demo --offline
```

The demo creates a temporary project with a fake worm payload, Claude hook and VS Code task.
It skips machine-wide checks and uses a fake credential list.

## Why use it?

Upgrading a malicious package does not remove a hook or service it already installed.
wormsign checks package versions and common persistence locations together, then gives you
paths to inspect and a credential rotation checklist when it finds a critical indicator.

This is incident triage. Finding a package in a lockfile does not prove it executed, and
finding no indicators does not prove a machine is safe.

## Install

[Release binaries](https://github.com/mansoor-mamnoon/wormsign/releases) are available for
macOS, Linux and Windows. The shell installer checks the download's SHA-256 checksum:

```sh
curl -fsSL https://raw.githubusercontent.com/mansoor-mamnoon/wormsign/main/install.sh | sh
```

Or build with Go 1.22 or later:

```sh
go install github.com/mansoor-mamnoon/wormsign@latest
```

To pin a release:

```sh
curl -fsSL https://raw.githubusercontent.com/mansoor-mamnoon/wormsign/main/install.sh | WORMSIGN_VERSION=0.1.2 sh
go install github.com/mansoor-mamnoon/wormsign@v0.1.2
```

The behavior documented here includes unreleased fixes on `main`. To try those fixes:

```sh
go install github.com/mansoor-mamnoon/wormsign@main
```

## Usage

```sh
wormsign                    # home directory and machine-wide checks
wormsign ~/code             # this directory and machine-wide checks
wormsign --project .        # only this directory; suitable for CI
wormsign --offline ~/code   # local indicators only; no package advisory lookup
wormsign --project --json . # machine-readable results
```

Put flags before paths. Reports start with one of these verdicts:

| Verdict | Meaning |
|---|---|
| CLEAN | No known indicators found in the files checked. |
| REVIEW | Warnings need inspection; they can be legitimate. |
| DETECTED | A known-malicious package or critical local indicator was found. This does not establish execution or credential theft. |
| PARTIAL | A lookup, traversal or lockfile parsing failure prevented a complete scan, or package lookup was skipped. |

A detection takes precedence over an incomplete scan; the report still lists scan failures.
An offline report always states when package versions were not checked.

Exit status: **0** when no critical indicator or scan error is found; **1** for a critical
indicator, or a warning with `--strict`; **2** for a scan or usage error. Explicitly using
`--offline` does not itself cause exit 2. Demo mode exits 0 after displaying its fixture.

## What it checks

| Check | Coverage |
|---|---|
| Packages | npm, yarn, pnpm, Bun text, poetry, uv, pdm and pipenv lockfiles; pinned requirements; installed `node_modules` and Python `site-packages`; common global npm, pnpm, Bun, npx, pipx and uv tool locations. Versions are queried against [OSV](https://osv.dev). Malware is identified by `MAL-*` IDs or aliases. |
| Coding agents | Claude hooks and MCP configurations in supported client locations, including Claude Code, Cursor, VS Code and Codex. |
| Editors | VS Code tasks that run on folder open. |
| CI | Workflow indicators such as serializing all secrets or executing untrusted issue text on a self-hosted runner. |
| Autostart | macOS LaunchAgents, systemd user units, XDG autostart, crontab and shell startup files. |
| Payloads | Campaign-associated filenames in installed npm packages and selected staging locations. File contents and hashes are not verified. |
| Credentials | Presence of supported credential files and secret-like environment variable names, used for a rotation checklist. This does not establish that credentials were stolen. |

Generic command patterns, including secret scanners, tunneling services, inline JavaScript
and downloads piped to a shell, produce warnings even when several occur together. Campaign
file or domain matches can be critical. Review the path and surrounding configuration before
removing anything.

## Privacy

Online scans send package ecosystem, name and version to `api.osv.dev`. This can include
private package names found in your lockfiles. File contents, local paths and credential
values are not sent to OSV. There is no telemetry.

`--offline` skips OSV and makes no network requests. It cannot check package versions against
the advisory feed.

Reports omit raw hook, task and autostart commands, and MCP command arguments and URLs,
which may contain inline credentials. They include local paths, server names and credential
inventory metadata; review those before sharing a report. JSON MCP entries contain client,
name and configuration path, without launch details.

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
      - uses: mansoor-mamnoon/wormsign@v0
        # with:
        #   args: --strict
        #   version: 0.1.2
```

The action runs `--project`, skips machine-wide checks and the credential inventory, and
writes its report to the job summary. `@v0` follows the action's 0.x releases; `@v0.1.2` pins
the action. The `version` input independently pins the installed scanner; otherwise it uses
the latest release. Neither includes unreleased fixes on `main`.

## Other tools

Use `npm audit` for an npm project's vulnerability report. [OSV-Scanner](https://github.com/google/osv-scanner)
supports recursive dependency scanning across more ecosystems. Dedicated
[Shai-Hulud scanners](https://github.com/CyberDracula/shai-hulud-2-scanner) also check local
installations and caches.

wormsign combines npm/PyPI version checks with local agent, editor and autostart inspection.
It does not replace those tools or a forensic investigation.

## Flags

```text
  --demo        scan a harmless fake infected project
  --project     skip machine-wide checks and credential inventory
  --offline     skip package advisory lookup
  --json        print results as JSON
  --strict      fail on warnings too
  --all-vulns   include ordinary vulnerability warnings alongside malware
  --no-globals  skip global package installs and caches
  --no-color    disable ANSI color and progress animation
  --version     print version
```

## Limits and false positives

- Detection depends on OSV coverage and the local patterns in this repository. There is no
  guarantee that a newly reported campaign is already covered.
- The directory search skips caches, toolchains, cloud-synced folders and selected OS folders,
  and stops at a depth of 14. Depth-limit and traversal errors are reported; excluded folders
  are not traversed. General directory symlinks are not followed.
- Bun's binary `bun.lockb` is not parsed. Text parsers implement selected lockfile formats,
  not complete YAML or TOML grammars. Unpinned dependencies cannot be checked by version.
- Not all read or parse failures in installed package trees and local configuration checks
  are surfaced yet. Inspect unsupported or unreadable locations separately.
- Local checks use patterns and filenames. They can flag legitimate tools and miss renamed,
  obfuscated or removed payloads. A filename match is not a verified malware signature.
- Autostart checks focus on macOS and Linux; Windows persistence coverage is limited.
- This is a point-in-time scan, not monitoring or cleanup. If a payload ran, rotate affected
  credentials from a trusted machine and investigate any persistence it could have installed.

Report false positives, missed detections and sourced campaign indicators in
[issues](https://github.com/mansoor-mamnoon/wormsign/issues). Include a minimal example with
secrets removed.

## Development

```sh
go vet ./...
go test -race ./...
go run . --demo --offline
```

Release history: [releases](https://github.com/mansoor-mamnoon/wormsign/releases). License: [MIT](LICENSE).
