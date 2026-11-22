<p align="center"><img src="docs/logo.svg" alt="wormsign" width="112"></p>

<h1 align="center">wormsign</h1>

<p align="center">Checks whether an npm or PyPI worm reached your machine,<br>and lists the credentials to rotate if one did.</p>

<p align="center">
  <a href="https://github.com/mansoor-mamnoon/wormsign/actions/workflows/ci.yml"><img src="https://github.com/mansoor-mamnoon/wormsign/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/mansoor-mamnoon/wormsign/releases"><img src="https://img.shields.io/github/v/release/mansoor-mamnoon/wormsign" alt="release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT"></a>
</p>

```sh
brew install mansoor-mamnoon/tap/wormsign
wormsign
```

One Go binary with no dependencies, account or API key. It reads files under your home
directory and a few system locations. It never runs package scripts or changes your files.
A scan of 29,000 directories and 4,350 packages takes about 7 seconds on a laptop.

To see a detection without being infected, run `wormsign --demo`. It builds a harmless fake
project in a temp directory and scans only that:

<p align="center"><img src="docs/demo.gif" alt="wormsign --demo: DETECTED verdict for the malicious keyv 6.0.0 release, a Claude Code SessionStart hook and a VS Code folder-open task, followed by a credential rotation checklist" width="900"></p>

## Why

Since September 2025, self-spreading npm worms (Shai-Hulud, Mini Shai-Hulud, SANDWORM_MODE,
ChainDrop) have stolen npm and GitHub tokens and republished themselves into hundreds of
packages. ChainDrop infected 444 packages in four hours in August 2026. After each outbreak
the advice is to check whether you installed an affected version.

That check has to cover every project on the machine, plus global installs and the npx cache
that MCP servers run from. And upgrading the package does not remove what the worm installed:
a Claude Code `SessionStart` hook, a VS Code task that runs when a folder opens, an MCP
server, a LaunchAgent. wormsign checks package versions and those locations in one pass.

It is a triage tool. A malicious version in a lockfile does not prove the code ran, and a
clean result means no known indicators were found in the files checked.

## Install

```sh
brew install mansoor-mamnoon/tap/wormsign
```

The install script downloads a [release binary](https://github.com/mansoor-mamnoon/wormsign/releases)
for macOS or Linux and checks its SHA-256 checksum:

```sh
curl -fsSL https://raw.githubusercontent.com/mansoor-mamnoon/wormsign/main/install.sh | sh
```

With Go 1.22 or later:

```sh
go install github.com/mansoor-mamnoon/wormsign@latest
```

Windows binaries are on the releases page. wormsign is not published to npm. A tool that
checks for npm compromise should not need `npm install` to run.

To pin a version, set `WORMSIGN_VERSION=0.1.4` for the install script or use
`go install github.com/mansoor-mamnoon/wormsign@v0.1.4`.

## Usage

```sh
wormsign                     # home directory plus machine-wide checks
wormsign ~/code              # one directory plus machine-wide checks
wormsign --project .         # only this directory; for CI
wormsign --offline           # local checks only; no OSV lookup
wormsign --json              # machine-readable results
```

Put flags before paths. Each report starts with a verdict:

| Verdict | Meaning |
|---|---|
| CLEAN | No known indicators in the files checked. |
| REVIEW | Warnings to inspect. They can be legitimate. |
| DETECTED | A known-malicious package version or a critical local indicator. This alone does not establish that code ran or credentials were stolen. |
| PARTIAL | A lookup or lockfile parse failed, or `--offline` skipped the package check. |

A detection takes precedence over an incomplete scan, and the report still lists what failed.
Directories deeper than 14 levels or unreadable are skipped and counted in one line; `--json`
lists them.

Exit status is 0 when nothing critical is found, 1 for a critical finding (or any warning
with `--strict`), and 2 when the scan was incomplete or a usage error occurred. Choosing
`--offline` does not by itself cause exit 2. `--demo` always exits 0.

## What it checks

| Check | Coverage |
|---|---|
| Packages | npm, yarn, pnpm, Bun text, poetry, uv, pdm and pipenv lockfiles; pinned requirements files; installed `node_modules` (including pnpm's store) and Python `site-packages`; global npm, pnpm and Bun installs, the npx cache, pipx and uv tools. Versions are looked up in [OSV](https://osv.dev); malware has `MAL-*` ids. |
| Coding agents | Claude Code hooks; MCP servers configured for Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, Codex, Gemini CLI, Zed, Kiro and others. |
| Editors | VS Code tasks with `runOn: folderOpen`. |
| CI | Workflows that serialize every secret or run issue or discussion text on a self-hosted runner. |
| Autostart | macOS LaunchAgents, systemd user units, XDG autostart, crontab and shell startup files. |
| Payloads | Campaign filenames (`setup_bun.js`, `bun_environment.js`) in installed packages and known staging locations. File contents and hashes are not verified. |
| Credentials | Which credential files and secret-named environment variables exist, for the rotation checklist. Values are never read into the output. |

A known campaign file, domain or package is critical. Generic patterns (a download piped to a
shell, inline `node -e`, a tunneling service, a secret scanner) are warnings, even several at
once, because developer tools use them too.

## Privacy

Online scans send each package's ecosystem, name and version to `api.osv.dev`. That can
include private package names from your lockfiles. Paths, file contents and credential values
are not sent, and there is no telemetry. `--offline` makes no network requests.

The terminal report shows the command a flagged hook, task or autostart entry runs, with
token, key and password values masked, so you can tell whether it is yours. JSON output and
`--project` runs leave commands out, since those end up in files and CI logs. Reports do
include local paths and the names of credential files; check them before sharing one.

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
        #   args: --strict      # fail on warnings too
        #   version: 0.1.4      # pin the scanner
```

The action runs `wormsign --project` on the repository and writes the report to the job
summary. The build fails when a lockfile pins a known-malicious version or the repository
contains worm persistence.

## Other tools

`npm audit` reports vulnerabilities for one npm project.
[OSV-Scanner](https://github.com/google/osv-scanner) scans dependencies across many more
ecosystems. Campaign-specific scanners such as
[shai-hulud-2-scanner](https://github.com/CyberDracula/shai-hulud-2-scanner) check for one
worm's indicators. wormsign covers every campaign in OSV's malware feed for npm and PyPI and
adds the agent, editor and autostart checks. It does not replace a forensic investigation.

## Flags

```text
  --demo        scan a harmless fake infected project
  --project     only the given paths; skip machine-wide checks and the credential list
  --offline     skip the OSV lookup
  --json        print results as JSON
  --strict      exit 1 on warnings too
  --all-vulns   also report ordinary vulnerabilities
  --no-globals  skip global installs and caches
  --no-color    disable color and the progress spinner
  --version     print the version
```

## Limits

- Detection depends on OSV's malware feed and the local patterns in this repository. A
  campaign reported today may not be covered yet.
- The search skips caches, toolchains, cloud-synced folders and selected OS folders, and does
  not follow directory symlinks.
- Bun's binary `bun.lockb` is not parsed. The lockfile parsers cover the formats listed above,
  not full YAML or TOML. Unpinned dependencies cannot be checked by version.
- Local checks match patterns and filenames. They can flag legitimate tools and miss renamed
  or obfuscated payloads.
- Windows autostart locations are not checked yet.
- It scans once. It does not monitor the machine or remove anything. If a payload ran, rotate
  credentials from a different machine.

Please report false positives, misses and new campaign indicators in
[issues](https://github.com/mansoor-mamnoon/wormsign/issues), with secrets removed.

## Development

```sh
gofmt -l .          # CI formats with Go 1.27; older gofmt aligns some maps differently
go vet ./...
go test -race ./...
go run . --demo
```

`scripts/render-demo.py <binary>` records a real `--demo` run and renders `docs/demo.gif`.
It needs network access and [agg](https://github.com/asciinema/agg).

## Changelog

- 0.1.4: skipped directories no longer mark a scan as partial; scans are four times faster;
  reports show the redacted command behind each finding; the demo shows the OSV hit again.
- 0.1.3: stricter handling of incomplete scans, OSV pagination, safer severities for generic
  patterns, terminal-escape sanitizing.
- 0.1.2 and 0.1.1: verdict-first report; GitHub Action writes to the job summary.
- 0.1.0: first release.

Full notes are on the [releases page](https://github.com/mansoor-mamnoon/wormsign/releases).
License: [MIT](LICENSE).
