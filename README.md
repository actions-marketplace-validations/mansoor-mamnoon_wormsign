<h1 align="center">wormsign</h1>

<p align="center"><b>Did a supply-chain worm get your machine? One command, ten seconds, every project.</b></p>

<p align="center">
  <a href="https://github.com/mansoor-mamnoon/wormsign/actions/workflows/ci.yml"><img src="https://github.com/mansoor-mamnoon/wormsign/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/mansoor-mamnoon/wormsign/releases"><img src="https://img.shields.io/github/v/release/mansoor-mamnoon/wormsign" alt="release"></a>
  <img src="https://img.shields.io/badge/dependencies-0-brightgreen" alt="zero dependencies">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT"></a>
</p>

<p align="center"><img src="docs/demo.svg" alt="wormsign --demo output" width="820"></p>

Shai-Hulud. Mini Shai-Hulud. SANDWORM_MODE. ChainDrop. Every few weeks another npm worm
steals tokens, republishes itself into hundreds of packages, and the advice is always the same:
*"check whether you installed an affected version."*

Across **every** project on your laptop? Plus global installs, the npx cache your MCP servers run
from, and the Claude Code hooks and VS Code tasks the worm plants so it can come back?

```sh
wormsign
```

That's it. It scans your whole home directory and tells you.

## Install

```sh
# macOS / Linux: checksum-verified binary (read the script first, it's short)
curl -fsSL https://raw.githubusercontent.com/mansoor-mamnoon/wormsign/main/install.sh | sh

# or with Go
go install github.com/mansoor-mamnoon/wormsign@latest
```

Windows: grab the zip from [Releases](https://github.com/mansoor-mamnoon/wormsign/releases).

**Not on npm, on purpose.** You shouldn't have to `npm install` something to find out whether
`npm install` got you. wormsign is one static Go binary with zero dependencies.

Want to see what a hit looks like first? `wormsign --demo` scans a harmless fake infected project.

## What it checks

| | What | Why |
|---|---|---|
| 📦 | **Every lockfile and install on disk.** npm, yarn (classic + berry), pnpm (v5–v9), bun, pip/requirements, poetry, uv, pdm, Pipfile, `node_modules`, `site-packages`, global npm/pnpm/bun, **the npx cache**, pipx/uv tools | Matched against [OSV.dev](https://osv.dev)'s live malicious-package feed (`MAL-*`, including GitHub malware advisories). New campaigns show up there within hours, with no hardcoded list for anyone to maintain. |
| 🤖 | **Coding-agent persistence.** Claude Code `SessionStart` and other hooks, MCP servers across Claude Code/Desktop, Cursor, VS Code, Windsurf, Codex, Gemini CLI, Zed, Kiro and more | Recent worms add a hook or inject an MCP server so they re-run every time you open your agent. |
| 🧩 | **Editor auto-run tasks.** `.vscode/tasks.json` with `runOn: folderOpen` | Opening the repo silently re-runs the payload. |
| ⚙️ | **Backdoored GitHub workflows.** `toJSON(secrets)` dumps, discussion-body injection on self-hosted runners, the `SHA1HULUD` runner | How the worms persist in your repos and steal org secrets. |
| 🚀 | **Autostart.** macOS LaunchAgents, systemd user units, XDG autostart, crontab, shell rc files | Token-stealers that survive `rm -rf node_modules`. |
| 🪱 | **Dropped payload files.** `setup_bun.js`, `bun_environment.js`, TruffleHog caches, staging dirs | Direct evidence the payload ran. |
| 🔑 | **What you'd have to rotate.** npm, GitHub CLI, AWS, GCP, Azure, Docker, kube, PyPI, SSH keys, Claude/Codex logins, secret-looking env vars | If something is critical, you get a rotation checklist for *this* machine. |

The persistence checks look at **behaviour** (piping downloads into shells, inline `node -e`,
reading `.npmrc`, posting to webhook sites, running from temp dirs), not just one campaign's file
hashes, so they keep working when the next worm renames its files.

## What leaves your machine

Only `(ecosystem, package name, version)` tuples, sent to `api.osv.dev` (Google's open
vulnerability database), the same thing `osv-scanner` sends. No paths, no file contents, no
telemetry. Credentials are detected by file presence; **values are never read into the output**.

`wormsign --offline` runs every local check with no network at all.

## Use it in CI

Fail a PR that pins a known-malicious version or adds worm persistence to the repo:

```yaml
- uses: actions/checkout@v4
- uses: mansoor-mamnoon/wormsign@v0
  # with:
  #   path: .
  #   args: --strict   # also fail on warnings
```

Locally, `wormsign --project .` does the same: it scans just that directory and skips machine-wide checks.

## Flags

```
wormsign [flags] [path ...]     # default path: your home directory

  --demo        scan a harmless fake infected project
  --project     only the given paths; skip machine-wide checks (CI)
  --offline     no network; skip the OSV lookup
  --json        machine-readable output
  --strict      exit 1 on warnings, not just critical findings
  --all-vulns   also report ordinary CVEs (off by default: this is a malware tool)
  --no-globals  skip global installs and the npx cache
```

Exit status: `0` clean · `1` critical finding · `2` error.

## FAQ

**Why not `npm audit`?** It checks one project's npm tree, and only when you run it there.
wormsign checks every project on the machine across npm and PyPI, plus global installs, the npx
cache, and the persistence the worm leaves behind after you've already upgraded the bad package.

**Why not osv-scanner / Socket / Snyk?** Use them! They're great at keeping bad packages
*out* of a project. wormsign answers a different question: *"a worm was just announced, was this
laptop hit, and what do I rotate?"*

**It flagged something I added on purpose.** Warnings are "a human should glance at this," not
accusations. A repo-level `SessionStart` hook is legitimate sometimes, and it's also exactly what a
worm adds. Criticals need a known-malicious package, a known worm artifact, or several
independent suspicious behaviours together.

**Something's missing or a check is wrong.** Please open an issue, especially with a new
campaign's indicators.

## Limitations

- Bun's binary `bun.lockb` isn't parsed (the text `bun.lock`, Bun's default since 1.2, is).
- Heuristics can miss a novel, careful attacker. A clean result means "no known signs," not a guarantee.
- It's a triage tool, not EDR. If it says you're compromised, rotate from a different machine.

## License

MIT
