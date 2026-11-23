# Wormsign launch playbook

No launch can guarantee stars. The goal is qualified attention: developers who
can run the tool, challenge its assumptions, report misses, and decide whether
it deserves a star.

## Before posting

- Ship the coverage-safety, pinned Action, Go 1.22 CI, CodeQL, security policy,
  and provenance changes in a tagged release.
- Test the release binary, Homebrew formula, `wormsign --demo`, and Action from
  clean environments.
- Keep the maintainer free to answer questions for several hours after each
  post.
- Post to one community at a time. Adapt the wording and incorporate useful
  feedback before the next post.
- Do not ask for upvotes, coordinate votes, mass-message people, or repost a
  weak submission. Ask for specific technical feedback instead.

## Show HN

Read the current [Show HN rules](https://news.ycombinator.com/showhn.html) and
[HN guidelines](https://news.ycombinator.com/newsguidelines.html) immediately
before posting. HN currently asks authors not to submit generated or
AI-edited text, so use the material below as factual notes and write the final
submission yourself in your normal voice.

Suggested title:

> Show HN: Wormsign – scan npm and Python installs for known malware and persistence

Link the title directly to the repository. In the first comment, explain in
your own words:

1. Checking one current lockfile was not enough after a package-worm incident:
   old projects, global installs, caches, hooks, editor tasks, and startup
   entries also mattered.
2. Wormsign is a Go CLI that inventories npm and Python packages, checks known
   malware records in OSV, and separately flags persistence indicators.
3. The fastest safe trial is `wormsign --demo`; it creates a temporary fake
   infected project.
4. Strong evidence and heuristics are deliberately separate. Reports say
   CLEAN, REVIEW, DETECTED, or PARTIAL.
5. Online checks send package names and versions to OSV; `--offline` does not.
6. It is not antivirus: it can miss new or renamed indicators, can warn on
   legitimate commands, does not remediate, and has limited Windows
   persistence coverage.
7. Ask: “Which package stores or persistence surfaces am I missing, and is the
   confidence model clear from the demo?”

Prepare concise answers about OSV-Scanner, Trivy, npm audit, pip-audit, private
package names, false positives, release-binary trust, and Windows support.

## r/coolgithubprojects

Check the subreddit rules, flair choices, and recent moderator announcements
on the day of posting. Use a direct repository link or the demo GIF rather than
a generic promotional image.

Suggested title:

> Wormsign: an open-source CLI that checks npm and Python installs for known malware and persistence

Draft body:

> I built Wormsign because checking a development machine after a
> package-supply-chain incident involves more than the current project's
> lockfile.
>
> It scans npm and Python lockfiles, installed packages, global installs, and
> caches; checks discovered versions against OSV's known-malware records; and
> inspects developer configs and startup locations for persistence. That
> includes Claude Code hooks, MCP configs, VS Code tasks, dev-container
> commands, shell startup files, LaunchAgents, systemd user units, and cron.
>
> Safe demo:
>
> ```sh
> brew install mansoor-mamnoon/tap/wormsign
> wormsign --demo
> ```
>
> It is written in Go, MIT licensed, has release binaries and a GitHub Action,
> and has no telemetry. Online scans send package names and versions to OSV;
> `--offline` skips that lookup.
>
> This detects known malware and suspicious patterns, not every threat. A clean
> result is not proof that a machine is safe, and Wormsign does not remove
> anything.
>
> https://github.com/mansoor-mamnoon/wormsign
>
> I would especially value examples of package locations or persistence
> mechanisms it currently misses.

## r/SideProject

Check the current rules before posting. This audience is a better fit for the
motivation and product decisions than a feature list.

Suggested title:

> I built a CLI to check development machines for known npm/Python malware and persistence

Draft body:

> “Check whether you installed the affected version” sounds simple until you
> consider old repositories, multiple lockfile formats, global packages, npx
> caches, and Python tool environments. Updating a package also does not remove
> a hook or startup entry that was already created.
>
> I built Wormsign to perform that investigation in one pass. It checks
> discovered npm and Python package versions against OSV's known-malware
> records, then inspects developer configs and user startup locations for
> persistence indicators.
>
> The key design choice was separating strong evidence from heuristics. A known
> malicious package version or payload is critical; patterns such as
> `curl | sh` in startup configuration are warnings that need human review.
>
> You can try the output safely:
>
> ```sh
> brew install mansoor-mamnoon/tap/wormsign
> wormsign --demo
> ```
>
> Repo: https://github.com/mansoor-mamnoon/wormsign
>
> Current limits: known indicators only, possible false positives, no
> remediation, bounded filesystem traversal, and incomplete Windows startup
> coverage.
>
> I am looking for focused feedback on two things:
>
> 1. Which package stores or persistence locations should it inspect next?
> 2. Is the CLEAN / REVIEW / DETECTED / PARTIAL model understandable from the
>    demo?

## Follow-through

Reply with technical detail, acknowledge valid limitations, and turn repeated
questions into README improvements. Track installs, release downloads,
returning contributors, useful issues, and stars, but do not optimize the post
for stars alone. A smaller group of credible users produces better long-term
distribution than artificial engagement.

Successful Show HN examples worth studying for structure and comment handling:
[Monolith](https://news.ycombinator.com/item?id=20774322),
[Sidekick](https://news.ycombinator.com/item?id=41591018),
[git-who](https://news.ycombinator.com/item?id=43404548), and
[Parqeye](https://news.ycombinator.com/item?id=45959780).
