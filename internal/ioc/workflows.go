package ioc

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	wfSecretsDump   = regexp.MustCompile(`toJSON\(\s*secrets\s*\)`)
	wfDiscussionRCE = regexp.MustCompile(`\$\{\{\s*github\.event\.(discussion|issue|comment)\.(body|title)\s*\}\}`)
	wfRunLine       = regexp.MustCompile(`(?m)^\s*(-\s*)?run:\s*\|?(.*)$`)
	wfKnownNames    = regexp.MustCompile(`(?i)shai-?hulud|sha1-?hulud|s1ngularity|chaindrop`)
)

// Workflow checks a GitHub Actions workflow for the backdoors worms commit:
// secret dumps, self-hosted runners that execute discussion bodies, and the
// named workflows from known campaigns.
func Workflow(path string) []Finding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	text := string(data)
	name := filepath.Base(path)
	f := func(sev Severity, title, evidence string) Finding {
		return Finding{
			Severity: sev, Check: "workflows", Title: title, Path: path, Evidence: truncate(evidence, 200),
			Fix: "Not yours? Delete it and rotate every repo and org secret.",
		}
	}
	var out []Finding
	if m := wfKnownNames.FindString(name + "\n" + text); m != "" {
		out = append(out, f(Critical, "Workflow matches a known worm campaign ("+m+")", name))
	}
	if strings.Contains(text, "SHA1HULUD") {
		out = append(out, f(Critical, "Workflow targets the SHA1HULUD self-hosted runner used by Shai-Hulud 2.0", "runs-on: SHA1HULUD"))
	}
	if wfSecretsDump.MatchString(text) {
		sev := Warn
		if strings.Contains(text, "curl") || strings.Contains(text, "wget") || strings.Contains(text, "upload-artifact") || strings.Contains(text, "webhook") {
			sev = Critical
		}
		out = append(out, f(sev, "Workflow serialises every secret with toJSON(secrets)", wfSecretsDump.FindString(text)))
	}
	for _, m := range wfRunLine.FindAllStringSubmatchIndex(text, -1) {
		// Look at the run block (this line + following indented lines).
		block := text[m[0]:min(len(text), m[1]+400)]
		if wfDiscussionRCE.MatchString(block) && strings.Contains(text, "self-hosted") {
			out = append(out, f(Critical, "Workflow runs attacker-controlled discussion/issue text on a self-hosted runner", wfDiscussionRCE.FindString(block)))
			break
		}
	}
	return out
}
