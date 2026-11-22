package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/mansoor-mamnoon/wormsign/internal/scan"
)

func TestIncompleteReportDoesNotClaimClean(t *testing.T) {
	var out bytes.Buffer
	Text(&out, &scan.Result{ParseErrors: []string{"/project/package-lock.json: invalid JSON"}}, NewStyle(false), "", "test")
	text := out.String()
	if strings.Contains(text, "CLEAN") || strings.Contains(text, "Checked and clean") || !strings.Contains(text, "PARTIAL") || !strings.Contains(text, "package-lock.json") {
		t.Fatalf("misleading incomplete report:\n%s", text)
	}
}
