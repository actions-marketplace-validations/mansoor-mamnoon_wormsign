package pkgs

import (
	"bufio"
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
)

// NormalizePyPI applies PEP 503 name normalization.
func NormalizePyPI(name string) string {
	return strings.ToLower(pyNormRe.ReplaceAllString(name, "-"))
}

var pyNormRe = regexp.MustCompile(`[-_.]+`)

var reqLine = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;#,]+)`)

// ParseRequirements extracts exact pins (name==version) from requirements files.
func ParseRequirements(data []byte) ([]Package, error) {
	var out []Package
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if m := reqLine.FindStringSubmatch(strings.TrimSpace(sc.Text())); m != nil && !strings.Contains(m[2], "*") {
			out = append(out, Package{PyPI, NormalizePyPI(m[1]), m[2]})
		}
	}
	return out, sc.Err()
}

// ParseTOMLPackages handles poetry.lock, uv.lock and pdm.lock, which all use
// [[package]] tables with name/version keys.
func ParseTOMLPackages(data []byte) ([]Package, error) {
	var out []Package
	var name, version string
	inPkg := false
	flush := func() {
		if inPkg && name != "" {
			out = append(out, Package{PyPI, NormalizePyPI(name), version})
		}
		name, version = "", ""
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(stripTOMLComment(sc.Text()))
		if strings.HasPrefix(line, "[") {
			if line == "[[package]]" {
				flush()
				inPkg = true
			} else {
				flush()
				inPkg = false
			}
			continue
		}
		if !inPkg {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch k {
		case "name":
			if name == "" {
				name = v
			}
		case "version":
			if version == "" {
				version = v
			}
		}
	}
	flush()
	return out, sc.Err()
}

// stripTOMLComment ignores # inside basic and literal strings.
func stripTOMLComment(line string) string {
	var quote rune
	escaped := false
	for i, r := range line {
		if escaped {
			escaped = false
			continue
		}
		if quote == '"' && r == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '"' || r == '\'' {
			quote = r
		}
		if r == '#' {
			return line[:i]
		}
	}
	return line
}

// ParsePipfileLock handles Pipfile.lock JSON.
func ParsePipfileLock(data []byte) ([]Package, error) {
	var lock map[string]json.RawMessage
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	var out []Package
	for section, raw := range lock {
		if section == "_meta" {
			continue
		}
		var deps map[string]struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(raw, &deps) != nil {
			continue
		}
		for n, d := range deps {
			out = append(out, Package{PyPI, NormalizePyPI(n), strings.TrimLeft(d.Version, "=")})
		}
	}
	return out, nil
}
