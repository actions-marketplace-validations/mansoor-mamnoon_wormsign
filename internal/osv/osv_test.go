package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mansoor-mamnoon/wormsign/internal/pkgs"
)

func fakeOSV(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			var req struct {
				Queries []query `json:"queries"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			results := make([]map[string]any, len(req.Queries))
			for i, q := range req.Queries {
				results[i] = map[string]any{}
				switch q.Package.Name + "@" + q.Version {
				case "keyv@6.0.0":
					results[i]["vulns"] = []map[string]string{{"id": "MAL-2026-11524"}}
				case "lodash@4.17.20":
					results[i]["vulns"] = []map[string]string{{"id": "GHSA-35jh-r3h4-6jhm"}}
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"results": results})
		case "/v1/vulns/MAL-2026-11524":
			w.Write([]byte(`{"id":"MAL-2026-11524","summary":"Malicious code in keyv (npm)"}`))
		case "/v1/vulns/GHSA-35jh-r3h4-6jhm":
			w.Write([]byte(`{"id":"GHSA-35jh-r3h4-6jhm","summary":"Command injection in lodash"}`))
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestCheckReportsOnlyMalware(t *testing.T) {
	srv := fakeOSV(t)
	defer srv.Close()
	c := New()
	c.BaseURL = srv.URL
	in := []pkgs.Package{{Ecosystem: pkgs.NPM, Name: "keyv", Version: "6.0.0"}, {Ecosystem: pkgs.NPM, Name: "lodash", Version: "4.17.20"}, {Ecosystem: pkgs.NPM, Name: "left-pad", Version: "1.3.0"}}

	hits, err := c.Check(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].Package.Name != "keyv" || !hits[0].Advisories[0].Malicious {
		t.Fatalf("unexpected hits: %+v", hits)
	}
	if hits[0].Advisories[0].Summary == "" {
		t.Error("expected advisory details to be fetched")
	}

	c.IncludeVulns = true
	hits, _ = c.Check(context.Background(), in)
	if len(hits) != 2 {
		t.Fatalf("with vulns: want 2 hits, got %+v", hits)
	}
}

func TestIsMalicious(t *testing.T) {
	if !IsMalicious("GHSA-x", []string{"MAL-2025-1"}) || IsMalicious("GHSA-x", nil) || !IsMalicious("MAL-1", nil) {
		t.Fatal("IsMalicious wrong")
	}
}
