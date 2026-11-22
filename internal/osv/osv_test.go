package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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

func TestMalwareAliasOnLaterPage(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			calls++
			var req struct {
				Queries []query `json:"queries"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
				return
			}
			if calls == 1 {
				w.Write([]byte(`{"results":[{}, {"next_page_token":"more"}]}`))
			} else {
				if len(req.Queries) != 1 || req.Queries[0].PageToken != "more" || req.Queries[0].Package.Name != "bad" {
					t.Errorf("wrong next page query: %+v", req.Queries)
				}
				w.Write([]byte(`{"results":[{"vulns":[{"id":"MAL-2026-test"}]}]}`))
			}
		case "/v1/vulns/MAL-2026-test":
			w.Write([]byte(`{"id":"MAL-2026-test","summary":"malware"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := New()
	c.BaseURL = srv.URL
	hits, err := c.Check(context.Background(), []pkgs.Package{{Ecosystem: pkgs.NPM, Name: "good", Version: "1.0.0"}, {Ecosystem: pkgs.NPM, Name: "bad", Version: "1.0.0"}})
	if err != nil || len(hits) != 1 || hits[0].Package.Name != "bad" || !hits[0].Advisories[0].Malicious {
		t.Fatalf("lost malware on a later page: hits=%+v err=%v", hits, err)
	}
}

func TestAdvisoryFailurePreservesKnownMalware(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/querybatch" {
			w.Write([]byte(`{"results":[{"vulns":[{"id":"MAL-test"},{"id":"GHSA-unknown"}]}]}`))
		} else {
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := New()
	c.BaseURL = srv.URL
	hits, err := c.Check(context.Background(), []pkgs.Package{{Ecosystem: pkgs.NPM, Name: "bad", Version: "1.0.0"}})
	if err != nil || len(hits) != 1 || !hits[0].Advisories[0].Malicious {
		t.Fatalf("want the malware hit without a lookup error: hits=%+v err=%v", hits, err)
	}
}

func TestRepeatedPageTokenFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"next_page_token":"stuck"}]}`))
	}))
	defer srv.Close()
	c := New()
	c.BaseURL = srv.URL
	if _, err := c.Check(context.Background(), []pkgs.Package{{Ecosystem: pkgs.NPM, Name: "pkg", Version: "1.0.0"}}); err == nil {
		t.Fatal("repeated pagination token must fail")
	}
}

func TestCanceledRequestDoesNotRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cancel()
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	c := New()
	c.BaseURL = srv.URL
	start := time.Now()
	if _, err := c.Check(ctx, []pkgs.Package{{Ecosystem: pkgs.NPM, Name: "pkg", Version: "1.0.0"}}); err == nil {
		t.Fatal("canceled request should fail")
	}
	if time.Since(start) > time.Second {
		t.Fatal("canceled request waited for retry backoff")
	}
}

// Fetching every CVE record to look for malware aliases made scans take
// 30s instead of 5s. Only MAL-* records are fetched unless --all-vulns.
func TestOnlyMalwareDetailsAreFetched(t *testing.T) {
	var fetched []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/querybatch" {
			w.Write([]byte(`{"results":[{"vulns":[{"id":"MAL-1"},{"id":"GHSA-a"},{"id":"CVE-b"}]}]}`))
			return
		}
		fetched = append(fetched, r.URL.Path)
		w.Write([]byte(`{"id":"MAL-1","summary":"malware"}`))
	}))
	defer srv.Close()
	c := New()
	c.BaseURL = srv.URL
	if _, err := c.Check(context.Background(), []pkgs.Package{{Ecosystem: pkgs.NPM, Name: "x", Version: "1.0.0"}}); err != nil {
		t.Fatal(err)
	}
	if len(fetched) != 1 || fetched[0] != "/v1/vulns/MAL-1" {
		t.Fatalf("fetched %v, want only the MAL record", fetched)
	}
}
