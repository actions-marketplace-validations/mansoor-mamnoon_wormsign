package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mansoor-mamnoon/wormsign/internal/pkgs"
)

func TestInvalidAdvisoryCannotEraseMalware(t *testing.T) {
	for _, body := range []string{"{}", "null", `{"id":"GHSA-different"}`} {
		t.Run(body, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/querybatch" {
					w.Write([]byte(`{"results":[{"vulns":[{"id":"MAL-known"}]}]}`))
					return
				}
				w.Write([]byte(body))
			}))
			defer srv.Close()
			client := New()
			client.BaseURL = srv.URL
			hits, err := client.Check(context.Background(), []pkgs.Package{{Name: "bad", Version: "1.0.0", Ecosystem: pkgs.NPM}})
			// The hit must survive; losing the summary text is not a failure.
			if err != nil || len(hits) != 1 || !hits[0].Advisories[0].Malicious {
				t.Fatalf("malformed detail erased evidence: hits=%+v err=%v", hits, err)
			}
		})
	}
}

func TestNullBatchResultCannotPass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[null]}`))
	}))
	defer srv.Close()
	client := New()
	client.BaseURL = srv.URL
	if _, err := client.Check(context.Background(), []pkgs.Package{{Name: "bad", Version: "1.0.0", Ecosystem: pkgs.NPM}}); err == nil {
		t.Fatal("null result silently treated as checked and clean")
	}
}

func TestLaterBatchFailurePreservesMalware(t *testing.T) {
	for _, failure := range []string{"status", "length"} {
		t.Run(failure, func(t *testing.T) {
			// Batches run concurrently, so the server picks its answer from
			// the batch size: the full 1000-package batch succeeds and the
			// trailing 1-package batch fails.
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/querybatch" {
					w.Write([]byte(`{"id":"MAL-known"}`))
					return
				}
				var req struct {
					Queries []query `json:"queries"`
				}
				json.NewDecoder(r.Body).Decode(&req)
				if len(req.Queries) == 1000 {
					results := make([]map[string]any, 1000)
					for i := range results {
						results[i] = map[string]any{}
					}
					results[0]["vulns"] = []map[string]string{{"id": "MAL-known"}}
					json.NewEncoder(w).Encode(map[string]any{"results": results})
				} else if failure == "status" {
					w.WriteHeader(http.StatusBadRequest)
				} else {
					w.Write([]byte(`{"results":[]}`))
				}
			}))
			defer srv.Close()
			client := New()
			client.BaseURL = srv.URL
			packages := make([]pkgs.Package, 1001)
			for i := range packages {
				packages[i] = pkgs.Package{Name: "bad", Version: "1.0.0", Ecosystem: pkgs.NPM}
			}
			hits, err := client.Check(context.Background(), packages)
			if err == nil || len(hits) != 1 || !hits[0].Advisories[0].Malicious {
				t.Fatalf("lost earlier batch evidence: %+v %v", hits, err)
			}
		})
	}
}

func TestInvalidResultDoesNotDiscardLaterPackageMalware(t *testing.T) {
	for _, invalid := range []string{`{"next_page_token":"same"}`, "null"} {
		t.Run(invalid, func(t *testing.T) {
			// Batches run concurrently, so the server picks its answer from
			// the batch size: the full 1000-package batch succeeds and the
			// trailing 1-package batch fails.
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/querybatch" {
					w.Write([]byte(`{"id":"MAL-known"}`))
					return
				}
				var req struct {
					Queries []query `json:"queries"`
				}
				json.NewDecoder(r.Body).Decode(&req)
				if len(req.Queries) == 1000 {
					w.Write([]byte(`{"results":[{"next_page_token":"same"},{"next_page_token":"more"}]}`))
					return
				}
				w.Write([]byte(`{"results":[` + invalid + `,{"vulns":[{"id":"MAL-known"}]}]}`))
			}))
			defer srv.Close()
			client := New()
			client.BaseURL = srv.URL
			hits, err := client.Check(context.Background(), []pkgs.Package{{Name: "first", Version: "1.0.0", Ecosystem: pkgs.NPM}, {Name: "second", Version: "1.0.0", Ecosystem: pkgs.NPM}})
			if err == nil || len(hits) != 1 || hits[0].Package.Name != "second" || !hits[0].Advisories[0].Malicious {
				t.Fatalf("lost later result evidence: %+v %v", hits, err)
			}
		})
	}
}

func TestLaterPageFailurePreservesMalware(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/querybatch" {
			w.Write([]byte(`{"id":"MAL-known"}`))
			return
		}
		// A repeated page token is a protocol failure after useful evidence.
		w.Write([]byte(`{"results":[{"vulns":[{"id":"MAL-known"}],"next_page_token":"same"}]}`))
	}))
	defer srv.Close()
	client := New()
	client.BaseURL = srv.URL
	hits, err := client.Check(context.Background(), []pkgs.Package{{Name: "bad", Version: "1.0.0", Ecosystem: pkgs.NPM}})
	if err == nil || len(hits) != 1 || !hits[0].Advisories[0].Malicious {
		t.Fatalf("lost malware on pagination failure: hits=%+v err=%v", hits, err)
	}
}

func TestBatchRejectsRedirect(t *testing.T) {
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("received redirected inventory") }))
	defer destination.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	client := New()
	client.BaseURL = server.URL
	if _, err := client.Check(context.Background(), []pkgs.Package{{Name: "private", Version: "1", Ecosystem: pkgs.NPM}}); err == nil {
		t.Fatal("redirected batch succeeded")
	}
}
