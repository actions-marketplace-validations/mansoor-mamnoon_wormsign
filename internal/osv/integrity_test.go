package osv

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mansoor-mamnoon/wormsign/internal/pkgs"
)

// These tests exercise the client over actual HTTP connections, including
// malformed wire responses; no transport or filesystem doubles are installed.
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
			if err == nil || len(hits) != 1 || !hits[0].Advisories[0].Malicious {
				t.Fatalf("malformed detail erased evidence: hits=%+v err=%v", hits, err)
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
