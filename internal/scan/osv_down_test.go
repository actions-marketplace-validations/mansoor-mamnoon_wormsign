package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mansoor-mamnoon/wormsign/internal/demo"
	"github.com/mansoor-mamnoon/wormsign/internal/osv"
)

func TestOSVFailureIsReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()
	dir, err := demo.Create()
	if err != nil {
		t.Fatal(err)
	}
	c := osv.New()
	c.BaseURL = srv.URL
	res := Run(context.Background(), Options{Roots: []string{dir}, Home: dir, NoGlobals: true, OSV: c})
	if res.OSVError == "" || res.OSVChecked {
		t.Fatalf("expected OSV error to be surfaced, got %+v", res)
	}
}
