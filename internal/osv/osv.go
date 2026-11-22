// Package osv checks packages against OSV.dev's malicious-package feed.
//
// OSV aggregates the OpenSSF malicious-packages dataset (MAL-* ids) and
// GitHub's malware advisories, so a single batch query covers every known
// campaign — Shai-Hulud, ChainDrop, typosquats — without a hardcoded list.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mansoor-mamnoon/wormsign/internal/pkgs"
)

const batchSize = 1000

// Client talks to the OSV API.
type Client struct {
	BaseURL string
	HTTP    *http.Client
	// IncludeVulns also reports ordinary (non-malware) vulnerabilities.
	IncludeVulns bool
}

func New() *Client {
	return &Client{BaseURL: "https://api.osv.dev", HTTP: &http.Client{Timeout: 60 * time.Second}}
}

// Advisory is a matched OSV record.
type Advisory struct {
	ID        string   `json:"id"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details,omitempty"`
	Aliases   []string `json:"aliases,omitempty"`
	Published string   `json:"published,omitempty"`
	Malicious bool     `json:"malicious"`
}

// Hit is a package with the advisories that match it.
type Hit struct {
	Package    pkgs.Package `json:"package"`
	Advisories []Advisory   `json:"advisories"`
}

type query struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

type batchResp struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
		NextPageToken string `json:"next_page_token"`
	} `json:"results"`
}

// IsMalicious reports whether an OSV id denotes malware rather than a bug.
func IsMalicious(id string, aliases []string) bool {
	if strings.HasPrefix(id, "MAL-") {
		return true
	}
	for _, a := range aliases {
		if strings.HasPrefix(a, "MAL-") {
			return true
		}
	}
	return false
}

// Check queries all packages and returns the ones with matching advisories.
func (c *Client) Check(ctx context.Context, ps []pkgs.Package) ([]Hit, error) {
	ids := make([][]string, len(ps))
	for start := 0; start < len(ps); start += batchSize {
		end := min(start+batchSize, len(ps))
		res, err := c.batch(ctx, ps[start:end])
		if err != nil {
			return nil, err
		}
		for i, r := range res {
			ids[start+i] = r
		}
	}

	// Collect ids that need detail lookups.
	need := map[string]bool{}
	for _, list := range ids {
		for _, id := range list {
			if c.IncludeVulns || strings.HasPrefix(id, "MAL-") {
				need[id] = true
			}
		}
	}
	details := c.fetchAll(ctx, need)

	var hits []Hit
	for i, list := range ids {
		var advs []Advisory
		for _, id := range list {
			a, ok := details[id]
			if !ok {
				if !strings.HasPrefix(id, "MAL-") {
					continue
				}
				a = Advisory{ID: id, Malicious: true}
			}
			if a.Malicious || c.IncludeVulns {
				advs = append(advs, a)
			}
		}
		if len(advs) > 0 {
			hits = append(hits, Hit{Package: ps[i], Advisories: advs})
		}
	}
	return hits, nil
}

func (c *Client) batch(ctx context.Context, ps []pkgs.Package) ([][]string, error) {
	qs := make([]query, len(ps))
	for i, p := range ps {
		qs[i].Package.Name = p.Name
		qs[i].Package.Ecosystem = p.Ecosystem
		qs[i].Version = p.Version
	}
	body, _ := json.Marshal(map[string]any{"queries": qs})
	var out batchResp
	if err := c.post(ctx, "/v1/querybatch", body, &out); err != nil {
		return nil, err
	}
	if len(out.Results) != len(ps) {
		return nil, fmt.Errorf("osv: expected %d results, got %d", len(ps), len(out.Results))
	}
	res := make([][]string, len(ps))
	for i, r := range out.Results {
		for _, v := range r.Vulns {
			res[i] = append(res[i], v.ID)
		}
		// Paged results are only returned for packages with >1000 vulns;
		// malware entries are never that numerous, so we don't follow them.
	}
	return res, nil
}

func (c *Client) fetchAll(ctx context.Context, ids map[string]bool) map[string]Advisory {
	out := map[string]Advisory{}
	var mu sync.Mutex
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for id := range ids {
		wg.Add(1)
		sem <- struct{}{}
		go func(id string) {
			defer wg.Done()
			defer func() { <-sem }()
			var a Advisory
			if err := c.get(ctx, "/v1/vulns/"+id, &a); err != nil {
				return
			}
			a.Malicious = IsMalicious(a.ID, a.Aliases)
			mu.Lock()
			out[id] = a
			mu.Unlock()
		}(id)
	}
	wg.Wait()
	return out
}

func (c *Client) post(ctx context.Context, path string, body []byte, v any) error {
	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, v)
}

func (c *Client) get(ctx context.Context, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.BaseURL+path, nil)
	if err != nil {
		return err
	}
	return c.do(req, v)
}

func (c *Client) do(req *http.Request, v any) error {
	req.Header.Set("User-Agent", "wormsign")
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
			if req.GetBody != nil {
				req.Body, _ = req.GetBody()
			}
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode >= 500 || resp.StatusCode == 429 {
			resp.Body.Close()
			lastErr = fmt.Errorf("osv: %s", resp.Status)
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("osv: %s %s", req.URL.Path, resp.Status)
		}
		return json.NewDecoder(resp.Body).Decode(v)
	}
	return lastErr
}
