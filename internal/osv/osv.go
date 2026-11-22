// Package osv checks packages against OSV.dev's malicious-package feed.
//
// OSV supplies advisory IDs in batches; detail records identify malware aliases.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
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
	Version   string `json:"version"`
	PageToken string `json:"page_token,omitempty"`
}

type batchResp struct {
	Results []*struct {
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
	var batchErr error
	for start := 0; start < len(ps); start += batchSize {
		end := min(start+batchSize, len(ps))
		res, err := c.batch(ctx, ps[start:end])
		for i, r := range res {
			ids[start+i] = r
		}
		if err != nil {
			batchErr = err
			break
		}
	}

	// Collect ids that need detail lookups.
	need := map[string]bool{}
	for _, list := range ids {
		for _, id := range list {
			need[id] = true
		}
	}
	details, detailErr := c.fetchAll(ctx, need)

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
	return hits, errors.Join(batchErr, detailErr)
}

func (c *Client) batch(ctx context.Context, ps []pkgs.Package) ([][]string, error) {
	qs := make([]query, len(ps))
	for i, p := range ps {
		qs[i].Package.Name = p.Name
		qs[i].Package.Ecosystem = p.Ecosystem
		qs[i].Version = p.Version
	}
	res := make([][]string, len(ps))
	indexes := make([]int, len(ps))
	for i := range indexes {
		indexes[i] = i
	}
	seenTokens := make([]map[string]bool, len(ps))
	for len(qs) > 0 {
		body, _ := json.Marshal(map[string]any{"queries": qs})
		var out batchResp
		if err := c.post(ctx, "/v1/querybatch", body, &out); err != nil {
			return res, err
		}
		if len(out.Results) != len(qs) {
			return res, fmt.Errorf("osv: expected %d results, got %d", len(qs), len(out.Results))
		}
		var next []query
		var nextIndexes []int
		for i, r := range out.Results {
			index := indexes[i]
			if r == nil {
				return res, fmt.Errorf("osv: null result for %s", ps[index].String())
			}
			for _, v := range r.Vulns {
				if !slices.Contains(res[index], v.ID) {
					res[index] = append(res[index], v.ID)
				}
			}
			if token := r.NextPageToken; token != "" {
				if seenTokens[index] == nil {
					seenTokens[index] = map[string]bool{}
				}
				if seenTokens[index][token] {
					return res, fmt.Errorf("osv: repeated page token for %s", ps[index].String())
				}
				seenTokens[index][token] = true
				q := qs[i]
				q.PageToken = token
				next = append(next, q)
				nextIndexes = append(nextIndexes, index)
			}
		}
		qs, indexes = next, nextIndexes
	}
	return res, nil
}

func (c *Client) fetchAll(ctx context.Context, ids map[string]bool) (map[string]Advisory, error) {
	var errs []error
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
			err := c.get(ctx, "/v1/vulns/"+url.PathEscape(id), &a)
			if err == nil && (id == "" || a.ID != id) {
				err = fmt.Errorf("response advisory ID does not match requested ID")
			}
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("osv: advisory %s: %w", id, err))
				mu.Unlock()
				return
			}
			a.Malicious = IsMalicious(a.ID, a.Aliases)
			mu.Lock()
			out[id] = a
			mu.Unlock()
		}(id)
	}
	wg.Wait()
	return out, errors.Join(errs...)
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
		if err := req.Context().Err(); err != nil {
			return err
		}
		if attempt > 0 {
			select {
			case <-req.Context().Done():
				return req.Context().Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
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
