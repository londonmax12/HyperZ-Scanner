package checks

import (
	"context"
	"net/http"

	"github.com/londonball/hyperz/internal/httpclient"
	"github.com/londonball/hyperz/internal/page"
)

// snapshot is the per-URL response a check inspects: status, headers, and
// (optionally) body. It deliberately mirrors the subset of *http.Response
// every passive check actually reads, so checks don't have to keep a live
// response open while they iterate findings.
type snapshot struct {
	Status  int
	Headers http.Header
	Body    []byte
}

// ensureResponse returns a snapshot for p. When the crawler / no-crawl
// feeder already populated p.Headers, that snapshot is reused as-is and
// no HTTP request fires. Otherwise the helper issues a GET against p.URL
// and reads up to maxBody bytes of body.
//
// maxBody applies only on the fetch path; when the snapshot comes from p,
// body is whatever the producer captured (bounded by the crawler's
// MaxBodyBytes). Pass maxBody=0 if you only need headers.
//
// This is the load-bearing helper that lets the Page rewrite pay off:
// instead of 5 checks each GET'ing every URL, the crawler's single GET
// is reused by every passive check downstream.
func ensureResponse(ctx context.Context, client *httpclient.Client, p page.Page, maxBody int64) (snapshot, error) {
	if p.Headers != nil {
		return snapshot{
			Status:  p.Status,
			Headers: p.Headers,
			Body:    p.Body,
		}, nil
	}
	resp, err := client.Get(ctx, p.URL)
	if err != nil {
		return snapshot{}, err
	}
	defer resp.Body.Close()
	var body []byte
	if maxBody > 0 {
		body, err = httpclient.ReadBody(resp, maxBody)
		if err != nil {
			return snapshot{}, err
		}
	}
	return snapshot{
		Status:  resp.StatusCode,
		Headers: resp.Header,
		Body:    body,
	}, nil
}
