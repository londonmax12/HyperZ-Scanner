package checks

import (
	"context"
	"errors"
	"net/http"

	"github.com/londonmax12/hyperz/internal/httpclient"
	"github.com/londonmax12/hyperz/internal/page"
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

// ErrFetchAlreadyFailed is returned by ensureResponse when the producer
// (typically the crawler) already attempted the GET for p.URL and got
// nothing back: p.Fetched is true but p.Headers is still nil. Checks
// bubble this up; the scanner recognizes it and suppresses the per-check
// onError event, since the crawler already reported the original failure
// once for the URL. Without this, N passive checks against a dead host
// produced 1 crawler error + N duplicate "connection refused" errors and
// N wasted HTTP requests.
var ErrFetchAlreadyFailed = errors.New("hyperz: response unavailable; producer already failed to fetch this URL")

// ensureResponse returns a snapshot for p. When the crawler / no-crawl
// feeder already populated p.Headers, that snapshot is reused as-is and
// no HTTP request fires. When p.Fetched is set but p.Headers is nil the
// producer tried and failed; ensureResponse returns ErrFetchAlreadyFailed
// without issuing a retry. Otherwise the helper issues a GET against
// p.URL and reads up to maxBody bytes of body.
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
	if p.Fetched {
		return snapshot{}, ErrFetchAlreadyFailed
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
