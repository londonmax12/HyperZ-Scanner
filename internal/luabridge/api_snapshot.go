package luabridge

import (
	"net/http"

	"github.com/londonmax12/hyperz/internal/checks"
	"github.com/londonmax12/hyperz/internal/httpclient"
)

// snapshot is the bridge-internal mirror of the Go checks helper
// of the same shape: status / headers / body together. The fields
// are exposed back to Lua as a plain table from ctx:ensure_response,
// so this struct only exists to keep the Go binding code clean.
type snapshot struct {
	status  int
	headers http.Header
	body    []byte
}

// callEnsureResponse implements the same contract the checks package
// uses internally: reuse the producer's snapshot when available, fall
// back to a fresh GET when no fetch has happened, and propagate
// ErrFetchAlreadyFailed when the producer tried and failed. Lua
// authors call ctx:ensure_response which routes here.
//
// maxBody applies only on the fetch path. When the snapshot comes
// from the page artifact, body is whatever the producer captured
// (bounded by the crawler's MaxBodyBytes). Pass 0 if the check only
// needs headers - the typical passive-check shape.
func callEnsureResponse(env *runEnv, maxBody int64) (snapshot, error) {
	p := env.page
	if p.Headers != nil {
		return snapshot{status: p.Status, headers: p.Headers, body: p.Body}, nil
	}
	if p.Fetched {
		return snapshot{}, checks.ErrFetchAlreadyFailed
	}
	resp, err := env.client.Get(env.ctx, p.URL)
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
	return snapshot{status: resp.StatusCode, headers: resp.Header, body: body}, nil
}
