package core

import "errors"

// ErrFetchAlreadyFailed is returned when a check is asked to inspect a
// URL the producer (typically the crawler) already attempted to GET
// and got nothing back: p.Fetched is true but p.Headers is still nil.
// Checks bubble this up; the scanner recognises it and suppresses the
// per-check onError event, because the crawler already reported the
// original failure once for the URL. Without this, N passive checks
// against a dead host produced 1 crawler error + N duplicate
// "connection refused" errors and N wasted HTTP requests.
var ErrFetchAlreadyFailed = errors.New("hyperz: response unavailable; producer already failed to fetch this URL")
