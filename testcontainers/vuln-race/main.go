// vuln-race: deliberately race-able balance-deduct endpoint.
//
// POST /withdraw simulates a money-moving endpoint with a textbook
// TOCTOU split: a fast-path "is there enough budget?" check reads
// balance WITHOUT the lock, the handler then sleeps to simulate work
// (validation, signing, ledger lookup), and only at the end does it
// take the mutex to re-check and deduct. Under sequential traffic
// the locked re-check makes this look idempotent - every caller
// observes the up-to-date balance and the rejection branch fires
// once the budget runs out. Under parallel pressure the racy fast-
// path lets N callers through while they all observe the SAME pre-
// sleep snapshot, but the locked write-out serializes them, so the
// first few find enough budget and 200 while the later ones find
// the freshly-decremented balance and 402. That mixed-status pattern
// in a single parallel batch is exactly the variance the scanner's
// race-condition oracle keys on (>=2 distinct status codes with at
// least one 2xx).
//
// The endpoint is named /withdraw and exposed via a POST form on the
// index page so the crawler discovers a state-changing target whose
// path matches the check's curated keyword gate (withdraw is in the
// money-moving keyword list).
//
// The initial balance is sized at exactly 2 * amount so the scanner's
// pre-batch baseline depletes one slot, the parallel batch's racy
// gate lets all 10 through, and the locked slow path admits exactly
// one more before rejecting the rest - the minimal shape that still
// produces the (1x200, Nx402) histogram the oracle fires on.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const defaultAmount = 60

var (
	balanceMu sync.Mutex
	balance   = defaultAmount * 2
	once      = sync.Once{}
)

func handleWithdraw(w http.ResponseWriter, r *http.Request) {
	amount := defaultAmount
	if a := r.FormValue("amount"); a != "" {
		if n, err := strconv.Atoi(a); err == nil {
			amount = n
		}
	}

	// Racy fast-path: read balance without the lock. Returns 402 only
	// when the budget is visibly already drained from the unlocked
	// caller's perspective; under parallel pressure all N callers
	// snapshot the same pre-sleep value here and the gate is wide
	// open even though only the first few will actually find budget
	// once the lock-protected re-check runs.
	if balance < amount {
		w.WriteHeader(http.StatusPaymentRequired)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "balance": balance})
		return
	}

	// Simulated processing window (auth, ledger lookup, ...). The
	// sleep widens the gap between the fast-path snapshot and the
	// locked write so the single-packet attack can land all N final
	// bytes inside the same TOCTOU window.
	time.Sleep(80 * time.Millisecond)

	// Locked slow path. The mutex makes the deduct itself atomic, so
	// only one caller writes at a time - but the racy fast-path
	// already admitted N, so the late lock-holders find the balance
	// freshly decremented under them and 402.
	balanceMu.Lock()
	defer balanceMu.Unlock()
	if balance < amount {
		w.WriteHeader(http.StatusPaymentRequired)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "balance": balance})
		return
	}
	balance -= amount
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "balance": balance})
}

func handleReset(w http.ResponseWriter, r *http.Request) {
	balanceMu.Lock()
	balance = defaultAmount * 2
	balanceMu.Unlock()
	fmt.Fprintln(w, "reset")
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, `<!doctype html><title>vuln-race</title>
<form method="POST" action="/withdraw">
  <input name="amount" value="60">
  <button type="submit">withdraw</button>
</form>
<a href="/reset">reset</a>`)
	})
	mux.HandleFunc("/withdraw", handleWithdraw)
	mux.HandleFunc("/reset", handleReset)

	once.Do(func() { fmt.Println("vuln-race on :8084") })
	_ = http.ListenAndServe(":8084", mux)
}
