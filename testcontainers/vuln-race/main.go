// vuln-race: deliberately race-able balance-deduct endpoint.
//
// The "balance" lives in process memory. /spend reads the balance,
// pauses briefly to widen the TOCTOU window, then writes back the
// post-deduct value with NO lock. Parallel requests for the same
// coupon all clear the read-balance check and all decrement, so the
// final balance goes negative and multiple callers see a 200 OK
// when only one should have. The scanner's race-condition check
// observes that >=2 distinct status codes (or a balance that
// shouldn't be possible) come back from a single-packet attack and
// confirms.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

var (
	balance int = 100
	once        = sync.Once{}
)

func handleSpend(w http.ResponseWriter, r *http.Request) {
	amount := 60
	if a := r.URL.Query().Get("amount"); a != "" {
		if n, err := strconv.Atoi(a); err == nil {
			amount = n
		}
	}

	// Deliberate TOCTOU window: read, sleep, write. No lock.
	current := balance
	time.Sleep(80 * time.Millisecond)
	if current < amount {
		w.WriteHeader(http.StatusPaymentRequired)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "balance": current})
		return
	}
	balance = current - amount
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "balance": balance})
}

func handleReset(w http.ResponseWriter, r *http.Request) {
	balance = 100
	fmt.Fprintln(w, "reset")
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintln(w, `<!doctype html><title>vuln-race</title>
<a href="/spend?amount=60">spend</a>
<a href="/reset">reset</a>`)
	})
	mux.HandleFunc("/spend", handleSpend)
	mux.HandleFunc("/reset", handleReset)

	once.Do(func() { fmt.Println("vuln-race on :8084") })
	_ = http.ListenAndServe(":8084", mux)
}
