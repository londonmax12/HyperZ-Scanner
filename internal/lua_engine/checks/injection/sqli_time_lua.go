package injection

import "time"

// This file exposes the sqli-time check's helpers to the Lua bridge.
// Sibling to sqli_time.go: forwards into the package-private timing
// knobs so a test that calls SetSQLiTimeTuningForTest flips both
// implementations to the same fast value in lockstep.

// SQLiTimeSleepSeconds / SQLiTimeMargin expose the Go side's test-
// tunable timing knobs to the Lua port. Lua checks read these every
// Run so a test that calls SetSQLiTimeSleepForTest (in the Go test
// helper file) flips both implementations to the same fast value
// without each side hand-rolling its own override path.
func SQLiTimeSleepSeconds() int { return int(sqliTimeSleep / 1e9) }
func SQLiTimeMargin() float64   { return sqliTimeMargin }

// SetSQLiTimeTuningForTest lets the checks_lua parity tests dial the
// production timing knobs down to test-friendly values without each
// test reaching into private vars.
func SetSQLiTimeTuningForTest(sleepSecs int, margin float64) (restore func()) {
	prevSleep, prevMargin := sqliTimeSleep, sqliTimeMargin
	sqliTimeSleep = time.Duration(sleepSecs) * time.Second
	sqliTimeMargin = margin
	return func() {
		sqliTimeSleep = prevSleep
		sqliTimeMargin = prevMargin
	}
}
