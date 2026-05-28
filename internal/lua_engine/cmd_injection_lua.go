package lua_engine

import "time"

// This file exposes the cmd-injection check's helpers to the Lua
// bridge. Sibling to cmd_injection.go: forwards into the package-
// private timing knobs + sink-value filler so a test that flips the
// Go side flips the Lua port in lockstep.

// CmdInjectionSleepSeconds / CmdInjectionMargin expose the cmd-
// injection timing oracle. Same rationale as the sqli-time pair:
// tests flip the Go side and the Lua port follows in lockstep.
func CmdInjectionSleepSeconds() int { return int(cmdInjectionSleep / 1e9) }
func CmdInjectionMargin() float64   { return cmdInjectionMargin }

// SetCmdInjectionTuningForTest lets the checks_lua parity tests dial
// the production timing knobs down to test-friendly values without
// each test reaching into private vars.
func SetCmdInjectionTuningForTest(sleepSecs int, margin float64) (restore func()) {
	prevSleep, prevMargin := cmdInjectionSleep, cmdInjectionMargin
	cmdInjectionSleep = time.Duration(sleepSecs) * time.Second
	cmdInjectionMargin = margin
	return func() {
		cmdInjectionSleep = prevSleep
		cmdInjectionMargin = prevMargin
	}
}

// CmdInjectionFillerValue exposes the filler the cmd-injection checks
// substitute for an empty sink.Value before payload append. Empty
// originals leave the payload without a leading character; anchoring
// with "1" turns `param=` into `param=1; sleep 5`, which executes.
func CmdInjectionFillerValue() string { return cmdInjectionFillerValue }
