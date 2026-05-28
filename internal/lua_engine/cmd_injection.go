package lua_engine

import "time"

// cmdInjectionFillerValue replaces an empty sink.Value so the payload
// still has a leading byte to land against. Shell commands usually
// tolerate empty arguments, but a missing value can break the host
// command's parse before our injection separator fires.
const cmdInjectionFillerValue = "1"

// cmdInjectionSleep is the duration each {{SLEEP}} placeholder resolves
// to. Same tradeoff as sqliTimeSleep - long enough to clearly exceed
// jitter, short enough that confirmation doubles the wall time without
// blowing through the budget. Package var so tests can dial it down to
// 1s and avoid pinning the suite on real sleeps.
var cmdInjectionSleep = 5 * time.Second

// cmdInjectionMargin is the slack TimingCompare allows. 0.3 = >=70%
// of the requested sleep must land. Package var so tests can widen
// the margin on a fast loopback server.
var cmdInjectionMargin = 0.3
