package lua_engine

import "time"

// sqliTimeSleep is the duration each {{SLEEP}} placeholder resolves to.
// Long enough to clearly exceed normal jitter (sub-second) but short
// enough that two confirming probes on a vulnerable sink cost ~10s of
// wall time, not minutes. Package var so tests can dial it down to 1s
// and avoid pinning the suite on real sleeps.
var sqliTimeSleep = 5 * time.Second

// sqliTimeMargin is the fraction of sqliTimeSleep TimingCompare is
// allowed to "lose" to noise. 0.3 = require >=70% of the requested sleep
// landed. Matches the oracle's documented guidance. Package var so
// tests can widen the margin when running against a fast loopback
// server where the "expected" delay is dominated by the sleep itself.
var sqliTimeMargin = 0.3
