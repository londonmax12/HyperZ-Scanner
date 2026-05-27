//go:build integration

package testcontainers

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
)

// progressWriter is the stream live test progress is sent to. It is
// resolved lazily on first use:
//
//   - Unix:    /dev/tty
//   - Windows: CONOUT$
//   - fallback (no controlling terminal, e.g. CI): os.Stderr
//
// The point is to bypass `go test`'s per-test stdout/stderr capture
// so messages stream as each container's scan happens. Without this
// hack, `go test` (sans -v) buffers everything until the test exits
// and only emits it on failure - which is exactly the wrong shape
// when the user is staring at a 15-minute integration run waiting
// to see which container finished.
//
// Resolved once via sync.Once so a long suite doesn't open a new fd
// per progress() call.
var (
	progressOnce   sync.Once
	progressWriter io.Writer
)

func progress(msg string) {
	progressOnce.Do(func() {
		var tty *os.File
		var err error
		switch runtime.GOOS {
		case "windows":
			tty, err = os.OpenFile("CONOUT$", os.O_RDWR, 0)
		default:
			tty, err = os.OpenFile("/dev/tty", os.O_RDWR, 0)
		}
		if err != nil || tty == nil {
			progressWriter = os.Stderr
			return
		}
		progressWriter = tty
	})
	fmt.Fprintln(progressWriter, msg)
}
