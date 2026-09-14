package utils

import (
	"fmt"
	"log"
	"os"
	"sync"
)

var (
	debugLog *log.Logger
	verbose  bool
	sinkMu   sync.RWMutex
	sink     func(string)
)

func EnableDebug() {
	verbose = true
	debugLog = log.New(os.Stderr, "", log.LstdFlags|log.Lmicroseconds)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
}

// SetVerbose is EnableDebug but reversible - used where a caller (mobile.go)
// needs to turn logging on or off per session rather than for the process's
// whole life.
func SetVerbose(enabled bool) {
	verbose = enabled
	if enabled && debugLog == nil {
		debugLog = log.New(os.Stderr, "", log.LstdFlags|log.Lmicroseconds)
	}
}

// SetLogSink additionally forwards every Debugf line to fn (e.g. to a
// mobile.Callback), on top of the normal stderr output. nil clears it.
func SetLogSink(fn func(string)) {
	sinkMu.Lock()
	sink = fn
	sinkMu.Unlock()
}

func Debugf(format string, args ...interface{}) {
	if !verbose {
		return
	}
	line := fmt.Sprintf(format, args...)
	debugLog.Output(2, line)

	sinkMu.RLock()
	fn := sink
	sinkMu.RUnlock()
	if fn != nil {
		fn(line)
	}
}

func IsVerbose() bool {
	return verbose
}
