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

func SetVerbose(enabled bool) {
	verbose = enabled
	if enabled && debugLog == nil {
		debugLog = log.New(os.Stderr, "", log.LstdFlags|log.Lmicroseconds)
	}
}

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

// SafeGo recovers a panic inside fn and logs it instead of taking down the whole process - for a long-lived background loop nothing else on the stack would catch it.
func SafeGo(name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				Debugf("[PANIC] recovered in %s: %v", name, r)
			}
		}()
		fn()
	}()
}
