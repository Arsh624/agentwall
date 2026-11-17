package main

import (
	"syscall"
	"unsafe"
)

// Go's own clock on Windows ticks only every ~0.5 ms, far too coarse for microsecond
// round trips, so read the high-resolution performance counter instead.
var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	qpc      = kernel32.NewProc("QueryPerformanceCounter")
	freq     = func() float64 {
		var f int64
		kernel32.NewProc("QueryPerformanceFrequency").Call(uintptr(unsafe.Pointer(&f)))
		return float64(f)
	}()
)

// micros is a monotonic timestamp in microseconds.
func micros() float64 {
	var c int64
	qpc.Call(uintptr(unsafe.Pointer(&c)))
	return float64(c) * 1e6 / freq
}
