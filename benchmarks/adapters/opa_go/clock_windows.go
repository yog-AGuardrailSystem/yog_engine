//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

var (
	kernel32      = syscall.NewLazyDLL("kernel32.dll")
	procCounter   = kernel32.NewProc("QueryPerformanceCounter")
	procFrequency = kernel32.NewProc("QueryPerformanceFrequency")
	qpcFrequency  int64
)

func init() {
	if result, _, _ := procFrequency.Call(uintptr(unsafe.Pointer(&qpcFrequency))); result == 0 {
		panic("QueryPerformanceFrequency failed")
	}
}

// nowNs returns a monotonic timestamp from QueryPerformanceCounter.  Go's
// time.Now has coarse resolution on some Windows hosts, which is unusable for
// microsecond-scale policy decisions.
func nowNs() int64 {
	var counter int64
	if result, _, _ := procCounter.Call(uintptr(unsafe.Pointer(&counter))); result == 0 {
		panic("QueryPerformanceCounter failed")
	}
	return counter * 1_000_000_000 / qpcFrequency
}
