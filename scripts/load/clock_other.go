//go:build !windows

package main

import "time"

var epoch = time.Now()

// micros is a monotonic timestamp in microseconds.
func micros() float64 { return float64(time.Since(epoch).Nanoseconds()) / 1000 }
