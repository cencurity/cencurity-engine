//go:build windows

package loadtest

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32        = syscall.NewLazyDLL("kernel32.dll")
	getProcessTimes = kernel32.NewProc("GetProcessTimes")
)

func processCPUTime() (time.Duration, error) {
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0, fmt.Errorf("GetCurrentProcess: %w", err)
	}
	var creation syscall.Filetime
	var exit syscall.Filetime
	var kernel syscall.Filetime
	var user syscall.Filetime
	result, _, callErr := getProcessTimes.Call(
		uintptr(process),
		uintptr(unsafe.Pointer(&creation)),
		uintptr(unsafe.Pointer(&exit)),
		uintptr(unsafe.Pointer(&kernel)),
		uintptr(unsafe.Pointer(&user)),
	)
	if result == 0 {
		return 0, fmt.Errorf("GetProcessTimes: %w", callErr)
	}
	return filetimeDuration(kernel) + filetimeDuration(user), nil
}

func filetimeDuration(value syscall.Filetime) time.Duration {
	const hundredNanoseconds = 100
	count := (uint64(value.HighDateTime) << 32) | uint64(value.LowDateTime)
	return time.Duration(count*hundredNanoseconds) * time.Nanosecond
}
