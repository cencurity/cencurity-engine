//go:build !windows

package loadtest

import "time"

func processCPUTime() (time.Duration, error) {
	return 0, nil
}
