package loadtest

import "time"

// Config controls a synthetic direct-vs-proxy load test run.
type Config struct {
	Concurrency      []int
	RequestsPerWorker int
	Chunks           int
	ChunkBytes       int
	RequestTimeout   time.Duration
}

// Summary captures load-test results for one scenario.
type Summary struct {
	Name             string
	Concurrency      int
	TotalRequests    int
	Successes        int
	Timeouts         int
	Disconnects      int
	ParseFailures    int
	OtherFailures    int
	Min              time.Duration
	Max              time.Duration
	P50              time.Duration
	P95              time.Duration
	P99              time.Duration
	Mean             time.Duration
	ThroughputRPS    float64
	WallTime         time.Duration
	PeakHeapBytes    uint64
	ApproxCPUPercent float64
}

// Comparison captures proxy overhead relative to direct calls.
type Comparison struct {
	Concurrency         int
	Direct              Summary
	Proxy               Summary
	MeanLatencyIncrease time.Duration
	P95LatencyIncrease  time.Duration
	ThroughputDropPct   float64
}

// ActionStats captures observed policy-path counts for live shadow runs.
type ActionStats struct {
	Allow int
	Redact int
	Block int
}
