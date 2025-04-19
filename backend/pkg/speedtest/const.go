package speedtest

import "time"

const (
	ChunkSize          = 1048576
	MaxChunkSize       = 1024
	DefaultHTTPTimeout = 3 * time.Second
)
