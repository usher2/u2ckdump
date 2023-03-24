package main

import (
	"time"

	"github.com/usher2/u2ckdump/internal/logger"
)

// locationMSK - Moscow timezone.
var locationMSK *time.Location

// Set the Moscow timezone at init time.
func init() {
	var err error

	locationMSK, err = time.LoadLocation("Europe/Moscow")
	if err != nil {
		panic(err)
	}
}

// ParseTime - parse RFC3339 time string to unix timestamp.
func parseTime(s string) int64 {
	if s == "" {
		return 0
	}

	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		logger.Error.Printf("Can't parse time: %s (%s)\n", err, s)

		return 0
	}

	return t.Unix()
}

// parseIncludeTime - time format for parsing RFC3339 like time withouth timezone.
const parseIncludeTime = "2006-01-02T15:04:05"

// ParseTime2 - parse RFC3339 like time string in Moscow timezone to unix timestamp.
func parseTime2(s string) int64 {
	if s == "" {
		return 0
	}

	t, err := time.ParseInLocation(parseIncludeTime, s, locationMSK)
	if err != nil {
		logger.Error.Printf("Can't parse time: %s (%s)\n", err, s)

		return 0
	}

	return t.Unix()
}
