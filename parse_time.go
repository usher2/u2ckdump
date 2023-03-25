package main

import (
	"time"

	"github.com/usher2/u2ckdump/internal/logger"
)

// Provides functions to parse RFC3339 time strings into Unix timestamps.
// It supports parsing time strings in the Moscow timezone and without a timezone specified.

// locationMSK represents the Moscow timezone.
var locationMSK *time.Location

// init initializes the Moscow timezone.
func init() {
	var err error

	locationMSK, err = time.LoadLocation("Europe/Moscow")
	if err != nil {
		panic(err)
	}
}

// parseRFC3339Time converts an RFC3339 time string to a Unix timestamp.
// Returns 0 if the input string is empty or the parsing fails.
func parseRFC3339Time(s string) int64 {
	if s == "" {
		return 0
	}

	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		// logger.Error.Printf("Can't parse time: %s (%s)\n", err, s)
		return 0
	}

	return t.Unix()
}

// parseIncludeTime is a format for parsing RFC3339-like time strings without a timezone.
const parseIncludeTime = "2006-01-02T15:04:05"

// parseMoscowTime converts an RFC3339-like time string in the Moscow timezone to a Unix timestamp.
// Returns 0 if the input string is empty or the parsing fails.
func parseMoscowTime(s string) int64 {
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
