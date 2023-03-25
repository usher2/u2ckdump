package main

import (
	"io"
	"os"
	"testing"

	"github.com/usher2/u2ckdump/internal/logger"
)

func init() {
	logger.LogInit(io.Discard, os.Stdout, os.Stderr, os.Stderr)
}

// TestParseRFC3339Time tests the parseRFC3339Time function.
func TestParseRFC3339Time(t *testing.T) {
	tests := []struct {
		name        string
		timeStr     string
		expectedVal int64
	}{
		{"Valid RFC3339 Time", "2023-03-25T12:34:56Z", 1679747696},
		{"Empty String", "", 0},
		{"Invalid Time String", "invalid_time", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseRFC3339Time(tt.timeStr)
			if result != tt.expectedVal {
				t.Errorf("Expected %d, got %d", tt.expectedVal, result)
			}
		})
	}
}

// TestParseMoscowTime tests the parseMoscowTime function.
func TestParseMoscowTime(t *testing.T) {
	tests := []struct {
		name        string
		timeStr     string
		expectedVal int64
	}{
		{"Valid Moscow Time", "2023-03-25T15:34:56", 1679747696},
		{"Empty String", "", 0},
		{"Invalid Time String", "invalid_time", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseMoscowTime(tt.timeStr)
			if result != tt.expectedVal {
				t.Errorf("Expected %d, got %d", tt.expectedVal, result)
			}
		})
	}
}
