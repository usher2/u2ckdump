package main

import "time"

func parseTime(s string) int64 {
	if s == "" {
		return 0
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		Error.Printf("Can't parse time: %s (%s)\n", err.Error(), s)
		return 0
	}
	return t.Unix()
}

const parseIncludeTime = "2006-01-02T15:04:05"

func parseTime2(s string) int64 {
	if s == "" {
		return 0
	}
	t, err := time.Parse(parseIncludeTime, s)
	if err != nil {
		Error.Printf("Can't parse time: %s (%s)\n", err.Error(), s)
		return 0
	}
	return t.Unix() - 3600*3
}
