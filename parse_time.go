package main

import "time"

var locationMSK *time.Location

func init() {
	var err error

	locationMSK, err = time.LoadLocation("Europe/Moscow")
	if err != nil {
		panic(err)
	}
}

func parseTime(s string) int64 {
	if s == "" {
		return 0
	}

	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		Error.Printf("Can't parse time: %s (%s)\n", err, s)

		return 0
	}

	return t.Unix()
}

const parseIncludeTime = "2006-01-02T15:04:05"

func parseTime2(s string) int64 {
	if s == "" {
		return 0
	}

	t, err := time.ParseInLocation(parseIncludeTime, s, locationMSK)
	if err != nil {
		Error.Printf("Can't parse time: %s (%s)\n", err, s)

		return 0
	}

	return t.Unix()
}
