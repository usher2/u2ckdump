package main

import (
	"os"
	"runtime"
	"time"

	"google.golang.org/grpc"
)

// DumpPoll - poll "vygruzki" service for new dumps.
func DumpPoll(s *grpc.Server, done chan bool, sigs chan os.Signal, url, token, dir string, d time.Duration) {
	timer := time.NewTimer(time.Millisecond)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			DumpRefresh(url, token, dir)
		case <-sigs:
			done <- true
		}

		timer.Reset(d * time.Second)
	}
}

// DumpRefresh - try to fetch new dump.
func DumpRefresh(url, token, dir string) {
	ts := time.Now().Unix()

	lastDump, err := GetLastDumpID(ts, url, token)
	if err != nil {
		Error.Printf("Can't get last dump id: %s\n", err.Error())

		return
	}

	if lastDump.ID == "" {
		Error.Println("Last dump Id is empty...")

		return
	}

	Info.Printf("Last dump id: %s\n", lastDump.ID)

	cachedDump, err := ReadCurrentDumpID(dir + "/current")
	if err != nil {
		Error.Printf("Can't read cached dump id: %s\n", err.Error())

		// TODO: investigate thi case.
		//return
	}

	if cachedDump.ID == "" {
		Warning.Println("Cashed dump Id is empty...")
	}

	// TDO: Why hear?
	defer runtime.GC()

	// two states...
	switch {
	case lastDump.CRC != cachedDump.CRC:
		Info.Printf("Getting new dump..")

		err := FetchDump(lastDump.ID, dir+"/dump.zip", url, token)
		if err != nil {
			Error.Printf("Can't fetch last dump: %s\n", err.Error())

			return
		}

		Info.Println("Last dump fetched")

		err = DumpUnzip(dir+"/dump.zip", dir+"/dump.xml")
		if err != nil {
			Error.Printf("Can't extract last dump: %s\n", err.Error())

			return
		}

		Info.Println("Last dump extracted")

		// parse xml
		dumpFile, err := os.Open(dir + "/dump.xml")
		if err != nil {
			Error.Printf("Can't open dump file: %s\n", err.Error())

			return
		}

		defer dumpFile.Close()

		err = Parse(dumpFile)
		if err != nil {
			Error.Printf("Parse error: %s\n", err.Error())

			return
		}

		Info.Printf("Dump parsed")

		err = WriteCurrentDumpID(dir+"/current", lastDump)
		if err != nil {
			Error.Printf("Can't write currentdump file: %s\n", err.Error())

			return
		}

		Info.Println("Last dump metainfo saved")
	case lastDump.ID != cachedDump.ID:
		Info.Printf("Not changed, but new dump metainfo")

		Parse2(lastDump.UpdateTime)
	default:
		Info.Printf("No new dump")
	}
}
