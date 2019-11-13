package main

import (
	"runtime"
	"time"
)

func DumpPoll(done, stop chan bool, url, token, dir string, d time.Duration) {
	runtime.GC()
	Info.Printf("Complete GC\n")
	DumpRefresh(url, token, dir)
	for {
		timer := time.NewTimer(d * time.Second)
		select {
		case <-timer.C:
			DumpRefresh(url, token, dir)
		case <-stop:
			done <- true
		}
	}
}

func DumpRefresh(url, token, dir string) {
	ts := time.Now().Unix()
	lastDump, err := GetLastDumpId(ts, url, token)
	if err != nil {
		Error.Printf("Can't get last dump id: %s\n", err.Error())
		return
	}
	if lastDump.Id == "" {
		Error.Println("Last dump Id is empty...")
		return
	}
	Info.Printf("Last dump id: %s\n", lastDump.Id)
	cachedDump, err := ReadCurrentDumpId(dir + "/current")
	if err != nil {
		Error.Printf("Can't read cached dump id: %s\n", err.Error())
		return
	}
	if cachedDump.Id == "" {
		Warning.Println("Cashed dump Id is empty...")
	}
	// two states...
	if lastDump.CRC != cachedDump.CRC {
		Info.Printf("Getting new dump..")
		err := FetchDump(lastDump.Id, dir+"/dump.zip", url, token)
		if err != nil {
			Error.Printf("Can't fetch last dump: %s\n", err.Error())
			return
		}
		Debug.Println("Last dump fetched")
		err = DumpUnzip(dir+"/dump.zip", dir+"/dump.xml")
		if err != nil {
			Error.Printf("Can't extract last dump: %s\n", err.Error())
			return
		}
		Debug.Println("Last dump extracted")
		err = Parse(dir + "/dump.xml")
		if err != nil {
			Error.Printf("Parse error: %s\n", err.Error())
			return
		} else {
			Info.Printf("Dump parsed")
			runtime.GC()
			Info.Printf("Complete GC\n")
		}
		err = WriteCurrentDumpId(dir+"/current", lastDump)
		if err != nil {
			Error.Printf("Can't write currentdump file: %s\n", err.Error())
			return
		}
		Debug.Println("Last dump metainfo saved")
	} else if lastDump.Id != cachedDump.Id {
		Info.Printf("Not changed, but new dump metainfo")
		Parse2(lastDump.UpdateTime)
		runtime.GC()
		Info.Printf("Complete GC\n")
	} else {
		Info.Printf("No new dump")
	}
}
