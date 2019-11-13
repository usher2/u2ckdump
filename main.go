package main

import (
	"flag"
	"io/ioutil"
	//"log"
	//"net/http"
	//_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
)

func main() {
	debug.SetGCPercent(20)
	//go func() {
	//	log.Println(http.ListenAndServe("localhost:6060", nil))
	//}()
	confAPIURL := flag.String("u", "https://example.com", "Dump API URL")
	confAPIKey := flag.String("k", "xxxxxxxxxyyyyyyyyyyzzzzzzzzzqqqqqqqqqwwwwwwweeeeeeeerrrrrrrrrttt", "Dump API Key")
	confDumpCacheDir := flag.String("d", "res", "Dump cache dir")
	confLogLevel := flag.String("l", "Debug", "Logging level")
	flag.Parse()
	if *confLogLevel == "Info" {
		logInit(ioutil.Discard, os.Stdout, os.Stderr, os.Stderr)
	} else if *confLogLevel == "Warning" {
		logInit(ioutil.Discard, ioutil.Discard, os.Stderr, os.Stderr)
	} else if *confLogLevel == "Error" {
		logInit(ioutil.Discard, ioutil.Discard, ioutil.Discard, os.Stderr)
	} else {
		logInit(os.Stderr, os.Stdout, os.Stderr, os.Stderr)
	}
	if _, err := os.Stat(*confDumpCacheDir + "/current"); !os.IsNotExist(err) {
		err := os.Remove(*confDumpCacheDir + "/current") // remove cache
		if err != nil {
			Error.Printf("Can't remove cache file: %s", err.Error())
			os.Exit(1)
		}
	}
	if _, err := os.Stat(*confDumpCacheDir + "/dump.zip"); !os.IsNotExist(err) {
		Debug.Println("Zipped dump detecteded")
		err = DumpUnzip(*confDumpCacheDir+"/dump.zip", *confDumpCacheDir+"/dump.xml")
		if err != nil {
			Error.Printf("Can't extract last dump: %s\n", err.Error())
		} else {
			Debug.Println("Dump extracted")
		}
	}
	if _, err := os.Stat(*confDumpCacheDir + "/dump.xml"); !os.IsNotExist(err) {
		Debug.Println("Saved dump detecteded")
		err = Parse(*confDumpCacheDir + "/dump.xml")
		if err != nil {
			Error.Printf("Parse error: %s\n", err.Error())
		} else {
			Info.Printf("Dump parsed")
		}
	}
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	stop := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go DumpPoll(done, stop, *confAPIURL, *confAPIKey, *confDumpCacheDir, 60)
	<-sigs
	stop <- true
	<-done
	Warning.Printf("Exiting...")
}
