package main

import (
	"flag"
	"io/ioutil"

	//"log"
	//"net/http"
	//_ "net/http/pprof"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	pb "github.com/usher2/u2ckdump/msg"
	"google.golang.org/grpc"
)

func main() {
	debug.SetGCPercent(20)
	//go func() {
	//	log.Println(http.ListenAndServe("localhost:6060", nil))
	//}()
	confAPIURL := flag.String("u", "https://example.com", "Dump API URL")
	confAPIKey := flag.String("k", "xxxxxxxxxyyyyyyyyyyzzzzzzzzzqqqqqqqqqwwwwwwweeeeeeeerrrrrrrrrttt", "Dump API Key")
	confPBPort := flag.String("p", "50001", "gRPC port")
	confDumpCacheDir := flag.String("d", "res", "Dump cache dir")
	confLogLevel := flag.String("l", "Debug", "Logging level")
	flag.Parse()
	switch *confLogLevel {
	case "Info":
		logInit(ioutil.Discard, os.Stdout, os.Stderr, os.Stderr)
	case "Warning":
		logInit(ioutil.Discard, ioutil.Discard, os.Stderr, os.Stderr)
	case "Error":
		logInit(ioutil.Discard, ioutil.Discard, ioutil.Discard, os.Stderr)
	default:
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
		Info.Println("Zipped dump detecteded")
		err = DumpUnzip(*confDumpCacheDir+"/dump.zip", *confDumpCacheDir+"/dump.xml")
		if err != nil {
			Error.Printf("Can't extract last dump: %s\n", err.Error())
		} else {
			Info.Println("Dump extracted")
		}
	}
	if _, err := os.Stat(*confDumpCacheDir + "/dump.xml"); !os.IsNotExist(err) {
		Info.Println("Saved dump detecteded")
		// parse xml
		if dumpFile, err := os.Open(*confDumpCacheDir + "/dump.xml"); err != nil {
			Error.Printf("Can't open last dump: %s\n", err.Error())
		} else {
			err = Parse(dumpFile)
			if err != nil {
				Error.Printf("Parse error: %s\n", err.Error())
			} else {
				Info.Printf("Dump parsed")
			}
			dumpFile.Close()
		}
	}
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	lis, err := net.Listen("tcp", ":"+*confPBPort)
	if err != nil {
		Error.Printf("Failed to listen: %s\n", err.Error())
		os.Exit(1)
	}
	s := grpc.NewServer()
	pb.RegisterCheckServer(s, &server{})
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go DumpPoll(s, done, sigs, *confAPIURL, *confAPIKey, *confDumpCacheDir, 60)
	if err := s.Serve(lis); err != nil {
		Error.Printf("Failed to serve: %v", err.Error())
		os.Exit(1)
	}
	<-done
	Warning.Printf("Exiting...")
}
