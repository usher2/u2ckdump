package main

import (
	"flag"
	"io"

	//"log"
	//"net/http"
	//_ "net/http/pprof"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"google.golang.org/grpc"

	"github.com/usher2/u2ckdump/internal/logger"
	pb "github.com/usher2/u2ckdump/msg"
)

func main() {
	debug.SetGCPercent(20)
	//go func() {
	//	logger.Println(http.ListenAndServe("localhost:6060", nil))
	//}()
	confAPIURL := flag.String("u", "https://example.com", "Dump API URL")
	confAPIKey := flag.String("k", "xxxxxxxxxyyyyyyyyyyzzzzzzzzzqqqqqqqqqwwwwwwweeeeeeeerrrrrrrrrttt", "Dump API Key")
	confPBPort := flag.String("p", "50001", "gRPC port")
	confDumpCacheDir := flag.String("d", "res", "Dump cache dir")
	confLogLevel := flag.String("l", "Debug", "Logging level")
	flag.Parse()
	switch *confLogLevel {
	case "Info":
		logger.LogInit(io.Discard, os.Stdout, os.Stderr, os.Stderr)
	case "Warning":
		logger.LogInit(io.Discard, io.Discard, os.Stderr, os.Stderr)
	case "Error":
		logger.LogInit(io.Discard, io.Discard, io.Discard, os.Stderr)
	default:
		logger.LogInit(os.Stderr, os.Stdout, os.Stderr, os.Stderr)
	}
	if _, err := os.Stat(*confDumpCacheDir + "/current"); !os.IsNotExist(err) {
		err := os.Remove(*confDumpCacheDir + "/current") // remove cache
		if err != nil {
			logger.Error.Printf("Can't remove cache file: %s", err.Error())
			os.Exit(1)
		}
	}
	if _, err := os.Stat(*confDumpCacheDir + "/dump.zip"); !os.IsNotExist(err) {
		logger.Info.Println("Zipped dump detecteded")
		err = DumpUnzip(*confDumpCacheDir+"/dump.zip", *confDumpCacheDir+"/dump.xml")
		if err != nil {
			logger.Error.Printf("Can't extract last dump: %s\n", err.Error())
		} else {
			logger.Info.Println("Dump extracted")
		}
	}
	if _, err := os.Stat(*confDumpCacheDir + "/dump.xml"); !os.IsNotExist(err) {
		logger.Info.Println("Saved dump detecteded")
		// parse xml
		if dumpFile, err := os.Open(*confDumpCacheDir + "/dump.xml"); err != nil {
			logger.Error.Printf("Can't open last dump: %s\n", err.Error())
		} else {
			err = Parse(dumpFile)
			if err != nil {
				logger.Error.Printf("Parse error: %s\n", err.Error())
			} else {
				logger.Info.Printf("Dump parsed")
			}
			dumpFile.Close()
		}
	}

	listen, err := net.Listen("tcp", ":"+*confPBPort)
	if err != nil {
		logger.Error.Printf("Failed to listen: %s\n", err.Error())
		os.Exit(1)
	}

	serverGRPC := grpc.NewServer()
	pb.RegisterCheckServer(serverGRPC, &server{})

	quit := make(chan os.Signal, 1)
	done := make(chan struct{})
	killPoll := make(chan struct{})
	donePoll := make(chan struct{})

	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-quit

		close(killPoll)

		serverGRPC.GracefulStop()

		<-donePoll

		close(done)
	}()

	go DumpPoll(serverGRPC, donePoll, killPoll, *confAPIURL, *confAPIKey, *confDumpCacheDir, 60)

	if err := serverGRPC.Serve(listen); err != nil {
		logger.Error.Printf("Failed to serve: %v", err.Error())
		os.Exit(1)
	}

	<-done

	logger.Warning.Printf("Exiting...")
}
