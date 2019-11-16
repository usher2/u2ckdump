package main

//go:generate protoc -I msg --go_out=plugins=grpc:msg msg/msg.proto

import (
	"context"
	"fmt"

	pb "github.com/usher-2/u2ckdump/msg"
)

type server struct {
	pb.UnimplementedCheckServer
}

func (s *server) SearchIP4(ctx context.Context, in *pb.IP4Request) (*pb.SearchResponse, error) {
	query := in.GetQuery()
	fmt.Printf("Received IPv4: %d.%d.%d.%d\n", (query&0xFF000000)>>24, (query&0x00FF0000)>>16, (query&0x0000FF00)>>8, query&0x000000FF)
	if DumpSnap != nil && DumpSnap.utime > 0 {
		DumpSnap.Content.RLock()
		r := &pb.SearchResponse{}
		v := DumpSnap.ip[query]
		r.Results = make([]*pb.Content, len(v))
		i := 0
		for id, _ := range v {
			r.Results[i] = DumpSnap.Content.C[id]
			i++
		}
		DumpSnap.Content.RUnlock()
		return r, nil
	} else {
		return &pb.SearchResponse{Error: "Data not ready"}, nil
	}
}

func (s *server) SearchIP6(ctx context.Context, in *pb.IP6Request) (*pb.SearchResponse, error) {
	fmt.Printf("Received IPv6: %v\n", in.GetQuery())
	return &pb.SearchResponse{Error: "Oops"}, nil
}

func (s *server) SearchURL(ctx context.Context, in *pb.URLRequest) (*pb.SearchResponse, error) {
	fmt.Printf("Received URL: %v\n", in.GetQuery())
	return &pb.SearchResponse{Error: "Oops"}, nil
}

func (s *server) SearchDomain(ctx context.Context, in *pb.DomainRequest) (*pb.SearchResponse, error) {
	fmt.Printf("Received Domain: %v\n", in.GetQuery())
	return &pb.SearchResponse{Error: "Oops"}, nil
}
