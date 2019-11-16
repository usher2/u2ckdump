package main

//go:generate protoc -I msg --go_out=plugins=grpc:msg msg/msg.proto

import (
	"context"
	"fmt"

	pb "github.com/usher-2/u2ckdump/msg"
)

type server struct {
	pb.UnimplementedSearchServiceServer
}

func (s *server) Search(ctx context.Context, in *pb.SearchRequest) (*pb.SearchResponse, error) {
	fmt.Printf("Received: %v", in.GetQuery())
	return &pb.SearchResponse{Error: "Oops"}, nil
}
