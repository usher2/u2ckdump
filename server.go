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
	fmt.Printf("Received: %v", in.GetQuery())
	return &pb.SearchResponse{Error: "Oops"}, nil
}

func (s *server) SearchIP6(ctx context.Context, in *pb.IP6Request) (*pb.SearchResponse, error) {
	fmt.Printf("Received: %v", in.GetQuery())
	return &pb.SearchResponse{Error: "Oops"}, nil
}

func (s *server) SearchURL(ctx context.Context, in *pb.URLRequest) (*pb.SearchResponse, error) {
	fmt.Printf("Received: %v", in.GetQuery())
	return &pb.SearchResponse{Error: "Oops"}, nil
}

func (s *server) SearchDomain(ctx context.Context, in *pb.DomainRequest) (*pb.SearchResponse, error) {
	fmt.Printf("Received: %v", in.GetQuery())
	return &pb.SearchResponse{Error: "Oops"}, nil
}
