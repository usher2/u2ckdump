package main

//go:generate protoc -I msg --go-grpc_out=msg --go_out=msg --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative msg/msg.proto

import (
	"context"
	"net"

	"github.com/usher2/u2ckdump/internal/logger"
	pb "github.com/usher2/u2ckdump/msg"
)

// server - our grpc server.
type server struct {
	pb.UnimplementedCheckServer
}

// SearchDecision - search by decision number.
func (s *server) SearchDecision(ctx context.Context, in *pb.DecisionRequest) (*pb.SearchResponse, error) {
	query := in.GetQuery()

	logger.Debug.Printf("Received decision: %d\n", query)

	// TODO: Change to DunpSnap search method.
	if DumpSnap != nil && DumpSnap.utime > 0 {
		DumpSnap.RLock()

		resp := &pb.SearchResponse{RegistryUpdateTime: DumpSnap.utime}
		results := DumpSnap.decision[query]
		resp.Results = make([]*pb.Content, 0, len(results))

		for _, id := range results {
			if v, ok := DumpSnap.Content[id]; ok {
				resp.Results = append(resp.Results, v.newPbContent(0, nil, "", "", ""))
			}
		}

		DumpSnap.RUnlock()

		return resp, nil
	}

	return &pb.SearchResponse{Error: SrvDataNotReady}, nil
}

// SearchID - search by content ID.
func (s *server) SearchID(ctx context.Context, in *pb.IDRequest) (*pb.SearchResponse, error) {
	query := in.GetQuery()

	logger.Debug.Printf("Received content ID: %d\n", query)

	// TODO: Change to DunpSnap search method.
	if DumpSnap != nil && DumpSnap.utime > 0 {
		DumpSnap.RLock()

		resp := &pb.SearchResponse{RegistryUpdateTime: DumpSnap.utime}

		if result, ok := DumpSnap.Content[query]; ok {
			resp.Results = append(resp.Results, result.newPbContent(0, nil, "", "", ""))
		}

		DumpSnap.RUnlock()

		return resp, nil
	}

	return &pb.SearchResponse{Error: SrvDataNotReady}, nil
}

// SearchID - search by IPv4.
func (s *server) SearchIP4(c context.Context, in *pb.IP4Request) (*pb.SearchResponse, error) {
	query := in.GetQuery()
	ipBytes := net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
		byte((query & 0xFF000000) >> 24),
		byte((query & 0x00FF0000) >> 16),
		byte((query & 0x0000FF00) >> 8),
		byte(query & 0x000000FF),
	}

	logger.Debug.Printf("Received IPv4: %s\n", ipBytes)

	var resultSubnets, resulIPs ArrayIntSet
	var subnets []string

	// TODO: Change to DunpSnap search method.
	if DumpSnap != nil && DumpSnap.utime > 0 {
		DumpSnap.RLock()

		resp := &pb.SearchResponse{RegistryUpdateTime: DumpSnap.utime}

		// TODO: Change to DumpSnap search method
		cnw, err := DumpSnap.net.ContainingNetworks(ipBytes)
		if err != nil {
			logger.Debug.Printf("Can't get containing networks: %s: %s\n", ipBytes, err)
		} else {
			for _, entry := range cnw {
				subnet := entry.Network()
				subnetStr := subnet.String()

				if a, ok := DumpSnap.subnet[subnetStr]; ok {
					resultSubnets = append(resultSubnets, a...)

					for range a {
						subnets = append(subnets, subnetStr)
					}
				}
			}
		}

		if a, ok := DumpSnap.ip[query]; ok {
			resulIPs = append(resulIPs, a...)
		}

		resp.Results = make([]*pb.Content, 0, len(resultSubnets)+len(resulIPs))

		for i, id := range resultSubnets {
			if cont, ok := DumpSnap.Content[id]; ok {
				resp.Results = append(resp.Results, cont.newPbContent(0, nil, "", "", subnets[i]))
			}
		}

		for _, id := range resulIPs {
			if cont, ok := DumpSnap.Content[id]; ok {
				resp.Results = append(resp.Results, cont.newPbContent(query, nil, "", "", ""))
			}
		}

		DumpSnap.RUnlock()

		return resp, nil
	}

	return &pb.SearchResponse{Error: SrvDataNotReady}, nil
}

// SearchID - search by IPv6.
func (s *server) SearchIP6(ctx context.Context, in *pb.IP6Request) (*pb.SearchResponse, error) {
	query := in.GetQuery()

	logger.Debug.Printf("Received IPv6: %v\n", query)

	// TODO: Change to DunpSnap search method.
	if DumpSnap != nil && DumpSnap.utime > 0 {
		DumpSnap.RLock()

		resp := &pb.SearchResponse{RegistryUpdateTime: DumpSnap.utime}
		results := DumpSnap.ip6[string(query)]
		resp.Results = make([]*pb.Content, 0, len(results))

		for _, id := range results {
			if cont, ok := DumpSnap.Content[id]; ok {
				resp.Results = append(resp.Results, cont.newPbContent(0, query, "", "", ""))
			}
		}

		DumpSnap.RUnlock()

		return resp, nil
	}

	return &pb.SearchResponse{Error: SrvDataNotReady}, nil
}

// SearchID - search by URL.
func (s *server) SearchURL(ctx context.Context, in *pb.URLRequest) (*pb.SearchResponse, error) {
	query := in.GetQuery()

	logger.Debug.Printf("Received URL: %v\n", query)

	// TODO: Change to DunpSnap search method.
	if DumpSnap != nil && DumpSnap.utime > 0 {
		DumpSnap.RLock()

		resp := &pb.SearchResponse{RegistryUpdateTime: DumpSnap.utime}
		results := DumpSnap.url[query]
		resp.Results = make([]*pb.Content, 0, len(results))

		for _, id := range results {
			if cont, ok := DumpSnap.Content[id]; ok {
				resp.Results = append(resp.Results, cont.newPbContent(0, nil, "", query, ""))
			}
		}

		DumpSnap.RUnlock()

		return resp, nil
	}

	return &pb.SearchResponse{Error: SrvDataNotReady}, nil
}

// SearchID - search by domain.
func (s *server) SearchDomain(ctx context.Context, in *pb.DomainRequest) (*pb.SearchResponse, error) {
	query := in.GetQuery()

	logger.Debug.Printf("Received Domain: %v\n", query)

	// TODO: Change to DunpSnap search method.
	if DumpSnap != nil && DumpSnap.utime > 0 {
		DumpSnap.RLock()

		resp := &pb.SearchResponse{RegistryUpdateTime: DumpSnap.utime}
		results := DumpSnap.domain[query]
		resp.Results = make([]*pb.Content, 0, len(results))

		for _, id := range results {
			if cont, ok := DumpSnap.Content[id]; ok {
				resp.Results = append(resp.Results, cont.newPbContent(0, nil, query, "", ""))
			}
		}

		DumpSnap.RUnlock()

		return resp, nil
	}

	return &pb.SearchResponse{Error: SrvDataNotReady}, nil
}

// Ping - just ping.
func (s *server) Ping(ctx context.Context, in *pb.PingRequest) (*pb.PongResponse, error) {
	ping := in.GetPing()

	logger.Debug.Printf("Received Ping: %v\n", ping)

	// TODO: Change to DunpSnap search method.
	if DumpSnap != nil && DumpSnap.utime > 0 {
		DumpSnap.RLock()

		resp := &pb.PongResponse{Pong: SrvPongMessage, RegistryUpdateTime: DumpSnap.utime}

		DumpSnap.RUnlock()

		return resp, nil
	}

	return &pb.PongResponse{Error: SrvDataNotReady}, nil
}
