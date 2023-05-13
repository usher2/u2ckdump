package main

//go:generate protoc -I msg --go-grpc_out=msg --go_out=msg --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative msg/msg.proto

import (
	"context"
	"encoding/json"
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
	if CurrentDump != nil && CurrentDump.utime > 0 {
		CurrentDump.RLock()

		resp := &pb.SearchResponse{RegistryUpdateTime: CurrentDump.utime}
		results := CurrentDump.decisionIndex[query]
		resp.Results = make([]*pb.Content, 0, len(results))

		for _, id := range results {
			if v, ok := CurrentDump.ContentIndex[id]; ok {
				resp.Results = append(resp.Results, v.newPbContent(0, nil, "", "", ""))
			}
		}

		CurrentDump.RUnlock()

		return resp, nil
	}

	return &pb.SearchResponse{Error: SrvDataNotReady}, nil
}

// SearchContentID - search by content ID.
func (s *server) SearchContentID(ctx context.Context, in *pb.ContentIDRequest) (*pb.SearchResponse, error) {
	query := in.GetQuery()

	logger.Debug.Printf("Received content ID: %d\n", query)

	// TODO: Change to DunpSnap search method.
	if CurrentDump != nil && CurrentDump.utime > 0 {
		CurrentDump.RLock()

		resp := &pb.SearchResponse{RegistryUpdateTime: CurrentDump.utime}

		if result, ok := CurrentDump.ContentIndex[query]; ok {
			resp.Results = append(resp.Results, result.newPbContent(0, nil, "", "", ""))
		}

		CurrentDump.RUnlock()

		return resp, nil
	}

	return &pb.SearchResponse{Error: SrvDataNotReady}, nil
}

// SearchIPv4 - search by IPv4.
func (s *server) SearchIPv4(c context.Context, in *pb.IPv4Request) (*pb.SearchResponse, error) {
	query := in.GetQuery()
	ipBytes := net.IP{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
		byte((query & 0xFF000000) >> 24),
		byte((query & 0x00FF0000) >> 16),
		byte((query & 0x0000FF00) >> 8),
		byte(query & 0x000000FF),
	}

	logger.Debug.Printf("Received IPv4: %s\n", ipBytes)

	var resultSubnets, resulIPs IntArrayStorage
	var subnets []string

	// TODO: Change to DunpSnap search method.
	if CurrentDump != nil && CurrentDump.utime > 0 {
		CurrentDump.RLock()

		resp := &pb.SearchResponse{RegistryUpdateTime: CurrentDump.utime}

		// TODO: Change to DumpSnap search method
		cnw, err := CurrentDump.netTree.ContainingNetworks(ipBytes)
		if err != nil {
			logger.Debug.Printf("Can't get containing networks: %s: %s\n", ipBytes, err)
		} else {
			for _, entry := range cnw {
				subnet := entry.Network()
				subnetStr := subnet.String()

				if a, ok := CurrentDump.subnetIPv4Index[subnetStr]; ok {
					resultSubnets = append(resultSubnets, a...)

					for range a {
						subnets = append(subnets, subnetStr)
					}
				}
			}
		}

		if a, ok := CurrentDump.IPv4Index[query]; ok {
			resulIPs = append(resulIPs, a...)
		}

		resp.Results = make([]*pb.Content, 0, len(resultSubnets)+len(resulIPs))

		for i, id := range resultSubnets {
			if cont, ok := CurrentDump.ContentIndex[id]; ok {
				resp.Results = append(resp.Results, cont.newPbContent(0, nil, "", "", subnets[i]))
			}
		}

		for _, id := range resulIPs {
			if cont, ok := CurrentDump.ContentIndex[id]; ok {
				resp.Results = append(resp.Results, cont.newPbContent(query, nil, "", "", ""))
			}
		}

		CurrentDump.RUnlock()

		return resp, nil
	}

	return &pb.SearchResponse{Error: SrvDataNotReady}, nil
}

// SearchID - search by IPv6.
func (s *server) SearchIPv6(ctx context.Context, in *pb.IPv6Request) (*pb.SearchResponse, error) {
	query := in.GetQuery()

	logger.Debug.Printf("Received IPv6: %v\n", query)

	// TODO: Change to DunpSnap search method.
	if CurrentDump != nil && CurrentDump.utime > 0 {
		CurrentDump.RLock()

		resp := &pb.SearchResponse{RegistryUpdateTime: CurrentDump.utime}
		results := CurrentDump.IPv6Index[string(query)]
		resp.Results = make([]*pb.Content, 0, len(results))

		for _, id := range results {
			if cont, ok := CurrentDump.ContentIndex[id]; ok {
				resp.Results = append(resp.Results, cont.newPbContent(0, query, "", "", ""))
			}
		}

		CurrentDump.RUnlock()

		return resp, nil
	}

	return &pb.SearchResponse{Error: SrvDataNotReady}, nil
}

// SearchID - search by URL.
func (s *server) SearchURL(ctx context.Context, in *pb.URLRequest) (*pb.SearchResponse, error) {
	query := in.GetQuery()

	logger.Debug.Printf("Received URL: %v\n", query)

	// TODO: Change to DunpSnap search method.
	if CurrentDump != nil && CurrentDump.utime > 0 {
		CurrentDump.RLock()

		resp := &pb.SearchResponse{RegistryUpdateTime: CurrentDump.utime}
		results := CurrentDump.URLIndex[query]
		resp.Results = make([]*pb.Content, 0, len(results))

		for _, id := range results {
			if cont, ok := CurrentDump.ContentIndex[id]; ok {
				resp.Results = append(resp.Results, cont.newPbContent(0, nil, "", query, ""))
			}
		}

		CurrentDump.RUnlock()

		return resp, nil
	}

	return &pb.SearchResponse{Error: SrvDataNotReady}, nil
}

// SearchDomain - search by domain.
func (s *server) SearchDomain(ctx context.Context, in *pb.DomainRequest) (*pb.SearchResponse, error) {
	query := in.GetQuery()

	logger.Debug.Printf("Received Domain: %v\n", query)

	// TODO: Change to DunpSnap search method.
	if CurrentDump != nil && CurrentDump.utime > 0 {
		CurrentDump.RLock()

		resp := &pb.SearchResponse{RegistryUpdateTime: CurrentDump.utime}
		results := CurrentDump.domainIndex[query]
		resp.Results = make([]*pb.Content, 0, len(results))

		for _, id := range results {
			if cont, ok := CurrentDump.ContentIndex[id]; ok {
				resp.Results = append(resp.Results, cont.newPbContent(0, nil, query, "", ""))
			}
		}

		CurrentDump.RUnlock()

		return resp, nil
	}

	return &pb.SearchResponse{Error: SrvDataNotReady}, nil
}

// SearchSuffix - search by domain public suffix.
func (s *server) SearchDomainSuffix(ctx context.Context, in *pb.SuffixRequest) (*pb.SearchResponse, error) {
	query := in.GetQuery()
	variant := in.GetVariant()

	logger.Debug.Printf("Received Domain Suffix: %v\n", query)

	if CurrentDump != nil && CurrentDump.utime > 0 {
		CurrentDump.RLock()
		defer CurrentDump.RUnlock()

		resp := &pb.SearchResponse{RegistryUpdateTime: CurrentDump.utime}

		parent, suffix := parentDomains(query)
		if parent == "" && suffix == "" {
			resp.Results = make([]*pb.Content, 0)

			return resp, nil
		}

		logger.Debug.Printf("***Suffixes: %s, %s\n", parent, suffix)

		if parent == "" {
			resp.Results = make([]*pb.Content, 0)

			return resp, nil
		}

		results := CurrentDump.publicSuffixIndex[parent]

		logger.Debug.Printf("***Parent: %s, results: %v\n", parent, results)

		resp.Results = make([]*pb.Content, 0, len(results))

		for _, id := range results {
			if cont, ok := CurrentDump.ContentIndex[id]; ok {
				resp.Results = append(resp.Results, cont.newPbContent(0, nil, parent, "", ""))
			}
		}

		if variant != 2 || suffix == "" {
			return resp, nil
		}

		results = CurrentDump.publicSuffixIndex[suffix]

		logger.Debug.Printf("***Suffix: %s, results: %v\n", suffix, results)

		for _, id := range results {
			if cont, ok := CurrentDump.ContentIndex[id]; ok {
				resp.Results = append(resp.Results, cont.newPbContent(0, nil, suffix, "", ""))
			}
		}

		return resp, nil
	}

	return &pb.SearchResponse{Error: SrvDataNotReady}, nil
}

// SearchEntryType - search by entry type.
func (s *server) SearchEntryType(ctx context.Context, in *pb.EntryTypeRequest) (*pb.SearchResponse, error) {
	query := in.GetQuery()

	logger.Debug.Printf("Received EntryType: %v\n", query)

	if CurrentDump != nil && CurrentDump.utime > 0 {
		CurrentDump.RLock()
		defer CurrentDump.RUnlock()

		resp := &pb.SearchResponse{RegistryUpdateTime: CurrentDump.utime}

		results, ok := CurrentDump.entryTypeIndex[query]
		if !ok {
			resp.Results = make([]*pb.Content, 0)

			return resp, nil
		}

		resp.Results = make([]*pb.Content, 0, len(results))
		for _, id := range results {
			if cont, ok := CurrentDump.ContentIndex[id]; ok {
				resp.Results = append(resp.Results, cont.newPbContent(0, nil, "", "", ""))
			}
		}

		return resp, nil
	}

	return &pb.SearchResponse{Error: SrvDataNotReady}, nil
}

// Ping - just ping.
func (s *server) Ping(ctx context.Context, in *pb.PingRequest) (*pb.PongResponse, error) {
	ping := in.GetPing()

	logger.Debug.Printf("Received Ping: %v\n", ping)

	// TODO: Change to DunpSnap search method.
	if CurrentDump != nil && CurrentDump.utime > 0 {
		CurrentDump.RLock()

		resp := &pb.PongResponse{Pong: SrvPongMessage, RegistryUpdateTime: CurrentDump.utime}

		CurrentDump.RUnlock()

		return resp, nil
	}

	return &pb.PongResponse{Error: SrvDataNotReady}, nil
}

// Summary - return summary statistics.
func (s *server) Summary(ctx context.Context, in *pb.SummaryRequest) (*pb.SummaryResponse, error) {
	logger.Debug.Printf("Received Summary request\n")

	summary := Summary.Load()

	if summary == nil {
		return &pb.SummaryResponse{Error: SrvDataNotReady}, nil
	}

	data, err := json.Marshal(summary)
	if err != nil {
		return &pb.SummaryResponse{Error: err.Error()}, nil
	}

	return &pb.SummaryResponse{Summary: data}, nil
}
