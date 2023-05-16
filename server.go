package main

//go:generate protoc -I msg --go-grpc_out=msg --go_out=msg --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative msg/msg.proto

import (
	"context"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net"

	"github.com/usher2/u2ckdump/internal/logger"
	pb "github.com/usher2/u2ckdump/msg"
)

// server - our grpc server.
type server struct {
	pb.UnimplementedCheckServer
}

const encodeCorc = "abcdefghjkmnpqrstvwxyz0123456789"

func String2fnv2base32(s string) string {
	h64 := fnv.New64a()
	h64.Write([]byte(s))
	return Uint64ToBase32(h64.Sum64())
}

func String2fnv2uint64(s string) uint64 {
	h64 := fnv.New64a()
	h64.Write([]byte(s))
	return h64.Sum64()
}

func Uint64ToBase32(i uint64) string {
	b32 := base32.NewEncoding(encodeCorc).WithPadding(base32.NoPadding)
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, i)
	return b32.EncodeToString(b)
}

func Base32ToUint64(s string) (uint64, error) {
	b32 := base32.NewEncoding(encodeCorc).WithPadding(base32.NoPadding)
	b, err := b32.DecodeString(s)
	if err == nil {
		return binary.LittleEndian.Uint64(b), nil
	}
	return 0, err
}

// SearchDecision - search by decision number.
func (s *server) SearchDecision(ctx context.Context, in *pb.DecisionRequest) (*pb.SearchResponse, error) {
	query := in.GetQuery()

	logger.Debug.Printf("Received decision: %d\n", query)

	// TODO: Change to DunpSnap search method.
	if CurrentDump != nil && CurrentDump.utime > 0 {
		CurrentDump.RLock()

		resp := &pb.SearchResponse{RegistryUpdateTime: CurrentDump.utime, Query: fmt.Sprintf("%d", query)}
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

		resp := &pb.SearchResponse{RegistryUpdateTime: CurrentDump.utime, Query: fmt.Sprintf("%d", query)}

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

		resp := &pb.SearchResponse{RegistryUpdateTime: CurrentDump.utime, Query: ipBytes.String()}

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

	ip := net.IP(query)

	logger.Debug.Printf("Received IPv6: %s\n", ip.String())

	// TODO: Change to DunpSnap search method.
	if CurrentDump != nil && CurrentDump.utime > 0 {
		CurrentDump.RLock()

		resp := &pb.SearchResponse{RegistryUpdateTime: CurrentDump.utime, Query: ip.String()}
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

		resp := &pb.SearchResponse{RegistryUpdateTime: CurrentDump.utime, Query: query}
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

		resp := &pb.SearchResponse{RegistryUpdateTime: CurrentDump.utime, Query: query}
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

		resp := &pb.SearchResponse{RegistryUpdateTime: CurrentDump.utime, Query: query}

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

		resp := &pb.SearchResponse{RegistryUpdateTime: CurrentDump.utime, Query: query}

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

func (s *server) SearchOrg(ctx context.Context, in *pb.OrgRequest) (*pb.SearchResponse, error) {
	query := in.GetQuery()

	logger.Debug.Printf("Received Org: %x\n", query)

	if CurrentDump != nil && CurrentDump.utime > 0 {
		CurrentDump.RLock()
		defer CurrentDump.RUnlock()

		orgForSearch := CurrentDump.packedOrgIndex[query]

		resp := &pb.SearchResponse{RegistryUpdateTime: CurrentDump.utime, Query: orgForSearch}

		results, ok := CurrentDump.orgIndex[orgForSearch]
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

func (s *server) SearchWithoutNo(ctx context.Context, in *pb.WithoutNoRequest) (*pb.SearchResponse, error) {
	query := in.GetQuery()

	logger.Debug.Printf("Received WithoutNo: %v\n", query)

	if CurrentDump != nil && CurrentDump.utime > 0 {
		CurrentDump.RLock()
		defer CurrentDump.RUnlock()

		resp := &pb.SearchResponse{RegistryUpdateTime: CurrentDump.utime}

		results := CurrentDump.withoutDecisionNo

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
