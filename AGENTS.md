# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`u2ckdump` is a Go service in the [Usher2](https://usher2.club) ecosystem. It periodically fetches the signed Roscomnadzor ("vigruzki") block-list dump, parses the XML into an in-memory indexed structure, and serves lookup queries over gRPC (IPv4/IPv6, URL, domain, subnet, decision number, content ID, org, etc.). The gRPC service itself is private — only this dumper/parser is open source.

## Build / run / test

```sh
go build -o u2ckdump .                                       # build server
go build -o testc/testc ./testc                              # build gRPC test client
go test ./...                                                # run all unit tests
go test -run TestParseRFC3339Time ./...                      # run a single test
go vet ./... && gofmt -l .                                   # lint / format check
go generate ./...                                            # regenerate msg/*.pb.go from msg/msg.proto (needs protoc + go-grpc plugin)
```

Run the server (flags shown with defaults):

```sh
./u2ckdump -u https://<vigruzki-host> -k <api-key> -p 50001 -d res -l Debug
# -d : dump cache dir (must exist). Will read res/dump.zip or res/dump.xml at startup, then poll the API every 60s.
# -l : log level — Debug | Info | Warning | Error
```

The `u2ckdump.sh` wrapper in the repo contains a real API key/URL — do not commit changes to it.

## Architecture

### Startup → steady state

`main.go` wires the lifecycle:
1. On boot, if `res/dump.zip` exists it is unzipped; if `res/dump.xml` exists it is parsed into `CurrentDump` before the gRPC server starts accepting traffic.
2. `DumpPoll` (poll.go) runs in a goroutine and every 60s calls `DumpRefresh`, which hits `/last` on the vigruzki API, compares CRC/ID against the saved `res/current` metadata, fetches+unzips+parses if the CRC differs, or just bumps `utime` if only the metadata changed.
3. gRPC server serves `pb.Check` (see `msg/msg.proto`). All RPC handlers in `server.go` take an `RLock` on `CurrentDump` while the parser takes the write `Lock`.

### The central data structure: `Dump` (dump.go)

`CurrentDump *Dump` is a process-global singleton holding **all** state. `Dump` is an `sync.RWMutex` plus a collection of inverted indexes keyed by lookup type (IPv4, IPv6, subnet4/6, URL, domain, public suffix, decision hash, org, entry type) — each maps a search key to a slice of content IDs (`int32`). The authoritative records live in `ContentIndex map[int32]*PackedContent`. Subnets are additionally inserted into a `cidranger` radix tree (`netTree`) for "which subnet contains this IP" queries.

Two parallel content types exist and must not be confused:
- `Content` (types_snap.go) — the in-memory shape produced by XML decoding (`[]URL`, `[]Domain`, `[]IPv4`, ...).
- `PackedContent` (types_snap.go) — the **stored** shape inside `Dump.ContentIndex`. It carries a precomputed protobuf `Payload []byte` and a `RecordHash` (fnv64 of the raw `<content>...</content>` bytes) used to skip work on unchanged records.

When `Content` is inserted (`NewPackedContent`) or updated (`MergePackedContent`), every index that references the old fields must be diffed and updated — see those methods for the canonical pattern.

### XML parsing strategy (parse_xml.go)

The dump's outer envelope is parsed as a token stream, but each `<content>...</content>` is captured as raw bytes via a `TeeReader` into a `bytes.Buffer`, hashed (fnv64), and only fully `xml.Decode`'d if the hash differs from the stored `RecordHash`. This is intentional — see the README note: "Stream parsing a `<content>...</content>` object is not a good idea. Because we need some checksum on updates before data applying." Don't change to a streaming-per-content design without understanding that tradeoff.

After the file is fully consumed, `Dump.Cleanup` removes any `ContentIndex` entries whose IDs were not observed in this pass (tracked via the `ContJournal` set), tearing down their index references.

### Small-but-important pieces

- `set_*.go` (`set_arrayint.go`, `set_decision.go`, `set_ip4.go`, `set_string.go`) define the per-key set implementations used by the inverted indexes — they all expose `Insert(key, id) bool` / `Remove(key, id) bool` returning `true` when the key transitioned to/from existing.
- `parse_ip4.go` — hand-rolled IPv4 string→`uint32` parser (no `net.ParseIP` allocations).
- `parse_time.go` — hand-rolled RFC3339 + Moscow-time parsers; mirrors a TODO in README about native RFC3339 parsing.
- `normalizers.go` — URL/domain canonicalization (IDNA, lowercase, scheme stripping) applied on both ingest and query sides; the same normalization must be used or lookups silently miss.
- `psuffix.go` + `domainIndex` / `publicSuffixIndex` — domain lookups need both the FQDN index and a public-suffix index so suffix queries (`example.co.uk`) work.
- `summary.go` — `Summary` is an `atomic.Value` updated at the end of every parse; served by `Summary` RPC without touching the dump lock.
- `internal/logger` — leveled loggers (`Debug`, `Info`, `Warning`, `Error`). Use these, not `log` or `fmt.Println`.
- `msg/` — generated protobuf/gRPC code. Don't hand-edit `msg.pb.go` / `msg_grpc.pb.go`; edit `msg.proto` and run `go generate`.
- `testc/` — a standalone client binary for poking the live gRPC server; useful for sanity-checking new RPCs.

### Concurrency rules

- All readers of `CurrentDump` take `RLock`; the parser takes `Lock` around inserts/updates/cleanup.
- `CurrentDump` is replaced in place (never reassigned), so callers can hold the pointer without atomics.
- `Summary` is read lock-free via `atomic.Value`.

## Conventions specific to this code

- Don't trust input data. Quoting the README: "I don't trust to any data. I'm not trying to guess unknown errors. Only known patterns. Roskomnadzor officials are such entertainers." When you encounter an unknown XML attribute or value, log at `Debug`/`Warning` and skip — don't try to coerce it.
- The `res/` directory holds runtime state (`dump.zip`, `dump.xml`, `current`). It is git-ignored except for `*.zip-sample` files tracked via git-lfs for tests. Don't commit live dumps.
- `u2ckdump.sh` is also git-ignored (`*.sh` in `.gitignore`) and contains a real production key.
