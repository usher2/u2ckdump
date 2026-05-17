# XML parse review: fixes and simplification proposal

Date: 2026-05-17

Scope: `parse_xml.go`, parser-adjacent dump mutation/indexing code, and refresh behavior.

## Findings

### 1. Decode errors are best-effort after the record is marked as seen

`Parse` marks a content ID as present before decoding the captured content:

```go
ContJournal[id] = Nothing{}
newCont, err := NewContent(newRecordHash, contBuf)
if err != nil {
	logger.Error.Printf("Decode Error: %s\n", err)
	break
}
```

This is known behavior. Registry XML can contain malformed `<content>` records, and the parser should apply as much of the dump as possible instead of rejecting the whole update. Marking the ID as seen before decode also prevents cleanup from deleting a previous known-good record when a changed record for the same ID is malformed.

Impact:

- A changed bad record keeps its old packed content and indexes.
- A new bad record is counted as seen but is not inserted.
- Deleted-record cleanup will not remove the old record if the bad record uses the same ID. This is intentional.

Suggested follow-up: keep parsing, but collect recoverable per-content decode failures into parse statistics and the JSON summary.

### 2. Unchanged content gets the wrong per-record update time

`SetContentUpdateTime` accepts an `updateTime` argument but writes the previous dump time:

```go
func (dump *Dump) SetContentUpdateTime(id int32, updateTime int64) {
	dump.ContentIndex[id].RegistryUpdateTime = dump.utime
}
```

During parse, `dump.utime` is updated later in `Cleanup`, so unchanged records keep the old per-record `RegistryUpdateTime` while the global dump time advances.

Suggested fix:

```go
func (dump *Dump) SetContentUpdateTime(id int32, updateTime int64) {
	dump.ContentIndex[id].RegistryUpdateTime = updateTime
}
```

Add a test that parses two dumps with unchanged content bytes but different register `updateTime`, then checks the packed content update time.

### 3. Invalid subnets can panic after logging

`InsertToSubnetIPv4Index`, `RemoveFromSubnetIPv4Index`, `InsertToSubnetIPv6Index`, and `RemoveFromSubnetIPv6Index` log `net.ParseCIDR` errors but continue and dereference `*network`.

Example:

```go
_, network, err := net.ParseCIDR(subnet4)
if err != nil {
	logger.Debug.Printf("Can't parse CIDR: %s: %s\n", subnet4, err.Error())
}
err = d.netTree.Insert(cidranger.NewBasicRangerEntry(*network))
```

Impact: one malformed `ipSubnet` or `ipv6Subnet` can crash parsing.

Suggested fix: parse and validate the CIDR before inserting into the string index. If parsing fails, log and skip the subnet completely.

### 4. Invalid IPs are indexed as real lookup keys

IPv4 parsing returns `0xFFFFFFFF` for invalid input, which is also the valid address `255.255.255.255`. IPv6 parsing can return `nil`, which later becomes `string(nil) == ""` in the IPv6 index.

Suggested fix:

- Change IPv4 parsing to return `(uint32, bool)` or add a validation wrapper.
- Skip and log invalid IPv4/IPv6 values during content decode.
- Add tests for malformed IPv4 and IPv6 entries.

### 5. Raw content capture is fragile and tied to charset conversion

The raw `<content>` bytes used for hashing come from a `TeeReader` installed as `decoder.CharsetReader`. That means capture depends on the XML decoder invoking charset conversion. For UTF-8 or no encoding declaration, this path is fragile and can produce empty or incomplete captured content.

Suggested fix options:

- Wrap the original input reader in a counting/capture reader independent of `CharsetReader`.
- Or, if the registry `hash` attribute is reliable enough, use it as the primary unchanged-record check and keep FNV only as a fallback/verification path.

## Simplification opportunities

### Keep purge-then-rebind for changed records

The current `MergePackedContent` shape removes old indexes, refreshes payload/hash/time, clears indexed fields, then extracts and applies the new fields. This is much simpler and safer than per-field diffing.

Keep this model unless profiling shows a real bottleneck. It avoids index leaks and makes update behavior match deletion plus insertion.

### Decode outside the write lock

The parse loop currently takes the dump write lock before decoding changed content. For large changed records, this blocks all lookup RPCs longer than needed.

Suggested shape:

1. Capture and hash the raw content.
2. Take a short lock or read lock to compare the previous hash.
3. Decode and marshal outside the dump lock if the content is new or changed.
4. Take the write lock to recheck and apply.

This keeps lookup blocking limited to actual map/index mutation.

### Split `Cleanup`

`Cleanup` currently purges deleted records, calculates max reference stats, updates `utime`, builds summary values, and repopulates `packedOrgIndex`.

Splitting these steps would make lock duration and side effects easier to reason about:

- `purgeMissing(seenIDs)`
- `calcIndexStats()`
- `buildSummary()`
- `refreshPackedOrgIndex()`

### Remove global parser coupling

`Parse` mutates `CurrentDump` directly. Passing the target dump explicitly would make tests easier and make parser side effects clearer:

```go
func Parse(dumpFile io.Reader, dump *Dump) (*ParseStatistics, error)
```

The existing `CurrentDump` singleton can still be used by callers.

## Suggested order

1. Fix `SetContentUpdateTime`.
2. Collect content decode failures in parse statistics and summary.
3. Validate subnets before indexing and avoid nil CIDR dereferences.
4. Validate IP values before indexing.
5. Add focused tests for unchanged update time, malformed content statistics, bad subnet, bad IPv4, and bad IPv6.
6. Refactor content capture and lock boundaries after correctness fixes are covered.

## Verification during review

Current test status before applying these fixes:

```sh
go test ./...
```

Result: all tests passed.
