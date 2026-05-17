# parse_xml.go — review, bugs, and simplification proposal

Date: 2026-05-12
Scope: `parse_xml.go` (with `dump.go` / `types_snap.go` for context).

## Bugs

### 1. IPv6 subnets are routed into the IPv4 subnet index (high)

`ExtractAndApplySubnetIPv6` and `EctractAndApplyUpdateSubnetIPv6` both call the IPv4 index methods:

```go
// parse_xml.go:767
func (dump *Dump) ExtractAndApplySubnetIPv6(record *Content, pack *PackedContent) {
    if len(record.SubnetIPv6) > 0 {
        pack.SubnetIPv6 = record.SubnetIPv6
        for _, subnet6 := range pack.SubnetIPv6 {
            dump.InsertToSubnetIPv4Index(subnet6.SubnetIPv6, pack.ID)   // ← wrong index
        }
    }
}

// parse_xml.go:789
dump.RemoveFromSubnetIPv4Index(subnetIPv6.SubnetIPv6, pack.ID)         // ← wrong index
```

Effects:

- `Dump.subnetIPv6Index` stays empty for fresh inserts.
- It then gets stuck with stale entries on update, because the update path
  *does* call `InsertToSubnetIPv6Index` for items it considers new.
- `InsertToSubnetIPv4Index` calls `net.ParseCIDR(...)` and inserts the network
  into `netTree` from the IPv4 code path — `net.ParseCIDR` succeeds on an
  IPv6 CIDR, so the entry ends up in `netTree` without v6 tagging.
  `SearchSubnetIPv6` lookups will largely miss.

Fix: call `InsertToSubnetIPv6Index` / `RemoveFromSubnetIPv6Index` in those
two functions.

### 2. All `EctractAndApplyUpdate*` paths mutate the slice they iterate (high)

```go
// EctractAndApplyUpdateIPv4, parse_xml.go:643
for _, ip4 := range pack.IPv4 {
    if _, ok := ipExisted[ip4.IPv4]; !ok {
        pack.RemoveIPv4(ip4)                       // shifts pack.IPv4 in place
        dump.RemoveFromIPv4Index(ip4.IPv4, pack.ID)
    }
}
```

`RemoveIPv4` does `pack.IPv4 = append(pack.IPv4[:i], pack.IPv4[i+1:]...)`.
The `for range` captured the underlying array and length once; the in-place
shift leaves the loop visiting the wrong slot, so **every other element to
be removed is skipped**. When multiple IPs disappear from a record at once,
stale entries linger in both `pack.IPv4` and `dump.IPv4Index`.

Same pattern in `EctractAndApplyUpdate{IPv6, SubnetIPv4, SubnetIPv6, Domain, URL}`
— six copies, all broken the same way.

Standard fixes: iterate backwards, collect items to remove and then remove
them, or rebuild `pack.X` from scratch using the set already computed.

### 3. `entryTypeIndex` leaks on purge (medium)

Insert path stores the key computed from the **raw** decision org:

```go
// parse_xml.go:560
pack.EntryTypeString = entryTypeKey(record.EntryType, record.Decision.Org, record.Decision.Number)
```

Purge recomputes the key from the **normalized** org stored on `PackedContent`:

```go
// parse_xml.go:484
dump.RemoveFromEntryTypeIndex(entryTypeKey(cont.EntryType, cont.DecisionOrg, cont.DecisionNumber), cont.ID)
```

`pack.DecisionOrg` was rewritten by `makeRightDecisionOrg`: `""→"Генпрокуратура"`,
`"…суд…"→"Суд"`, `"…ФССП…"→"ФССП"`. For e.g. `entryType=1, org=""`, the insert
key is `"15_1_1"` (the `org == ""` branch), but the purge key uses
`org="Генпрокуратура"`, which doesn't match any case and falls back to `"15_1"`.
The remove silently no-ops; the orphan stays in `entryTypeIndex` until the next
time content with the same normalized org happens to land on the same bucket.

Fix: either (a) call `entryTypeKey` against the raw values in both places, or
(b) just `RemoveFromEntryTypeIndex(cont.EntryTypeString, cont.ID)` and avoid
recomputing. (b) is the same trick the update path already uses.

### 4. `hasher64` is a package-global, lazy-initialized (low)

```go
// parse_xml.go:32
var hasher64 hash.Hash64
```

Initialized inside `Parse()`. `hashDecision` (used from every Extract/Ectract
path) assumes it's non-nil. Today that's fine because Parse runs at startup,
but it's a foot-gun: any direct unit test of `hashDecision` (or future code
path that calls Extract without going through Parse) nil-derefs. Also not
safe to call concurrently — currently OK because the Dump lock serialises
writers, but the coupling isn't obvious from the type.

Fix: move it into `Parse`'s frame and pass it down, or use `fnv.New64a()`
on demand (it's a `*sum64a` allocation; cheap).

### 5. `decoder.Skip()` return value ignored (low)

```go
// parse_xml.go:198
decoder.Skip()
```

If skipping a malformed `<content>` fails, the buffer offsets computed next
(`tokenStartOffset = decoder.InputOffset() - offsetCorrection`) are based
on partial consumption. At minimum log it.

### 6. `Test_Parse` assertions can never pass (low)

```go
// parse_xml_test.go:126
var stats ParseStatistics      // <-- local, never populated
...
err := Parse(dumpFile)          // populates its own stats inside Parse()
if stats.MaxItemReferences != 5 || stats.Count != 5 || ... {
    t.Errorf(...)
}
```

The test's `stats` always stays zero, so the `!= 5` checks always fire and
the test always errors. `Parse` would need to return its `stats` (or write
into a passed-in pointer) for the assertion to mean anything. The downstream
`len(CurrentDump.IPv4Index) != 13` checks only work because `CurrentDump` is
shared global state.

### 7. Typos (cosmetic)

- `EctractAndApplyUpdate*` (12 occurrences) — `Ectract` → `Extract`.
- `LargestSizeOfContentCintentID` — `Cintent` → `Content`.

## Simplifications

### Replace 8 × Extract/Ectract pairs with a full re-bind

Roughly **400 lines** of `ExtractAndApply…` / `EctractAndApplyUpdate…` /
`Insert<Type>` / `Remove<Type>` per-field methods exist solely to do "what's
new, what's gone" diffing inside the write lock. But:

- A change is only processed when the fnv64 of the raw `<content>` bytes
  differs, i.e. *something* in the record changed.
- The whole update happens under `Dump.Lock()`, so readers never observe a
  transient state — there's no consistency benefit to surgical diffs.
- "Insert N, remove K" against map-backed indexes is roughly the same number
  of map ops as "remove old N, insert new N′", just with worse constants
  because each diff also has an O(N) linear scan in `pack.InsertX`.

A much shorter shape: when the hash differs, treat it as `purge(prev)` (which
`Dump.purge` already does correctly for the cleanup case) followed by
`NewPackedContent(newCont, …)`. That lets us delete:

- every `EctractAndApplyUpdate*` (eliminates bug #2 entirely)
- every `pack.InsertX` / `pack.RemoveX` linear-scan helper
- per-field slices on `PackedContent` shrink to whatever `purge` actually
  needs (which can also be read back off `pack.Payload` if we don't want to
  store them at all)

This also automatically fixes bug #3 because the entry-type key is then
computed from the same source in both paths.

### Smaller wins

- `string(ip6.IPv6) == string(existed.IPv6)` allocates two strings per
  comparison. Use `bytes.Equal`. (Hot for records with many IPv6 entries.)
- `pack.Insert<X>` / `pack.Remove<X>` are O(N) linear scans; combined with
  the outer loop that's O(N²). For records with hundreds of URLs (which
  exist in the vigruzki) that's noticeable. If we keep the diff approach,
  build the "existed" set first and diff the two sets.
- `record.Hash` (the `hash="…"` attribute the registry itself ships) is
  parsed into `Content.Hash` and never used. If we trust it, it's a free
  pre-check before fnv'ing the raw bytes. If we don't trust it (probable
  — README says so), drop the field.
- `getContentId` parses attrs to fish out `id` even though `parseContentElement`
  does the same a few lines later for the full content decode. The first
  pass is unavoidable (we need the id before deciding to decode), but the
  duplication can be inlined as a one-liner.
- `Dump.Cleanup` mixes three concerns: purge, recompute summary, and
  re-populate `packedOrgIndex`. Splitting them would make the lock window
  clearer and let `Summary` be rebuilt outside the write lock from the
  purged state.

## Suggested order of work

1. Fix bugs 1 and 2 — silent data-correctness bugs in production hot paths.
2. Fix bug 3 (`entryTypeIndex` leak) — same category, slower-moving.
3. Collapse Extract/Ectract pairs to purge-then-insert. This also makes
   bugs 1 and 2 impossible to reintroduce.
4. Fix the test (`Parse` should return `stats` or take `*ParseStatistics`).
5. The typos.
