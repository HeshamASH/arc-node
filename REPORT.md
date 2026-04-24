# Audit Report: P2P Block Synchronization Logic (`crates/sync/src/handle.rs`)

This report addresses the security audit for the P2P Block Synchronization logic in Malachite (`crates/sync/src/handle.rs`), focusing strictly on the network sync components.

## 1. Amplification / Resource Exhaustion
**Finding:** Unbounded Concurrent Request Spam
**Impact:** Denial of Service (DoS) / Resource Exhaustion

**Analysis:**
A single malicious `SyncRequest` cannot force the node to load millions of blocks because `validate_request_range` strictly bounds the request size to the configured `batch_size`:

```rust
let len = (range.end().as_u64() - range.start().as_u64()).saturating_add(1) as usize;
if len > batch_size {
    warn!("Received request for too many values...");
    return false;
}
```

However, the sync actor `on_value_request` does **not** implement rate limiting or cap the maximum number of concurrent inbound requests per peer. A malicious peer can continuously spam thousands of concurrently valid `ValueRequest` messages (each requesting `batch_size` blocks). For each request, the sync actor blindly emits `Effect::GetDecidedValues`, commanding the database to load the blocks into memory. This will rapidly exhaust memory (OOM), overwhelm the database actor, and saturate outbound bandwidth when the node attempts to reply with thousands of `ValueResponse` packets.

## 2. Validation Bypass
**Finding:** Zero Cryptographic Validation in Network Actor
**Impact:** Spoofing / Network Layer Bypass

**Analysis:**
When syncing headers and values from peers, `handle.rs` (in `on_valid_value_response` and `on_value_response`) performs purely superficial boundary checks:

```rust
let is_valid = start.as_u64() == requested_range.start().as_u64()
    && start.as_u64() <= end.as_u64()
    && end.as_u64() <= requested_range.end().as_u64()
    && response.values.len() as u64 == range_len;
```

It does not check if the blocks are sequential, nor does it verify parent hashes or certificate signatures. Instead, it blindly trusts the response structure and forwards it to the consensus engine via `Effect::ProcessValueResponse`. While it is architecturally common to delegate cryptographic checks to the consensus engine, the total lack of basic sanity checks (e.g., verifying `response.values[0].height == start`) at the network layer means malicious peers can flood the consensus engine with cryptographically invalid garbage, forcing the node to perform expensive signature verification on entirely fake chains.

## 3. Deadlocks and Infinite Loops
**Finding:** Sybil Sync Stalling
**Impact:** Liveness Degradation

**Analysis:**
There are no true infinite `while` loops or deadlocks involving asynchronous locks in `handle.rs`. The partial response handler correctly avoids infinite looping because it ensures `values_count` is `> 0` before updating the request boundaries.

However, a sync stalling condition exists. If a node receives an invalid response (e.g., from an attacker) or encounters a processing error, it calls `re_request_values_from_peer_except`. If the node only has a few peers and the attacker occupies those slots (Sybil attack), or if alternative peers are unavailable, `random_peer_with_except` will return `None`.

```rust
let Some((peer, peer_range)) = state.random_peer_with_except(&range, except_peer_id) else {
    debug!("No peer to re-request sync from");
    state.sync_height = min(state.sync_height, *range.start());
    return Ok(());
};
```

When this happens, the node silently resets its `sync_height` backwards and aborts the request loop. If the attacker repeatedly triggers invalid responses and dominates the peer list, the node will permanently rollback its `sync_height` and stall, never syncing the actual chain.
