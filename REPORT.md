# [High] Resource Exhaustion via Unbounded Concurrent ValueRequests in P2P Sync

## Description
A critical resource exhaustion vulnerability exists in the P2P Block Synchronization logic (`crates/sync/src/handle.rs`) of the Malachite consensus engine. A malicious peer can overwhelm the node by spamming an unbounded number of concurrent `ValueRequest` messages, causing the node to continuously queue expensive database read operations and exhaust memory, ultimately leading to a Denial of Service (DoS) and node crash.

In the P2P synchronization architecture, when a peer requests blocks via a `ValueRequest`, the network actor routes the request to the `on_value_request` function in `handle.rs`. The handler successfully validates the bounds of each individual request (ensuring that a single request does not ask for more blocks than `batch_size`). However, there is no state-tracking mechanism to limit the **volume** or **concurrency** of inbound requests originating from a single peer.

```rust
// In `crates/sync/src/handle.rs`
pub async fn on_value_request<Ctx>(
    co: Co<Ctx>,
    state: &mut State<Ctx>,
    metrics: &Metrics,
    request_id: InboundRequestId,
    peer_id: PeerId,
    request: ValueRequest<Ctx>,
) -> Result<(), Error<Ctx>> {
    // Validates that the request size <= batch_size, but DOES NOT rate limit
    // or check how many requests are currently inflight for `peer_id`.
    if !validate_request_range::<Ctx>(&request.range, state.tip_height, state.config.batch_size) { ... }

    // Blindly issues a database read request for every validated message.
    perform!(
        co,
        Effect::GetDecidedValues(request_id, range, Default::default())
    );

    Ok(())
}
```

Because `handle.rs` operates asynchronously, a malicious peer can establish a connection and fire hundreds of thousands of valid, small `ValueRequest` messages in rapid succession. For every message, the sync actor emits an `Effect::GetDecidedValues` back to the host application.

This behavior results in two fatal resource exhaustion vectors:
1. **Database Flood:** The host application is flooded with synchronous or heavy I/O requests to load blocks from disk, completely saturating database read capacity and starving other critical node operations (like block processing or mempool validation).
2. **Memory Exhaustion (OOM):** The requested blocks are loaded into memory and buffered for the `GotDecidedValues` callback to be dispatched over the network. Processing an unbounded number of inflight requests causes the node to allocate memory continuously until it crashes with an Out-of-Memory (OOM) exception.

## Impact
A single unauthenticated, malicious peer can completely disable the node by causing a Denial of Service (DoS) via resource exhaustion. This disrupts network liveness, block production, and validation on the affected node.

## CVSS Assessment
**Severity:** High
**CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H (Score: 7.5)
- **Attack Vector (AV):** Network (Exploitable over the P2P layer).
- **Attack Complexity (AC):** Low (The attacker only needs to send repeated valid P2P messages).
- **Privileges Required (PR):** None (Any peer can send sync requests).
- **Availability (A):** High (Exhausts system memory and DB resources, causing node crash/unresponsiveness).

## Recommended Mitigation
The synchronization `State` struct must track the number of active/inflight inbound requests per peer to prevent unbounded queueing.

1. **Track Inflight Requests:** Add a mapping to the `State` struct to track active requests: `inbound_requests: HashMap<PeerId, usize>`.
2. **Enforce Concurrency Limits:** In `on_value_request`, check if the peer has exceeded a sane concurrent threshold (e.g., max 5 inflight requests). If they have, immediately drop the incoming `ValueRequest` or penalize the peer.
3. **Decrement Counter:** When `Input::GotDecidedValues` is processed and the response is sent back to the peer, decrement the active request counter for that `PeerId`.

```rust
// Proposed fix inside `on_value_request`
let inflight = state.inbound_requests.entry(peer_id).or_insert(0);
if *inflight >= MAX_CONCURRENT_INBOUND_REQUESTS {
    warn!(%peer_id, "Peer exceeded maximum concurrent value requests");
    // Optionally penalize peer: state.peer_scorer.update_score(peer_id, SyncResult::Failure);
    return Ok(());
}
*inflight += 1;
```
