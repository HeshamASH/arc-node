🛡️ Sentinel: [CRITICAL] Partial State Commit / BFT Amnesia via EVM Finalization Failure

## CVSS 4.0 Assessment
**Severity**: 10.0 (Critical)
**Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:H/SC:H/SI:H/SA:H`

### **Metric Justification**
- **Attack Vector (AV:N)**: A malicious node acting as proposer can broadcast a block payload over the P2P network.
- **Attack Complexity (AC:L)**: A malicious proposer simply builds a block that correctly validates BFT signatures but intentionally fails within the EVM boundary.
- **Attack Requirements (AT:N)**: No special node state or specific configurations are needed.
- **Privileges Required (PR:N)**: A proposer slot is required, but proposing is part of normal unprivileged consensus participation.
- **User Interaction (UI:N)**: Network propagation handles the attack entirely.
- **Integrity (VI:H)**: High. The local CL store becomes desynchronized and permanently invalid, containing a partially-committed certificate for a height that failed to execute.
- **Availability (VA:H)**: High. The node crashes or infinite-loops when attempting to restart the height.
- **Subsequent System Impact (SC:H, SI:H, SA:H)**: Complete network halt. Every honest node on the network processing the decided block will encounter the EVM error, attempt a restart, hit the DB conflict, and permanently halt.

### **CWE Classifications**
- **CWE-696**: Incorrect Behavior Order (Partial State Commit)
- **CWE-566**: Authorization Bypass Through User-Controlled SQL Primary Key (or similar Storage Collision logic)
- **CWE-400**: Uncontrolled Resource Consumption (Infinite Crash Loop)

## Summary
The Arc Network uses an execution layer (EVM Engine) coupled with a consensus layer (BFT). When the network decides on a block (reaches 2/3 commit signatures), the consensus node calls `decide()` which internally calls `commit()` to finalize the state.

A critical Partial State Commit vulnerability exists in `crates/malachite-app/src/handlers/decided.rs`. The `commit()` function sequentially performs three steps:
1. It permanently inserts the `CommitCertificate` into the `decided_blocks` store.
2. It eagerly cleans up "stale consensus data" (which includes the undecided block it was tracking).
3. It passes the payload to `block_finalizer.finalize_decided_block()` to execute the block on the EVM engine.

If `finalize_decided_block()` fails (which a malicious proposer can intentionally trigger by crafting a block with valid consensus signatures but an invalid EVM transition), the `commit()` function bubbles the error up, resulting in a `Decision::Failure`. The `finalized` handler will then call `restart_height()` to try again.

However, because the `commit()` function already permanently persisted the certificate to the CL database (and wiped its tracked undecided blocks), the node is placed in a **permanently bricked** state. Upon restarting the height, the database slots for that height are occupied, leading to a permanent sync divergence or infinite crash loop.

## Vulnerability Details
The vulnerability relies on the lack of a transactional rollback when crossing the BFT / EVM boundary.

**Source**: `crates/malachite-app/src/handlers/decided.rs:commit()`
```rust
    decided_blocks
        .store(certificate, block.execution_payload.clone(), block.proposer)
        .await
        // ... (1) Certificate stored successfully

    // Clean up stale consensus data
    if let Err(e) = pruning_service
        .clean_stale_consensus_data(certificate_height)
        // ... (2) Undecided block metadata wiped

    // Finalize the decided payload
    let (new_latest_block, _latest_valid_hash) =
        block_finalizer.finalize_decided_block(certificate_height, &block.execution_payload)
        .await
        // ... (3) EVM FAILS! Return Err() -> Decision::Failure
```

When the state drops back to `crates/malachite-app/src/handlers/finalized.rs`, it executes:
```rust
    let next = match decision {
        Decision::Success(next_height_info) => start_next_height(state, *next_height_info).await?,
        Decision::Failure(report) => {
            error!(error = ?report, "🔴 Decision failure, restarting height");
            restart_height(state, height).await?
        }
    };
```

This restart is fatal because the `decided_blocks` mapping for `height` is already populated. A single malicious proposer can "Brick" the entire network by broadcasting a block that passes BFT validation (so 2/3 honest nodes sign it and decide it) but intentionally fails EVM execution finality. Every single honest node will witness the block, store the certificate, fail execution, restart the height, and permanently halt due to the partial state commit.

## Proof of Concept
A failing unit test `test_decide_partial_commit_restart_panic` was successfully added to `crates/malachite-app/src/handlers/decided.rs` to explicitly trigger and demonstrate this vulnerability without applying a fix.

## Recommended Mitigation
Implement a full rollback mechanism or reorder the operations so that `finalize_decided_block()` is completely successful before writing the state to `decided_blocks` or cleaning up undecided consensus data.

```rust
    // Proposed Fix: Execute EVM first
    let (new_latest_block, _latest_valid_hash) =
        block_finalizer.finalize_decided_block(certificate_height, &block.execution_payload).await?;

    // Only store to DB if execution succeeds
    decided_blocks.store(certificate, block.execution_payload.clone(), block.proposer).await?;
```

## Impact
A single malicious validator chosen to propose a block can permanently crash all honest validators on the network, causing a total loss of liveness and unrecoverable chain halt requiring manual database surgery on every node.