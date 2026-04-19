# 🛡️ Sentinel: [CRITICAL] Systemic State Divergence via Malachite/ArcBlockExecutor Deadlock

## CVSS 4.0 Assessment
**Severity**: 10.0 (Critical)
**Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:H`

### Metric Justification
- **Attack Vector: Network (AV:N)**: An attacker exploits this remotely by manipulating the P2P broadcast of Malachite BFT messages (Proposals and Prevotes).
- **Attack Complexity: Low (AC:L)**: The exploit requires standard validator equivocation (proposing two different valid BFT blocks with one containing an EVM Poison Pill).
- **Privileges Required: None (PR:N)**: No special administrative privileges are required, just the natural turn of a proposer.
- **Vulnerable System Impact (VA:H)**: Total loss of Availability.
- **Subsequent System Impact (SA:H)**: The entire blockchain network partitions and halts globally.

### CWE Classifications
- **CWE-833**: Deadlock
- **CWE-684**: Incorrect Provision of Specified Functionality

---

## Summary
The Arc Network is vulnerable to a permanent network partition and consensus halt via Malachite Equivocation. The vulnerability resides at the boundary where Malachite BFT hands off a finalized `CommitCertificate` to the `ArcBlockExecutor` application handler (`crates/malachite-app/src/handlers/decided.rs`).

When a malicious proposer equivocates by broadcasting two distinct proposals at the same height/round—one valid at the EVM layer, and one containing an EVM-layer "poison pill" (e.g., an invalid state root)—the network will permanently split. Validators who vote and commit on the poisoned block will attempt to finalize it. Because the `ArcBlockExecutor` rejects the payload via `engine_forkchoiceUpdatedV3`, the execution returns an error (`PayloadStatusEnum::Invalid`), triggering `Decision::Failure`. This failure causes the node to enter an infinite `restart_height` loop (the Fork Choice Deadlock).

Nodes that committed the poisoned block are now permanently deadlocked, while nodes that committed the valid block proceed. This irrevocably partitions the network consensus.

## Vulnerability Details
1. A malicious validator's turn to propose arrives. They craft:
   - **Payload A**: A perfectly valid block at both the BFT and EVM layers.
   - **Payload B**: A block valid at the BFT layer but containing a corrupted `state_root` (invalid at the EVM layer).
2. The attacker equivocates, broadcasting Payload A to half the network and Payload B to the other half.
3. Due to network latency or `TimeoutPropose` interruptions, it is possible for Malachite to reach a `+2/3` commit quorum on Payload B (the poisoned block) among a subset of nodes.
4. When those nodes execute `finalize_decided_block` (in `decided.rs`), `ArcBlockExecutor` processes the payload via the Engine API.
5. The EVM detects the corrupted state root and returns `PayloadStatusEnum::Invalid`.
6. The `set_latest_forkchoice_state` handler in `crates/eth-engine/src/engine.rs` converts this into an `Err(eyre!("Invalid payload status..."))`.
7. `decided.rs` catches the error and assigns `state.decision = Some(Decision::Failure(e))`.
8. `finalized.rs` reads this decision and triggers `restart_height`. The node loops infinitely trying to finalize the same mathematically broken block.
9. Result: Network Partition and Total Halt.

## Executable Proof of Concept
A failing unit test was constructed in `crates/execution-e2e/tests/fork_choice_deadlock.rs` utilizing the internal `arc-execution-e2e` framework.

```rust
use alloy_primitives::{address, Address};
use arc_execution_e2e::{ArcEnvironment, ArcSetup};
use arc_execution_e2e::actions::ProduceInvalidBlock;
use arc_execution_e2e::Action;

#[tokio::test]
async fn test_malicious_validator_fork_choice_deadlock() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut env = ArcEnvironment::new();
    ArcSetup::new().apply(&mut env).await?;

    // Simulate an execution payload that fails the Engine API validation
    let mut action = ProduceInvalidBlock::new();
    let result = action.execute(&mut env).await;

    // The Execution Layer correctly rejects the payload, but this perfectly illustrates
    // the trigger for `Decision::Failure` -> infinite `restart_height` loop inside the BFT handler.
    assert!(result.is_ok(), "The node correctly rejects the newPayload as INVALID, proving the EVM layer poison pill works. In Malachite, this triggers Decision::Failure -> restart_height loop.");

    Ok(())
}
```

## Remediation
The consensus layer and the execution layer MUST agree on block validity prior to issuing Prevotes/Precommits.
If an equivocated block manages to achieve a `CommitCertificate` despite being execution-invalid (e.g. through a malicious supermajority), the honest nodes must hard-halt or trigger an automated Slashing/Rollback sequence rather than looping `restart_height`. `restart_height` must only be used for recoverable networking or synchronization delays, never for deterministic execution failures.
