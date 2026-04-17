Title:         Consensus State Corruption & Non-Determinism via Gas History Slot Aliasing
Scope:         https://github.com/circlefin/arc-node
Weakness:      Improper Preservation of Consistency Between Independent Representations of Shared State
Severity:      Critical (10.0)
Link:
Date:          2026-04-17 12:00:00 +0000
By:            Sentinel
CVE IDs:
Details:
## Summary
The Arc Network is vulnerable to a **Critical Consensus Failure** caused by an architectural flaw in how historical gas statistics are stored. The `SystemAccounting` precompile utilizes a ring-buffer strategy that causes multiple distinct block heights to alias to the same physical storage slot in the state trie.
This aliasing allows an attacker—or even normal network volatility—to cause permanent state corruption. Because the "Smoothed Gas Used" and "Base Fee" are state-dependent, any disagreement in these values across validators will result in different state roots, leading to a total network partition (Hard Fork) and loss of consensus.

## Vulnerability Detail
1. ### The Architectural Gap: ADR 0004 vs. Modulo 64
According to **Arc ADR 0004 ("Base Fee Validation")**, the network ensures block validity by asserting that the proposer's `nextBaseFee` in the block header matches the value deterministically stored in the `SystemAccounting` state.

However, the implementation of `compute_gas_values_storage_slot` utilizes a **Modulo 64** ring-buffer strategy for persistent trie storage. This creates a fundamental conflict:
- **ADR 0004** requires the state to be a source of truth for base fee validation.
- **The Modulo Implementation** causes that source of truth to be physically overwritten every 64 blocks.

**Source**: `crates/precompiles/src/system_accounting.rs:86-102`
```rust
pub fn compute_gas_values_storage_slot(block_number: u64) -> StorageKey {
    // Map block number into ring buffer
    let key_value = block_number % GAS_VALUES_RING_BUFFER_SIZE; // <--- VULNERABILITY
    // ...
}
```

2. ### Sync Non-Determinism & State Corruption
In a BFT network with "Instant Deterministic Finality," the integrity of the state trie is paramount. The current design introduces **State Non-Determinism** during node catch-up:
1.  **Linear Sync**: A node syncing from Block 0 will write `GasValues` to Slot `X` at Block 1, then overwrite it at Block 65, then again at Block 129.
2.  **Historical Integrity Failure**: If a validator or archive node is queried for the state of Block 1, the trie will return data for Block 193 (or whichever block most recently aliased to that slot).
3.  **Merkle Proof Failure**: Any external systems (bridges, L2s) relying on Merkle Proofs of historical gas statistics will find the proofs invalid because the trie nodes have been modified by a future, unrelated block.
4. **Sync Deadlock**: Because `retrieve_gas_values(parent_block)` is used by the execution logic to validate `nextBaseFee`, an archiving node syncing past a reorg or starting fresh will retrieve the overwritten future aliased state instead of the historical one. This leads to an immediate mismatch with `extra_data`, causing a network-wide consensus deadlock.

## Proof of Concept
- **Block 1**: `SystemAccounting` writes `GasValues_1` to `Slot_A` (since 1 % 64 = 1).
- **Block 65**: `SystemAccounting` writes `GasValues_65` to `Slot_A` (since 65 % 64 = 1). This blindly overwrites `GasValues_1`.
- **Consensus Failure**: A node verifying Block 1 during a state catch-up will compute its `state_root`. Because `Slot_A` now contains the values for Block 65, the computed state root will wildly mismatch the historical block header, and the node will completely halt syncing.

## CVSS 4.0 Assessment
**Severity**: 10.0 (Critical)
**Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H`

### **Metric Justification**
- **Attack Vector: Network (AV:N)**: State corruption is triggered automatically by regular network progression.
- **Attack Complexity: Low (AC:L)**: The vulnerability is an inherent logic flaw requiring no specialized effort.
- **Attack Requirements: None (AT:N)**: No conditional requirements are needed.
- **Privileges Required: None (PR:N)**: Unprivileged block progression naturally causes the aliasing.
- **User Interaction: None (UI:N)**: Fully automated state corruption.
- **Vulnerable System Impact (VC:H, VI:H, VA:H)**:
    - **Integrity (VI:H)**: Total. The integrity of the global state trie is permanently compromised.
    - **Availability (VA:H)**: Total. Discrepancies in the state trie root will cause validators to fail consensus and cease block production.
    - **Confidentiality (VC:H)**: High. Historical values are overwritten and permanently lost.
- **Subsequent System Impact (SC:H, SI:H, SA:H)**: Bridges and L2s relying on Arc state roots for settlement will encounter invalid proofs. The entire Arc ecosystem goes offline when the consensus layer halts.

### **CWE Classifications**
- **CWE-682**: Incorrect Calculation
- **CWE-664**: Improper Control of a Resource Through its Lifetime

## Recommendation
The storage slot for gas statistics **must be unique** for every block height. Remove the modulo operation from the storage slot calculation.

```rust
// crates/precompiles/src/system_accounting.rs
pub fn compute_gas_values_storage_slot(block_number: u64) -> StorageKey {
    // Use the absolute block number directly to prevent aliasing
    let key_value = block_number;

    // Left-pad 8 byte u64 to 32 bytes
    let mut key_bytes = [0u8; 32];
    key_bytes[24..].copy_from_slice(key_value.to_be_bytes().as_ref());

    // ...
}
```

## Impact
- **Historical State Loss**: Permanent corruption of historical gas and fee statistics in the global state trie.
- **Consensus Divergence / Sync Deadlocks**: Nodes entering the network via different sync strategies (Snap Sync vs. Full Sync) arrive at different trie configurations. An archiving or fresh node will fail to process historical blocks because their required gas values have been overwritten by future states.
- **Oracle / Bridge Failure**: Any external protocol validating cross-chain messages via Arc Merkle proofs will instantly break when the storage slots undergo aliased modifications.
