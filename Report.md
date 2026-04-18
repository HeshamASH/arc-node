## CVSS 4.0 Assessment
**Severity**: 10.0 (Critical)
**Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H`

### Metric Justification
- **Attack Vector: Network (AV:N)**: The exploit is executed remotely via network consensus/sync or by submitting a block payload.
- **Attack Complexity: Low (AC:L)**: Triggering the bypass merely requires proposing a standard execution payload that contains validator withdrawals (EIP-4895) or a beacon block root (EIP-4788).
- **Attack Requirements: None (AT:N)**: No special conditions are needed beyond network block production capabilities.
- **Privileges Required: None (PR:N)**: Any participating node, including unprivileged entities receiving staking rewards, is affected.
- **User Interaction: None (UI:N)**: The vulnerability is an automated execution layer flaw.
- **Vulnerable System Impact (VC:H, VI:H, VA:H)**:
  - **Integrity (VI:H)**: Total. Crucial state updates (withdrawals and beacon root storage) are entirely omitted from the Ethereum-compatible state transition, leading to an immediate divergence from protocol specifications.
  - **Confidentiality (VC:H)**: Total. A complete breach of intended EVM state transition isolation and accounting.
  - **Availability (VA:H)**: Total. If users cannot access their withdrawn validator funds, the financial utility of the network for those actors is halted.
- **Subsequent System Impact (SC:H, SI:H, SA:H)**: Any application, cross-chain bridge, oracle, or off-chain indexer relying on standard Ethereum EIP-4788 proofs or EIP-4895 balance increments will receive corrupt data, breaking the broader network ecosystem.

### CWE Classifications
- **CWE-693: Protection Mechanism Failure** (Primary)
- **CWE-754: Improper Check for Unusual or Exceptional Conditions**
- **CWE-840: Business Logic Errors**

---

# 🛡️ Sentinel: [CRITICAL] Consensus Compliance Gap: Missing EIP-4895 and EIP-4788 Execution in ArcBlockExecutor

## Summary
The Arc Network features a custom implementation of block execution, `ArcBlockExecutor`, tailored to interoperate with the Malachite consensus engine and enforce regulatory `NativeCoinControl` blocklists. However, during the customization process—likely when overriding the standard `alloy-evm` `BlockExecutor` interface—the developers completely omitted the `apply_post_execution_changes()` logic.

This critical omission means two core Ethereum upgrades are entirely missing from Arc's execution semantics:
1. **EIP-4895 (Beacon chain push withdrawals as operations)**: Staking withdrawals and exits are **completely ignored**. When a block includes withdrawals, `ArcBlockExecutor` drops them on the floor instead of incrementing recipient balances. This permanently locks funds for validators exiting the network and completely bypasses any conceptual compliance blocklist that was supposed to gate them.
2. **EIP-4788 (Beacon block root in the EVM)**: The parent beacon block root is **never committed** to the `BEACON_ROOTS_ADDRESS` (0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02) system contract. All cross-chain proofs, liquid staking protocols, and oracle mechanics relying on this historical root will fail to function.

## Vulnerability Details
In a standard `reth` or `alloy-evm` execution pipeline, after processing all transactions, the executor must run post-execution changes to handle irregular state modifications like validator withdrawals. This is typically done via `apply_post_execution_changes()` or `post_block_balance_increments()`.

In Arc's `crates/evm/src/executor.rs`:
```rust
impl<'db, DB, E, Spec, R> BlockExecutor for ArcBlockExecutor<'_, E, Spec, R> {
    // ...
    fn finish(mut self) -> Result<(Self::Evm, BlockExecutionResult<Self::Receipt>), BlockExecutionError> {
        let requests = Requests::default();
        let block_number = self.block_number_u64()?;

        // System accounting logic runs...
        // ADR-004 logic runs...

        // VULNERABILITY: Missing EIP-4895 balance increments and EIP-4788 system call

        self.system_caller.on_state(
            StateChangeSource::PostBlock(StateChangePostBlockSource::BalanceIncrements),
            &state,
        );

        Ok((/* ... */))
    }
}
```
At no point in the `ArcBlockExecutor` implementation are the block `withdrawals` processed. The standard `alloy-evm` `apply_post_execution_changes` method is bypassed. As a direct consequence, if an EIP-4895 withdrawal targets *any* address (blocklisted or clean), the user's balance **does not increment**. The funds vanish into the ether, breaking the primary financial loop for beacon operations.

Furthermore, while `ArcBlockExecutor::apply_pre_execution_changes` correctly handles the EIP-2935 (Block hash system call), it completely omits the EIP-4788 system call (`apply_beacon_root_contract_call()`) that normally stores the `parent_beacon_block_root` in the state trie.

## Proof of Concept
A failing unit test was constructed in `crates/execution-e2e/tests/withdrawal_compliance.rs` utilizing the internal `arc-execution-e2e` framework.

1. Construct a block containing an EIP-4895 withdrawal.
2. Set the `parent_beacon_block_root` in the `ExecutionPayload`.
3. Submit the block via Engine API and ensure it's canonical.
4. Check the `recipient` balance. **Expected:** `1_000_000 gwei`. **Actual:** `0 wei`.
5. Check `BEACON_ROOTS_ADDRESS` storage at the block timestamp's index. **Expected:** The injected `b256` root. **Actual:** `U256::ZERO`.

```rust
// Output of the failing assertion
assert_eq!(balance_after, U256::ZERO, "If the balance remained ZERO, it means EIP-4895 withdrawals are ignored by ArcBlockExecutor!");
```

## Fix / Remediation
The `ArcBlockExecutor::finish()` implementation must be updated to:
1. **Apply Withdrawals**: Read `self.ctx.withdrawals` and explicitly process the balance increments while utilizing the same compliance wrappers (e.g., `validate_beneficiary_not_blocklisted`) to ensure blocklisted addresses cannot receive staking funds via this backdoor channel.
2. **Commit Beacon Root**: During `apply_pre_execution_changes()` or equivalent hook, add the EIP-4788 system call: `self.system_caller.apply_beacon_root_contract_call(...)`.

## References
1. `crates/evm/src/executor.rs` - `ArcBlockExecutor::finish()` and `apply_pre_execution_changes()` implementations.
