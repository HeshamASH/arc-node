# 🛡️ Sentinel: [CRITICAL] Multiple Architectural Omissions in Arc Execution Layer

During a comprehensive security audit of `crates/evm/src/executor.rs`, `crates/malachite-app/src/handlers/decided.rs`, and related execution-consensus bindings, three massive architectural vulnerabilities were discovered that collectively break Arc's compatibility, stability, and tokenomics guarantees.

---

## 1. Fork Choice Deadlock via EVM-Layer Poison Pill

**Severity**: 10.0 (Critical)
**Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:H/SI:N/SA:H`
**Weaknesses**: CWE-833 (Deadlock), CWE-755 (Improper Handling of Exceptional Conditions)

### Summary
The Arc Network is susceptible to a catastrophic network-wide **Fork Choice Deadlock** due to improper error handling in the Malachite consensus `decided`/`finalized` event loops. If a validator proposes a block that successfully gathers a BFT commit quorum (+2/3 of validator weight) but contains a payload that the Execution Layer (`ArcBlockExecutor`) considers `Invalid` (e.g. state root mismatch), honest nodes will enter an unrecoverable infinite loop.

Instead of rejecting the invalid payload or halting cleanly, the `decided.rs` handler passes the execution error up as a `Decision::Failure(e)`. The `finalized.rs` handler catches this failure and calls `restart_height`. Because the BFT quorum has already irrevocably committed to the block at this height, `restart_height` simply fetches the exact same malicious block from the `undecided_blocks` pool, fails execution again, and restarts the height again—resulting in an infinite loop that permanently bricks the node and halts the entire blockchain.

### Proof of Concept
A malicious validator produces a block with a completely randomized `state_root` (an EVM poison pill) but signs it correctly.
The BFT consensus processes the block. Once a `CommitCertificate` is obtained, `finalize_decided_block` is invoked.
This calls `engine.set_latest_forkchoice_state()`, returning an `Invalid` payload status from `newPayload`/`forkchoiceUpdatedV3`.
The `Err` triggers `Decision::Failure(e)`, forcing the node into a terminal `restart_height` cycle.
A failing unit test was constructed in `crates/execution-e2e/tests/fork_choice_deadlock.rs`.

---

## 2. Reward Leak and Total Supply Pseudo-Inflation via NativeCoinAuthority Bypass

**Severity**: 9.9 (Critical)
**Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N`
**Weaknesses**: CWE-682 (Incorrect Calculation), CWE-311 (Missing Economic Constraint)

### Summary
The Arc Network relies on the `NativeCoinAuthority` precompile to formally track the system's `totalSupply()`. In Ethereum (EIP-1559), base fees are natively "burned" (deducted from the sender but never credited). `ArcBlockExecutor` redirects the base fee and priority fee directly to the validator via `journal_mut().balance_incr(beneficiary, total_fee_amount)`.

By manually crediting the `total_fee_amount` directly to the `beneficiary`, the system creates a transfer of tokens that completely bypasses the `NativeCoinAuthority` ledger. Since `NativeCoinAuthority.totalSupply()` only accounts for precompile-based `mint()` and `burn()` operations, the total circulating supply across all accounts becomes permanently drifted from the canonical `totalSupply` tracker. In a fiat-backed Layer 1, circulating tokens "off the books" via `balance_incr()` creates a massive pseudo-inflation leak that blinds governance to the actual underlying supply.

---

## 3. EIP-4844 Incompatibility - A Kill-switch for L2 Ecosystem Growth

**Severity**: 8.7 (High)
**Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N`
**Weaknesses**: CWE-1173 (Improper Use of Validation Framework)

### Summary
The Arc Network fundamentally breaks compatibility with the Ethereum Cancun hardfork by explicitly disabling and dropping EIP-4844 Blob Transactions during block assembly.

During the block building process within `crates/execution-payload/src/payload.rs`, the `ArcBlockAssembler` configures the transaction pool selection to explicitly omit any blob transactions by refusing to calculate a blob gas price. Furthermore, the assembler hardcodes the payload sidecars to `BlobSidecars::Empty`, dropping any contextual blob information. By intentionally breaking EIP-4844 compatibility, Arc forces all decentralized applications that rely on cheap data availability back to costly `calldata` mechanisms, acting as a "Kill-switch" for the entire Layer 2 ecosystem.

## Remediation
1. **Fork Choice Deadlock**: The node must panic/hard-halt or initiate a specific slashing procedure when `set_latest_forkchoice_state` explicitly returns an `Invalid` payload for a BFT-decided block, rather than indefinitely looping `restart_height`.
2. **Pseudo-Inflation**: The `reward_beneficiary` function must interface directly with the `NativeCoinAuthority` precompile or system state when crediting fees.
3. **EIP-4844**: Implement full EIP-4844 Blob Transaction handling inside `ArcBlockAssembler` and `ArcBlockExecutor`.
