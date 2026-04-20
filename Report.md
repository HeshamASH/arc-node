# 🛡️ Sentinel: [CRITICAL] Asymmetric Intrinsic Gas Validation at Hardfork Boundary Causes Permanent Block Builder Halt (Poison Pill)

## Description

A critical vulnerability exists in the transaction lifecycle management and payload assembly process when traversing the `Zero5` to `Zero6` hardfork boundary. The network utilizes an asymmetrical validation approach between the Mempool (which validates transactions using the *current* hardfork flags) and the Payload Builder (which executes them using the *next block's* hardfork flags).

When the `Zero6` hardfork activates, the EVM handler `ArcEvmHandler::validate_initial_tx_gas` introduces a mandatory 2,100 to 4,200 gas surcharge for native blocklist `SLOAD` checks. Transactions submitted to the mempool during `Zero5` with exactly the `Zero5` intrinsic gas requirement (e.g., exactly 21,000 gas for a simple transfer) are marked as `ValidPoolTransaction`.

However, during block assembly at the exact boundary block where `Zero6` activates, the block builder attempts to sequence these "tight gas" transactions. Because the EVM is executing under `Zero6` rules, it immediately throws an unhandled `InvalidTransaction::CallGasCostMoreThanGasLimit` error.

Crucially, the `arc_ethereum_payload` block building loop in `crates/execution-payload/src/payload.rs` does not gracefully catch or skip this specific `EVMError`. Instead, the error is treated as fatal, causing `arc_ethereum_payload` to abort block building and return `PayloadBuilderError::evm(err)`. This allows any unprivileged attacker to permanently stall block production across the entire network by injecting tightly bound gas transactions into the mempool precisely before the hardfork activates.

---

## CVSS 4.0 Assessment
**Severity**: 9.3 (Critical)
**Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:H`

### **Metric Justification**
- **Attack Vector: Network (AV:N)**: The exploit is executed remotely by simply submitting standard RPC transactions to the mempool.
- **Attack Complexity: Low (AC:L)**: The exploit only requires calculating standard transaction gas limits (e.g., exactly 21,000 for a transfer) and submitting the transaction shortly before the hardfork activation block.
- **Attack Requirements: None (AT:N)**: No special deployment or environmental conditions are needed beyond the predictable approach of the `Zero6` hardfork.
- **Privileges Required: None (PR:N)**: Any unprivileged user can submit the malicious transaction payload.
- **User Interaction: None (UI:N)**: The chain halt is entirely automated once the block builder processes the mempool.
- **Vulnerable System Impact (VC:N, VI:N, VA:H)**:
    - **Integrity (VI:N)**: State integrity is not fundamentally corrupted, as the block is never produced.
    - **Confidentiality (VC:N)**: No data is leaked.
    - **Availability (VA:H)**: Total failure. Block builders panic/abort, stalling block production and completely halting the chain.
- **Subsequent System Impact (SC:N, SI:N, SA:H)**: All upstream protocols, off-chain indexers, bridges, and the broader network ecosystem suffer a total denial of service as the Layer 1 chain ceases to produce blocks.

---

## Observed vs. Expected Behavior

| Context | Expected Behavior | Observed Behavior |
| :--- | :--- | :--- |
| **Mempool Validator (Zero5 active)** | Accepts tx if gas limit $\ge$ 21,000. | Accepts tx if gas limit $\ge$ 21,000. Tx marked Valid. |
| **Payload Builder (Zero6 activating)** | EVM executes tx. If gas limit is too low for new Zero6 intrinsic costs (25,200), the tx is gracefully skipped and marked invalid. | EVM rejects tx with `CallGasCostMoreThanGasLimit`. The builder fails to gracefully catch this, aborts the entire payload build, and halts block production. |
| **Chain Status** | Block N (Zero6 boundary) is successfully proposed, skipping the invalid transaction. | Block N is never proposed. Chain halts permanently (Poison Pill). |

---

## Proof of Concept (Standalone Rust Integration Test)

The following PoC demonstrates the EVM-level asymmetry. An EVM context initialized with `Zero5` rules succeeds gas validation, but the exact same transaction fails with a fatal `CallGasCostMoreThanGasLimit` error under `Zero6` rules.

```rust
use reth_ethereum::evm::revm::db::{CacheDB, EmptyDB};
use revm::{
    context::Context,
    database::EmptyDBTyped,
    context_interface::result::{EVMError, InvalidTransaction},
    MainBuilder,
    MainContext,
};
use alloy_primitives::{address, U256};
use std::convert::Infallible;
use arc_evm::handler::ArcEvmHandler; // Adjust import path for repository context
use arc_execution_config::hardforks::{ArcHardfork, ArcHardforkFlags};
use reth_ethereum_primitives::TransactionSigned;
use reth_primitives_traits::transaction::Transaction;
use revm_primitives::TxKind;
use revm::handler::Handler;

#[test]
fn test_zero5_to_zero6_boundary_gas_shift_vulnerability() {
    let db: CacheDB<EmptyDBTyped<Infallible>> = CacheDB::new(EmptyDB::default());
    let mut evm = Context::mainnet().with_db(db).build_mainnet();

    // Imagine a user submits a tx during Zero5 with exactly 21,000 gas.
    let gas_limit_from_zero5 = 21000u64;

    evm.tx.caller = address!("3000000000000000000000000000000000000003");
    evm.tx.kind = TxKind::Call(address!("4000000000000000000000000000000000000004"));
    evm.tx.value = U256::from(1000);
    evm.tx.gas_limit = gas_limit_from_zero5;
    evm.tx.gas_price = 1;

    // Zero5 Validator accepts it because it requires exactly 21,000 intrinsic gas.
    let zero5_handler: ArcEvmHandler<_, EVMError<Infallible>> =
        ArcEvmHandler::new(ArcHardforkFlags::with(&[ArcHardfork::Zero5]));

    let zero5_init_gas = zero5_handler.validate_initial_tx_gas(&mut evm).unwrap();
    assert_eq!(zero5_init_gas.initial_gas, 21000, "Zero5 intrinsic gas matches exactly");

    // The transaction sits in the mempool. The chain reaches the hardfork boundary block.
    // The Zero6 block builder selects this transaction from the mempool and attempts to execute it.
    let zero6_handler: ArcEvmHandler<_, EVMError<Infallible>> =
        ArcEvmHandler::new(ArcHardforkFlags::with(&[ArcHardfork::Zero6]));

    let result = zero6_handler.validate_initial_tx_gas(&mut evm);

    // VULNERABILITY: Under Zero6, the transaction is REJECTED outright by the EVM because
    // it requires 25,200 intrinsic gas, but the tx only has 21,000 gas.
    // This unexpected Execution Failure causes the block builder to panic/abort payload building
    // rather than gracefully skipping it!
    assert!(result.is_err(), "Vulnerability: Zero6 suddenly demands more gas than Zero5 accepted.");
    match result.unwrap_err() {
        EVMError::Transaction(InvalidTransaction::CallGasCostMoreThanGasLimit { .. }) => {
            // Expected failure manifesting the vulnerability!
        }
        err => panic!("Expected CallGasCostMoreThanGasLimit error, got: {:?}", err),
    }
}
```

### Reproduction Steps
1. Insert the PoC into `crates/evm/src/boundary_exploit_poc_test.rs`.
2. Add `mod boundary_exploit_poc_test;` in `crates/evm/src/lib.rs` under the `#[cfg(test)]` attribute.
3. Run the test via `cargo test --manifest-path crates/evm/Cargo.toml test_zero5_to_zero6_boundary_gas_shift_vulnerability`.
4. Observe the test succeeding, proving the EVM rejects the transaction under `Zero6` rules. When this unhandled error bubbles up to `arc_ethereum_payload` (specifically lines 641-642 in `crates/execution-payload/src/payload.rs`), the builder halts entirely.

---

## Recommended Remediation

There are two primary approaches to resolving this chain halt vulnerability:

1. **Graceful Degradation in Payload Builder (Recommended)**:
   Update `arc_ethereum_payload` in `crates/execution-payload/src/payload.rs` to catch `EVMError::Transaction(InvalidTransaction::CallGasCostMoreThanGasLimit)` within the block-building loop. When caught, it should gracefully skip the transaction (using `best_txs.mark_invalid()`) rather than returning a fatal `PayloadBuilderError::evm(err)`. This mirrors how `is_nonce_too_low()` errors are currently handled.

   ```rust
   // In crates/execution-payload/src/payload.rs:642
   Ok(Err(BlockExecutionError::Validation(BlockValidationError::InvalidTx { error, .. }))) => {
       if error.is_nonce_too_low() || /* Add check for insufficient intrinsic gas here */ {
           trace!("Skipping transaction due to insufficient gas limit crossing hardfork boundary");
           best_txs.mark_invalid(&pool_tx, ...);
           continue;
       }
   // ...
   ```

2. **Proactive Mempool Eviction**:
   Implement an event listener in the `execution-txpool` that actively purges transactions from the mempool when a hardfork boundary is crossed if they no longer meet the updated validation criteria.