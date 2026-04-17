Title:         Network Halt via Mempool / Block Builder Gas Validation Asymmetry (Zero6 Hardfork)
Scope:         https://github.com/circlefin/arc-node
Weakness:      Uncontrolled Resource Consumption
Severity:      Critical (9.3)
Link:
Date:          2026-04-17 12:00:00 +0000
By:            Sentinel
CVE IDs:
Details:
## Summary
The Arc Network is vulnerable to a targeted **Denial of Service (DoS) and Network Halt** due to a gas validation asymmetry between the Transaction Pool (Mempool) and the Block Builder (Executor).

Under the Zero6 hardfork, the core execution engine (`ArcEvmHandler::validate_initial_tx_gas`) adds an extra 2,100 to 4,200 gas (1-2 `PRECOMPILE_SLOAD_GAS_COST`) to the intrinsic gas cost of transactions to account for state blocklist checks. However, the `ArcTransactionValidator` in `crates/execution-txpool/src/validator.rs` does not include these additional costs when performing mempool validation.

An attacker can flood the network with standard native coin transfers (e.g., 21,000 gas limit). The mempool will evaluate the transactions as perfectly valid and include them in the transaction payload. During block assembly (`execute_transaction_without_commit` in `crates/evm/src/executor.rs`), the EVM engine calculates the intrinsic gas as 25,200. Because 25,200 exceeds the 21,000 gas limit, the engine throws an `InvalidTransaction::CallGasCostMoreThanGasLimit` error. The Block Executor directly maps this into a fatal `BlockExecutionError::evm` and halts block construction completely. This results in an unrecoverable chain halt for any validator attempting to propose a block.

## Vulnerability Detail
1. ### Mempool Accepts the Transaction
The `ArcTransactionValidator` in `execution-txpool` delegates gas limit validation to the standard `EthTransactionValidatorBuilder` (line 617, `validator.rs`). The standard ETH validator requires only 21,000 intrinsic gas for a standard `CALL` transaction with value. The mempool successfully queues the transaction.

2. ### The Execution Engine Rejects the Transaction
During execution, `ArcEvmHandler::validate_initial_tx_gas` evaluates the same transaction:
```rust
// crates/evm/src/handler.rs:119
if self.hardfork_flags.is_active(ArcHardfork::Zero6) {
    let mut extra_gas = PRECOMPILE_SLOAD_GAS_COST;
    if !tx.value().is_zero() {
        extra_gas += PRECOMPILE_SLOAD_GAS_COST; // +4,200 gas total
    }
    init_and_floor_gas.initial_gas = init_and_floor_gas.initial_gas.checked_add(extra_gas).ok_or(...)?;
    if init_and_floor_gas.initial_gas > tx.gas_limit() {
        // Fails here because 25,200 > 21,000
        return Err(InvalidTransaction::CallGasCostMoreThanGasLimit { ... }.into());
    }
}
```

3. ### The Network Halts
In `ArcBlockExecutor::execute_transaction_without_commit`, the returned error is mapped to a fatal `BlockExecutionError::evm` rather than being gracefully skipped or marked as a failed transaction.

```rust
// crates/evm/src/executor.rs:445
let result = self.evm.transact(tx_env)
    .map_err(|err| BlockExecutionError::evm(err, tx.tx().trie_hash()))?; // <--- HALTS BLOCK BUILDER
```
This forces the block builder to panic/revert entirely.

## Proof of Concept
1. The attacker creates 10,000 standard `CALL` transactions sending 1 wei to themselves or another EOA.
2. The attacker sets the `gasLimit` on all transactions exactly to `21,000`.
3. The attacker submits the transactions to the Arc Network RPC.
4. The RPC nodes (using `ArcTransactionValidator`) accept the transactions into the mempool because `21000 >= 21000` (standard intrinsic gas).
5. The Proposer attempts to construct the next block and pulls these transactions from the mempool.
6. The `executor.rs` attempts to `transact()` the first transaction. The EVM handler throws `CallGasCostMoreThanGasLimit`.
7. The `execute_transaction_without_commit` function returns `Err(BlockExecutionError::evm(...))`.
8. The block building process crashes. The Proposer misses their slot.
9. The next Proposer attempts the exact same process with the same mempool state, and also crashes. The network halts completely.

## CVSS 4.0 Assessment
**Severity**: 9.3 (Critical)
**Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:H/SI:H/SA:H`

### **Metric Justification**
- **Attack Vector: Network (AV:N)**: Triggered remotely by submitting standard transactions via RPC.
- **Attack Complexity: Low (AC:L)**: The exploit requires no custom opcodes, smart contracts, or specialized logic. It's just a standard transaction with a 21,000 gas limit.
- **Privileges Required: None (PR:N)**: Any unprivileged user can flood the mempool.
- **Availability Impact (VA:H)**: The entire network halts because the block builder crashes on processing.
- **Subsequent Impact (SC:H, SI:H, SA:H)**: Complete Denial of Service for the Arc Network and all relying applications.

## Recommendation
To prevent this asymmetry, the custom `ArcTransactionValidator` MUST implement the same Zero6 intrinsic gas calculation override as the `ArcEvmHandler`.

Modify `ArcTransactionValidator` (or the underlying standard `EthTransactionValidator`) to accurately calculate intrinsic gas including the `ArcHardfork::Zero6` blocklist `SLOAD` penalties, and reject transactions with insufficient gas limits at the mempool layer.

Alternatively, if a transaction fails the EVM validation strictly due to `CallGasCostMoreThanGasLimit` during `execute_transaction_without_commit`, the executor should log a warning and skip the transaction rather than returning a fatal `BlockExecutionError::evm` that halts block assembly.
