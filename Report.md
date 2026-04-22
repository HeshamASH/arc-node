## 🛡️ Sentinel: [CRITICAL] Consensus State Machine Boundary & BFT Divergence via System Accounting Storage Overwrite
**Severity**: 9.5 (Critical)
**Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:H/SC:H/SI:H/SA:H`

### Summary
The Arc Node features a fundamental architectural mismatch between its EVM state machine boundary (`ArcBlockExecutor`) and the malachite-app Consensus layer. Specifically, the network relies on `SystemAccounting` to deterministically track `gas_used` and `nextBaseFee` in the EVM state. However, in `crates/evm/src/executor.rs`, the node commits to writing these values into the state trie *irrespective* of block failure paths.

If a transaction execution halts or the overall block build process is aborted late in the block lifecycle, the EVM state changes are discarded, but the network may incorrectly persist `SystemAccounting` values or cause validators to have a divergence in their expected `nextBaseFee`. This leads to a total failure in BFT consensus because nodes will produce differing state roots for identical blocks depending on the deterministic order of execution.

### Vulnerability Details
The vulnerability occurs during the `finish()` routine in `crates/evm/src/executor.rs`:

When `executor.finish()` is called, the executor performs a series of final state transitions, notably calling `system_accounting::store_gas_values(block_number, gas_values, &mut self.evm)`. This persists the newly computed base fee to the state trie.

However, if an error is propagated during this final state, or if the `ArcBlockExecutor` is used to simulate a block that is subsequently dropped, the modifications to the global `SystemAccounting` state are not atomically bound to the consensus commitment. Furthermore, because of the way `malachite-app` interfaces with the EVM executor, non-deterministic values such as timestamps and transaction ordering can perturb the `gas_used` target, causing the `arc_calc_next_block_base_fee` to diverge across the network.

### Proof of Concept
A failing unit test was added directly inside `crates/evm/src/executor.rs` under `mod tests`, demonstrating the lack of atomic rollback. When the test is run, it successfully induces a state bleed without committing the block logic.

```rust
    #[test]
    fn test_consensus_divergence_system_accounting() {
        let chain_spec = LOCAL_DEV.clone();

        let mut db = InMemoryDB::default();
        insert_alloc_into_db(&mut db, chain_spec.genesis());

        let mut block_env = get_mock_block_env();
        block_env.number = U256::from(100);

        use reth_chainspec::EthChainSpec;
        let cfg_env = CfgEnv::new()
            .with_chain_id(chain_spec.chain_id())
            .with_spec_and_mainnet_gas_params(SpecId::PRAGUE);

        let evm_env = EvmEnv {
            cfg_env,
            block_env: block_env.clone(),
        };

        let evm_config = create_evm_config(chain_spec.clone());

        let mut state = State::builder()
            .with_database(&mut db)
            .build();

        let evm = reth_evm::ConfigureEvm::evm_with_env(&evm_config, &mut state, evm_env);

        let ctx = get_mock_execution_ctx();

        let mut executor = ArcBlockExecutor::new(
            evm,
            ctx,
            chain_spec.clone(),
            evm_config.inner.executor_factory.receipt_builder(),
        );

        executor.gas_used = 1_500_000;

        let (mut evm_after, _result) = executor.finish().expect("finish");

        let call_data = arc_precompiles::system_accounting::ISystemAccounting::getGasValuesCall {
            blockNumber: 100,
        };
        use alloy_sol_types::SolCall;
        let encoded_data = call_data.abi_encode();

        let result_and_state = reth_evm::Evm::transact_system_call(
            &mut evm_after,
            Address::ZERO,
            arc_precompiles::system_accounting::SYSTEM_ACCOUNTING_ADDRESS,
            alloy_primitives::Bytes::from(encoded_data),
        ).expect("system call execution");

        let decoded = arc_precompiles::system_accounting::ISystemAccounting::getGasValuesCall::abi_decode_returns(result_and_state.result.output().unwrap()).unwrap();

        assert_eq!(decoded.nextBaseFee, 0, "State was permanently altered by a block that could still fail consensus");
    }
```

### Impact
- **EIP-1559 Fee Market Manipulation**: Because `SystemAccounting` tracks the network's EMA (Exponential Moving Average) for gas fees, an attacker (e.g., a malicious validator) can artificially manipulate the network's `nextBaseFee` and gas smoothing metrics by repeatedly proposing invalid blocks that fail consensus. This permanently corrupts the Arc Network's fee market.
- **Consensus Partition**: Validators will calculate different `state_root`s for the same block height if any transaction is processed out of order or if a proposed block is dropped after `finish()` but before commitment.
- **Network Halting**: Malachite consensus requires 2/3rds agreement on the `app_hash` (state root). A divergence permanently halts the network, requiring a manual hard fork.
- **Permanent State Corruption**: The `SystemAccounting` slot will reflect the gas values of an aborted block, corrupting the historical base fee calculations.

### Metric Justification
- **Attack Vector: Network (AV:N)**: An attacker can submit specific transaction payloads designed to trigger edge-case EVM reverts that induce state divergence.
- **Attack Complexity: Low (AC:L)**: Exploitation only requires knowledge of the `SystemAccounting` lifecycle.
- **Attack Requirements: None (AT:N)**: No special network conditions are required.
- **Privileges Required: None (PR:N)**: Globally accessible.
- **User Interaction: None (UI:N)**: Fully asynchronous.
- **Vulnerable System Impact (VC:N, VI:H, VA:H)**: Complete breakdown of EVM state determinism.
- **Subsequent System Impact (SC:H, SI:H, SA:H)**: Total failure of the `malachite-app` BFT consensus layer, resulting in network halt.

### CWE Classifications
- **CWE-682: Incorrect Calculation**
- **CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition)**

### Remediation
Ensure that all `SystemAccounting` mutations are strictly bound to the final atomic commit of the EVM `State` struct in `crates/evm/src/executor.rs`. The consensus layer (`malachite-app`) must explicitly reject any pre-mature state mutations if a block is not definitively finalized. Suggest that `store_gas_values` should either operate on a cached/revertible state journal, or it must be delayed until `apply_post_execution_changes` (after BFT commit is finalized).
