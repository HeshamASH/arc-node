import re

with open("crates/evm/src/evm.rs", "r") as f:
    code = f.read()

replacement = """    #[test]
    fn test_zero_value_create_bypasses_blocklist() {
        use revm_primitives::{TxKind, Bytecode, keccak256};
        use arc_execution_config::{chainspec::localdev_with_hardforks, hardforks::ArcHardfork};

        let blocklisted_factory = address!("5555555555555555555555555555555555555555");
        let eoa = address!("1111111111111111111111111111111111111111");

        let factory_runtime: alloy_primitives::Bytes = vec![
            // push 0, push 0, push 0, create, push 0, mstore, push 32, push 0, return
            0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0xf0, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3
        ].into();

        let mut db = create_db(&[(eoa, 1_000_000), (blocklisted_factory, 1_000_000)]);
        db.insert_account_info(
            blocklisted_factory,
            revm::state::AccountInfo {
                balance: U256::from(100),
                code_hash: keccak256(&factory_runtime),
                code: Some(Bytecode::new_raw(factory_runtime.clone())),
                nonce: 1,
            },
        );

        // Add blocklisted factory manually
        let blocklist_entry_slot = arc_precompiles::native_coin_control::blocklisted_address_slot(blocklisted_factory);
        db.insert_account_storage(
            NATIVE_COIN_CONTROL_ADDRESS,
            blocklist_entry_slot,
            U256::from(1),
        ).unwrap();

        let chain_spec = localdev_with_hardforks(&[
            (ArcHardfork::Zero3, 0),
            (ArcHardfork::Zero4, 0),
            (ArcHardfork::Zero5, 0),
        ]);

        let mut evm = Context::mainnet()
            .with_db(db)
            .build_mainnet_with_inspector(
                revm_inspectors::tracing::TracingInspector::new(revm_inspectors::tracing::TracingInspectorConfig::default_geth())
            );

        let mut arc_evm = ArcEvmFactory::new(ArcHardforkFlags::with(&[ArcHardfork::Zero5]), std::sync::Arc::new(SubcallRegistry::new()))
            .create_arc_evm(&mut evm, chain_spec.spec_id());

        let tx = TxEnv {
            caller: eoa,
            kind: TxKind::Call(blocklisted_factory),
            value: U256::ZERO,
            gas_limit: 1_000_000,
            gas_price: 0,
            chain_id: Some(chain_spec.chain_id()),
            ..Default::default()
        };

        // transact_one is implemented on arc_evm. Wait, `test_zero5_transfer_log_precedes_precompile_log` does it
        // let result = arc_evm.transact_one(tx).expect("transact_one should succeed");
        // We'll just call `test_zero_value_create_bypasses_blocklist` here.

        // Wait, looking at `test_zero5_transfer_log_precedes_precompile_log` in evm.rs, it uses `create_db`, `setup_test_evm_with_db`? No, it uses:
        // `create_db`, then `ArcEvmFactory::new`, etc. Let's copy it.
    }
"""

with open("crates/evm/src/evm.rs", "w") as f:
    f.write(code.replace("    #[test]\n    fn test_zero5_transfer_log_precedes_precompile_log() {", replacement + "\n    #[test]\n    fn test_zero5_transfer_log_precedes_precompile_log() {"))
