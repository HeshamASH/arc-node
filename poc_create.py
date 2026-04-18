import re

with open("crates/evm/src/evm.rs", "r") as f:
    code = f.read()

replacement = """        assert!(
            workspace_toml.contains(&expected),
            "revm version has changed from {EXPECTED_REVM_VERSION}. \
             Review all forked/mirrored revm functions listed in this test's doc comment."
        );
    }

    #[test]
    fn test_zero_value_create_bypasses_blocklist() {
        use arc_execution_config::{chainspec::localdev_with_hardforks, hardforks::ArcHardfork};
        use revm_primitives::TxKind;

        let blocklisted_factory = address!("5555555555555555555555555555555555555555");
        let eoa = address!("1111111111111111111111111111111111111111");

        let factory_runtime: alloy_primitives::Bytes = vec![
            0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0xf0, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3
        ].into();

        let chain_spec = localdev_with_hardforks(&[
            (ArcHardfork::Zero3, 0),
            (ArcHardfork::Zero4, 0),
            (ArcHardfork::Zero5, 0),
            (ArcHardfork::Zero6, 0),
        ]);

        let mut db = create_db(&[(eoa, 1_000_000)]);
        db.insert_account_info(
            blocklisted_factory,
            revm::state::AccountInfo {
                balance: U256::from(0),
                code_hash: revm_primitives::keccak256(&factory_runtime),
                code: Some(revm_primitives::Bytecode::new_raw(factory_runtime.clone())),
                nonce: 1,
                ..Default::default()
            },
        );

        let blocklist_entry_slot = arc_precompiles::native_coin_control::blocklisted_address_slot(blocklisted_factory);
        db.insert_account_info(
            NATIVE_COIN_CONTROL_ADDRESS,
            revm::state::AccountInfo {
                balance: U256::ZERO,
                nonce: 0,
                code_hash: revm_primitives::KECCAK_EMPTY,
                code: None,
                ..Default::default()
            },
        );
        db.insert_account_storage(
            NATIVE_COIN_CONTROL_ADDRESS,
            blocklist_entry_slot,
            U256::from(1),
        ).unwrap();

        let mut evm = revm::Evm::builder()
            .with_db(db)
            .build();

        let flags = ArcHardforkFlags::with(&[ArcHardfork::Zero5]);
        let mut precompile_map = ArcPrecompileProvider::create_precompiles_map(chain_spec.spec_id(), flags.clone());
        let mut arc_evm = ArcEvm {
            inner: ArcEvmInner {
                frame_stack: revm::handler::FrameStack::new(),
                ctx: evm.context.evm,
                precompiles: precompile_map,
            },
            spec_id: chain_spec.spec_id(),
            hardfork_flags: flags,
            subcall_continuations: std::collections::HashMap::new(),
            subcall_registry: std::sync::Arc::new(crate::subcall::SubcallRegistry::new()),
            inspect: (),
        };

        let tx = TxEnv {
            caller: eoa,
            kind: TxKind::Call(blocklisted_factory),
            value: U256::ZERO,
            gas_limit: 100_000,
            gas_price: 1,
            chain_id: Some(chain_spec.chain_id()),
            ..Default::default()
        };

        arc_evm.inner.ctx.journaled_state.load_account(NATIVE_COIN_CONTROL_ADDRESS, arc_evm.inner.ctx.db).unwrap();

        let result = arc_evm.transact_one(tx).expect("transact_one should succeed");
        assert!(
            result.is_success(),
            "Outer transaction should succeed; ZERO value CREATE bypasses blocklist, got {:?}",
            result
        );

        let state = result.state().unwrap();
        let expected_new_contract = blocklisted_factory.create(1);

        assert!(state.get(&expected_new_contract).is_some(), "New contract should be successfully created by the blocklisted factory");
    }
}
"""

code = re.sub(r'    }\n}\n*$', replacement, code)

with open("crates/evm/src/evm.rs", "w") as f:
    f.write(code)
