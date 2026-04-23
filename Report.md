## Sentinel Investigation Report: Compliance Gates & Block Assembly Bypasses

### Target 1: `mintCall` Authorization Path (`crates/precompiles/src/native_coin_authority.rs`)
1. **Authorization Check**: The authorization check relies directly on `precompile_input.caller != ALLOWED_CALLER_ADDRESS` under the active Zero5+ hardfork (`crates/precompiles/src/native_coin_authority.rs:223-228`).
2. **Delegatecall Check**: Yes, `check_delegatecall` is explicitly invoked immediately after authorization, ensuring the `context.address` is identically `NATIVE_COIN_AUTHORITY_ADDRESS` (`crates/precompiles/src/native_coin_authority.rs:245-249`).
3. **`CallFrom` Spoofing Path**: Although `CallFrom` can spawn a subcall where `child_inputs.caller` is spoofed to `ALLOWED_CALLER_ADDRESS`, an unauthorized user cannot leverage this. To trigger `CallFrom` via an allowlisted contract (e.g. `Multicall3From`), `Multicall3From` passes its *own* `msg.sender` (the unauthorized user) as the payload's `sender`, which ultimately fails the `precompile_input.caller != ALLOWED_CALLER_ADDRESS` check.

### Target 2: `CallFrom` Allowlist Enforcement (`crates/precompiles/src/subcall.rs` -> `crates/evm/src/evm.rs`)
1. **Validation Line**: The exact line that validates against the allowlist is `crates/evm/src/evm.rs:565` (`if !allowed_callers.is_allowed(&call_inputs.caller) {`).
2. **CallInputs Field**: The field used is `call_inputs.caller`.
3. **Call Scheme Population**: The `CallScheme::DelegateCall` populates the `caller` field with the executing context's caller (the parent's `msg.sender`), which differs from the tx originator if chained. *However*, under `DelegateCall`, the `target_address` becomes the *executing* contract (e.g., an unlisted attacker contract), not `CALL_FROM_ADDRESS`. Because `ArcEvm` uses `call_inputs.target_address` to look up the subcall registry (`crates/evm/src/evm.rs:563`), the registry lookup yields `None`. Thus, a `DELEGATECALL` to `CallFrom` bypasses the `ArcEvm` interception entirely and falls back to `revm`, which executes empty bytecode and does nothing. The allowlist remains fully secure.

### Target 3: Block Assembly Beneficiary Bypasses (`crates/evm/src/assembler.rs`)
1. **Execution During Assembly**: Yes, `apply_pre_execution_changes` is invoked during block assembly. `crates/evm/src/assembler.rs:74` delegates to `EthBlockAssembler::assemble_block(input)`, which inherently invokes the `ArcBlockExecutor`'s implementation of `apply_pre_execution_changes`.
2. **Validation Bypasses**: The beneficiary validation path in `apply_pre_execution_changes` explicitly contains *two* bypasses:
   * **Early-exit/Fallback (Error Case)**: `crates/evm/src/executor.rs:376-383`. The code uses `if let Ok(expected_beneficiary) = protocol_config::retrieve_reward_beneficiary(&mut self.evm)`. If the retrieval returns an `Err` (e.g., via `transact_system_call` failure or decode error), it enters `.inspect_err` to log a warning ("Failed to retrieve reward beneficiary...") and safely skips the remaining validation block entirely, intentionally designed to "avoid halting the chain".
   * **Empty Address Bypass**: `crates/evm/src/executor.rs:384`. The code contains `if expected_beneficiary != Address::ZERO`. If the retrieved beneficiary is identically the zero address, the mismatch validation is skipped.

---
**Verdict**: The targeted precompile execution paths are secure. However, the intentional fallback/bypasses discovered in the block assembler's beneficiary validation demonstrate a potential vector where consensus divergence could occur if a validator manipulates the `retrieve_reward_beneficiary` system call to deliberately fail, thereby gaining the ability to mint rewards to arbitrary unverified beneficiaries.
