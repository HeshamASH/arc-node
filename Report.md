# 🛡️ Sentinel: [AUDIT] PQ Precompile Attack Surfaces Assessment

## Overview
As part of the proactive vulnerability hunting sweep on the Arc Network, an investigation was conducted on the Post-Quantum (PQ) Precompile (`crates/precompiles/src/pq.rs`) specifically targeting three known attack surfaces common in new cryptographic precompile integrations:
1. **Signature Replay / Caching** (e.g., lack of chain ID).
2. **Malformed Key Length Panics** (e.g., buffer allocation or unwrapping errors causing DoS).
3. **Blocklist Evasion** (e.g., using the precompile to bypass `NativeCoinControl` checks).

## Findings
The PQ Precompile was thoroughly audited and **verified as secure** against these specific vectors.

### 1. Signature Replay / Caching
**Assessment**: Secure
- The `PqPrecompile` struct does not implement any internal caching mechanism.
- The `pq.rs` module correctly uses the stateless invocation pattern for precompiles.
- Replay protection is enforced at the transaction/account level (EVM nonces) or smart contract application logic layer rather than in the PQ precompile itself, matching standard EVM design (e.g., `ecrecover`).

### 2. Malformed Key Length Panics
**Assessment**: Secure
- The precompile safely implements input validation before delegating to the `slh-dsa` parser.
```rust
if args.vk.len() != VK_LEN {
    return Err(PrecompileErrorOrRevert::new_reverted(gas_counter, "Invalid verifying key length"));
}
```
- It explicitly uses `TryFrom` with `map_err` to safely handle parsing errors instead of unwrapping, avoiding potential node crashes (DoS) from untrusted inputs:
```rust
let verifying_key = SlhDsaVerifyingKey::<Sha2_128s>::try_from(args.vk.as_ref())
    .map_err(|_| PrecompileErrorOrRevert::new_reverted(gas_counter, "Failed to parse verifying key"))?;
```

### 3. Blocklist Evasion
**Assessment**: Secure
- Unlike `ecrecover`, which returns an EVM `Address` that can be misconstrued or spoofed to bypass controls, the PQ precompile acts purely as a cryptographic verification boolean oracle (`verifySlhDsaSha2128sCall`).
- It has no integration with the `CallFrom` precompile or `NativeCoinControl` directly. Address derivation and blocklist enforcement remain safely decoupled in the EVM handler `check_blocklist()`.

## Conclusion
The `pq.rs` precompile demonstrates excellent defense-in-depth security practices. No vulnerabilities were found in the targeted attack surfaces.
