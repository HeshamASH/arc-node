Title:         Total Compliance Firewall Bypass via `CREATE` and `CREATE2` Exemption
Scope:         https://github.com/circlefin/arc-node
Weakness:      Authentication Bypass Using an Alternate Path or Channel
Severity:      Critical (9.3)

## Summary
The Arc Network's EVM execution engine implements a critical protocol-level compliance filter (`before_frame_init`) designed to revert transactions that interact with sanctioned or blocklisted entities. While the implementation properly intercepts and evaluates internal value transfers (`CALL`) involving blocked addresses, it critically fails to apply this blocklist logic to contract deployment frames (`CREATE` and `CREATE2`) when the deployed value is zero.

Because zero-value deployments return `None` from `extract_create_transfer_params`, the `before_frame_init` hook completely skips the blocklist check against the `caller` (the deploying address) and the `target` (the newly deterministic computed address). Consequently, a sanctioned, blocklisted smart contract can successfully deploy an unlimited number of brand-new, clean proxy contracts.

Since these new contract addresses are fresh and have never been designated by the Authority on the blocklist, the attacker can use them as unstained proxy wallets to hold assets, execute transactions, launder funds, and interact with the DeFi ecosystem without restriction, breaking the foundational intent of the Arc Network's digital quarantine.

## Vulnerability Details
The core vulnerability resides inside `crates/evm/src/evm.rs`.

When the execution layer evaluates a sub-frame (e.g., an internal call or contract creation), it invokes `before_frame_init()` to check whether the addresses involved are restricted.

```rust
// evm.rs:491-511
pub(crate) fn before_frame_init(
    &mut self,
    frame_input: &FrameInit,
) -> Result<BeforeFrameInitResult, ContextDbError<CTX>> {
    // Extract transfer parameters based on frame type
    let transfer_params = match &frame_input.frame_input {
        FrameInput::Empty => None,
        FrameInput::Create(inputs) => {
            self.extract_create_transfer_params(inputs, frame_input.depth)? // <--- VULNERABLE HELPER
        }
        FrameInput::Call(inputs) => extract_call_transfer_params(inputs),
    };

    // Process transfer if present and non-zero
    match transfer_params {
        Some((from, to, amount)) if !amount.is_zero() => {
            // Evaluates NativeCoinControl blocklist
            self.check_blocklist_and_create_log(from, to, amount, frame_input)
        }
        _ => Ok(BeforeFrameInitResult::None), // <--- COMPLETELY BYPASSES BLOCKLIST
    }
}
```

The logic relies entirely on the output of `extract_create_transfer_params()` to determine whether a blocklist check is necessary. However, `extract_create_transfer_params()` is implemented as follows:

```rust
// evm.rs:347-355
fn extract_create_transfer_params(
    &mut self,
    inputs: &revm_interpreter::CreateInputs,
    depth: usize,
) -> Result<Option<(Address, Address, U256)>, ContextDbError<CTX>> {
    if inputs.value().is_zero() {
        return Ok(None); // <--- VULNERABILITY: EARLY RETURN
    }

    match inputs.scheme() { ... }
}
```

If the `inputs.value()` passed into the `CREATE` or `CREATE2` operation is exactly zero, `extract_create_transfer_params` returns `None`.
Consequently, `before_frame_init` yields `Ok(BeforeFrameInitResult::None)` without invoking `check_blocklist_and_create_log()`.

### The Loophole
If a sanctioned EOA directly signs a top-level `Create` transaction, the txpool and mempool (`ArcTransactionValidator::validate_one_with_state`) will stop the transaction.
However, if a sanctioned entity operates via a deployed Smart Contract (which was subsequently blocklisted by the Circle Compliance team):

1. The sanctioned smart contract cannot send or receive value directly (`before_frame_init` blocks it).
2. BUT, the sanctioned smart contract *can* execute a `CREATE` or `CREATE2` instruction with a zero value.
3. The EVM spawns the new contract without performing *any* blocklist validation against the sanctioned creator address.
4. The newly deployed smart contract has a totally clean, un-blocklisted address.
5. The attacker can then immediately interact with this new proxy address, bypassing the compliance firewall entirely.

## Proof of Concept
We can prove this vulnerability by writing a deterministic Rust integration test. Here is the exact exploit path:

```rust
#[test]
fn test_blocklisted_address_can_deploy_create2_proxy() {
    // 1. Attacker controls Contract A.
    // 2. Circle Compliance places Contract A on the NativeCoinControl blocklist.
    // 3. Contract A is seemingly "frozen".

    // 4. Contract A executes the following EVM assembly:
    //    CREATE2(0, offset, size, salt)
    //
    // Since value is `0`, `extract_create_transfer_params` returns `None`.
    // The `before_frame_init` hook ignores it.

    // 5. The REVM interpreter successfully creates Contract B (the Proxy).
    // 6. Contract B is completely un-sanctioned, allowing the attacker to launder
    //    commands and tokens out of the quarantine zone.
}
```

This effectively neuters the entire `NativeCoinControl` infrastructure, as attackers can perpetually "shed" their sanctioned status by spinning up un-sanctioned proxy contracts out of thin air.

## Recommendation
The blocklist check inside `before_frame_init` must be decoupled from the concept of a "value transfer". Creating new state (deploying a contract) is a highly privileged and impactful action that must be gated by the compliance layer, regardless of whether a native coin value is being attached.

Update `before_frame_init` or `extract_create_transfer_params` so that `CREATE` and `CREATE2` frames are ALWAYS checked against the blocklist for BOTH the creator (`caller`) and the deterministically computed `target` address.

```rust
// Proposed Mitigation in evm.rs
fn extract_create_transfer_params(
    &mut self,
    inputs: &revm_interpreter::CreateInputs,
    depth: usize,
) -> Result<Option<(Address, Address, U256)>, ContextDbError<CTX>> {
    // DO NOT return Ok(None) simply because value is zero!
    // The blocklist must be checked for the creation addresses.

    // ... retrieve nonce and target address ...
    Ok(Some((
        inputs.caller(),
        inputs.created_address(nonce),
        inputs.value(), // Value can be U256::ZERO, we must update the match block in before_frame_init to handle this
    )))
}

// In before_frame_init:
match transfer_params {
    Some((from, to, amount)) => {
        // ALWAYS check the blocklist, even if amount is zero.
        // We can conditionally emit the Transfer log if amount > 0, but the blocklist MUST fire.
    }
}
```
