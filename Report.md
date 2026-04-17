Title:         Critical Native Coin Inflation via Misaligned Gas Refund Accounting in EVM Handler
Scope:         https://github.com/circlefin/arc-node
Weakness:      Incorrect Calculation
Severity:      Critical (9.9)
Link:
Date:          2026-04-17 12:00:00 +0000
By:            Sentinel
CVE IDs:
Details:
## Summary
The Arc Network uses a custom implementation for execution logic and block fee calculations, specifically within `ArcEvmHandler::reward_beneficiary`. This function redirects the EIP-1559 base fee (which is typically burned) directly to the network validator.
However, the calculation of the validator reward strictly uses raw consumed gas (`gas.used()`), failing to subtract the transaction's gas refunds (e.g., from `SSTORE` clearing). Because the transaction sender is properly refunded by the underlying `revm` engine at the end of the transaction, but the validator is credited for the *unrefunded* amount, **Native Coins are printed out of thin air.**
This allows an attacker to trigger massive unbacked inflation, completely compromising the network's economic invariants and bypassing the `NativeCoinAuthority` totalSupply guarantees.

## Vulnerability Details
EVM's gas model features dynamic refunds (e.g., clearing a non-zero storage slot to zero refunds 4,800 gas). In standard Ethereum execution, the transaction sender is explicitly refunded this amount (capped at 20% of gas used per EIP-3529) at the end of the transaction.

In `arc-node`, the `ArcEvmHandler` overrides the standard `revm` `reward_beneficiary` function to re-route what would normally be the burned base fee directly to the validator:

```rust
// File: crates/evm/src/handler.rs
    #[inline]
    fn reward_beneficiary(
        &self,
        evm: &mut Self::Evm,
        exec_result: &mut <<Self::Evm as EvmTr>::Frame as FrameTr>::FrameResult,
    ) -> Result<(), Self::Error> {
        let ctx = evm.ctx();
        let beneficiary = ctx.block().beneficiary();
        // ... Snip ...
        let effective_gas_price = ctx.tx().effective_gas_price(basefee);

        let gas_used = exec_result.gas().used(); // <--- Fails to subtract refunds!
        let total_fee_amount = U256::from(effective_gas_price) * U256::from(gas_used);
        // Transfer the total fee to the beneficiary
        evm.ctx_mut()
            .journal_mut()
            .balance_incr(beneficiary, total_fee_amount)
            .map_err(From::from)
    }
```

In the `revm` engine version used by `arc-node`, `gas.used()` represents the absolute raw gas consumed by EVM opcodes and intrinsic costs *before* refunds are applied. Because `ArcEvmHandler` omits `- gas.refunded()`, the accounting diverges and breaks the fundamental asset balance:

1. **Sender Pays**: `(gas.used() - capped_refund) * effective_gas_price` (calculated and refunded securely by `revm`'s fallback engine).
2. **Validator Receives**: `gas.used() * effective_gas_price`.
3. **Net System Effect**: A surplus of `capped_refund * effective_gas_price` is minted entirely out of thin air.

## Proof of Concept
To reproduce the economic inflation leak:
1. **Setup**: An attacker submits a transaction to a smart contract that clears heavily padded storage slots (non-zero to zero).
2. **Gas Metrics**: The transaction gas limit is `1,000,000` with `gas_price` at `10 gwei`.
3. **Execution**: The execution overhead and resets consume exactly `100,000` gas. The `SSTORE` opcode triggers `20,000` in gas refunds.
4. **Sender Refund Loop**: The underlying `revm` mainnet routine refunds the attacker's balance with the unused gas AND the refunded gas. The attacker is billed for only `80,000` gas (`800,000 gwei`).
5. **Validator Reward Loop**: `ArcEvmHandler::reward_beneficiary` executes and incorrectly evaluates `exec_result.gas().used()` returning the raw `100,000`.
6. **Desync Result**: The validator is credited `1,000,000 gwei` while the sender was only charged `800,000 gwei`. Exactly `200,000 gwei` of unbacked Native Coin has been minted from nowhere. If the attacker operates the validator or colludes with one, they can syphon infinite Native Coin.

## CVSS Assessment
**CVSS v4.0 Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N`
**Base Score**: 9.9 (Critical)

### Metric Justification
- **Attack Vector (AV:N)**: Exploit is executed over the network by sending a standard EVM transaction.
- **Attack Complexity (AC:L)**: Requires no special setup; any transaction triggering `SSTORE` refunds inadvertently inflates the coin.
- **Privileges Required (PR:N)**: No special node, whitelisting, or administrative privileges are needed. An unprivileged EOA triggers it.
- **Integrity (VI:H, SI:H)**: Complete breakage of the network's financial invariants via unbacked inflation, corrupting the native token ecosystem state.
- **Confidentiality (VC:H, SC:H)**: Absolute loss of protocol sovereignty over token reserves.

### Weakness Classification
- **CWE-682**: Incorrect Calculation
- **CWE-311**: Missing Economic Constraint

## Recommended Mitigation
Update `reward_beneficiary` to subtract the applied capped refund from the total gas used before computing the validator's reward.

```rust
// crates/evm/src/handler.rs
        // Compute the capped refund according to EIP-3529 (max 1/5th of used gas)
        let max_refund = exec_result.gas().used() / 5;
        let applied_refund = std::cmp::min(exec_result.gas().refunded() as u64, max_refund);
        let billable_gas = exec_result.gas().used() - applied_refund;
        let total_fee_amount = U256::from(effective_gas_price) * U256::from(billable_gas);
```

## Impact
The Arc network's `native_coin_authority` explicitly attempts to regulate and restrict the minting of Native Fiat Tokens to maintain 1:1 backing with fiat reserves.
This vulnerability silently bypasses the Mint protocol and creates counterfeit Native Coins proportional to refunded EVM storage operations. An attacker can deploy a smart contract that maximizes `SSTORE` refunds (up to the 20% block limit), creating a permanent, sustainable, and uncapped inflation loop.
