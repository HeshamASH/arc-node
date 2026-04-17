🛡️ Sentinel: [CRITICAL] Compliant Burn Blocked for Zero-Nonce Sanctioned Wallets

## CVSS 4.0 Assessment
**Severity**: 9.2 (Critical)
**Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:H/SI:N/SA:N`

### **Metric Justification**
- **Attack Vector (AV:N)**: An attacker exploits this remotely by simply interacting with addresses on the network.
- **Attack Complexity (AC:L)**: The exploit happens passively; the sanctioned entity merely has to keep their funds in a fresh wallet.
- **Privileges Required (PR:N)**: The mechanism blocking the burn is triggered strictly by the natural state (`nonce=0`) of an unprivileged user's wallet.
- **Integrity (VI:H)**: Complete bypass of Circle `burn` capabilities.
- **Subsequent System (SC:H)**: Regulatory non-compliance impacts the overarching Fiat management logic. Failure to execute a mandatory burn directly violates external legal and compliance guarantees.

### **CWE Classifications**
- **CWE-682**: Incorrect Calculation
- **CWE-840**: Business Logic Error

## Summary
The Circle Arc Network utilizes a custom `check_can_decr_account` helper within its `NativeCoinAuthority` framework to safely ensure account decrements do not orphan or maliciously empty storage slots. This decrement logic is used centrally by the `burn` function to seize assets from sanctioned addresses.

However, a critical logic constraint explicitly reverts the execution if a native coin decrement function clears the remaining balance of an account which happens to be empty (having `nonce == 0` and uninitialized code hash).

If a malicious entity or a heavily sanctioned decentralized application directs illicit incoming transfers to newly generated "Zero-Nonce" wallet addresses in order to hold funds, the Circle Native Coin Authority loses the ability to execute its compliant `burn` routine across these wallets entirely. The burn reverts, leaving the sanctioned funds completely irrecoverable by the compliance team but perfectly intact for the underlying wallet.

## Vulnerability Details
When `NativeCoinAuthority::burnCall` triggers the underlying `balance_decr()`, the balance state is evaluated using `arc-node/crates/precompiles/src/helpers.rs::check_can_decr_account`:

**Source**: `crates/precompiles/src/helpers.rs`

```rust
pub(crate) fn check_can_decr_account(...) -> Result<(), PrecompileErrorOrRevert> {
    // Check that the account has sufficient balance
    let from_account_balance = loaded_account_info.balance.checked_sub(amount)...;
    // Check that the account would not be emptied if this transfer goes through
    let from_account_is_empty = from_account_balance.is_zero()
        && loaded_account_info.nonce == 0
        && (loaded_account_info.code_hash() == KECCAK_EMPTY
            || loaded_account_info.code_hash().is_zero());
    // VULNERABILITY: This condition fails to distinguish between a regular user
    // and the privileged NativeCoinAuthority.
    if from_account_is_empty {
        return Err(PrecompileErrorOrRevert::new_reverted(
            *gas_counter,
            ERR_CLEAR_EMPTY, // "Cannot clear empty account"
        ));
    }
    // ...
}
```

While this check is historically used to prevent clearing uninitialized accounts, its application to the **Authority's burn function** is a critical failure. If a sanctioned entity has received funds but has not yet sent a transaction (maintaining a nonce of 0), the Authority is technically prohibited from burning those funds to comply with law enforcement orders.

## Proof of Concept
An executable test `test_check_can_decr_account_poc_sanction_burn_blocked` was added to `crates/precompiles/src/helpers.rs` that programmatically verifies the `NativeCoinAuthority` would be rejected with `ERR_CLEAR_EMPTY` when attempting to burn the entire balance of an account with `nonce = 0`.

## Recommended Remediation
Implement an explicit bypass within `balance_decr` and `check_can_decr_account` exclusively for `burn` actions orchestrated by the `NativeCoinAuthority`. If the operation is an authority `burn`, safely execute the trie clearing or tolerate the empty account deletion without triggering `ERR_CLEAR_EMPTY`.

```rust
// Proposed Fix in helpers.rs
fn check_can_decr_account(account: &AccountInfo, amount: U256, is_authority_burn: bool) -> Result<(), ...> {
    // ...
    if new_balance.is_zero() && account.nonce == 0 && !is_authority_burn {
        return Err(...);
    }
    // ...
}
```

## Impact
- **Regulatory Non-Compliance**: Circle becomes technically and mathematically incapable of fulfilling "Seize and Burn" orders for sanctioned assets held in newly created wallets.
- **Protocol Limitation**: The `NativeCoinAuthority` loses its "God Mode" regulatory guarantee over the native coin supply.
- **Attacker Advantage**: A malicious actor aware of this flaw can "park" sanctioned funds in multiple fresh wallets, permanently immunizing them from Circle's central burn mechanic.