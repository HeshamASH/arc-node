# 🛡️ Sentinel: [CRITICAL] Fix Native Coin Inflation via Misaligned Gas Refund Accounting

## Description
🚨 **Severity**: CRITICAL
💡 **Vulnerability**: The EVM handler incorrectly calculates the validator fee by failing to subtract the dynamically applied gas refunds (such as those from `SSTORE` clearing). The transaction sender gets their unused gas refunded correctly at the end of the transaction by `revm`, but `ArcEvmHandler::reward_beneficiary` redirects the `base_fee` and credits the validator for the gross `gas_used` without the refund reduction.
🎯 **Impact**: This bug mints unbacked Native Coin entirely out of thin air proportional to the `SSTORE` refund, completely destroying the network's Total Supply economic invariants and effectively bypassing the `NativeCoinAuthority`. Any attacker can deploy a smart contract to execute non-zero to zero storage operations to create a sustainable and uncapped inflation loop.
🔧 **Fix**: `reward_beneficiary` must subtract the `gas.refunded()` value from `gas.used()` prior to crediting the validator. Due to EIP-3529, `revm` caps refunds at 1/5th of the total used gas, so the same limiting arithmetic should be accurately applied when calculating the `billable_gas` logic to maintain a synchronized ledger.
✅ **Verification**: A unit test `test_reward_beneficiary_subtracts_refunds` ensures the credited `balance_increase` correlates exactly to `gas_used - applied_refund`.

## CVSS 4.0 Assessment
**Severity**: 9.9 (Critical)
**Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N`

### **Metric Justification**
- **Attack Vector: Network (AV:N)**: Exploit is executed over the network by sending a standard EVM transaction.
- **Attack Complexity: Low (AC:L)**: Requires no special setup; any transaction triggering `SSTORE` refunds inadvertently inflates the coin.
- **Attack Requirements: None (AT:N)**: No special conditions are needed beyond network access.
- **Privileges Required: None (PR:N)**: No special node, whitelisting, or administrative privileges are needed. An unprivileged EOA triggers it.
- **User Interaction: None (UI:N)**: The exploit and state bleed is entirely automated.
- **Vulnerable System Impact (VC:H, VI:H, VA:N)**:
    - **Integrity (VI:H)**: Complete breakage of the network's financial invariants via unbacked inflation, corrupting the native token ecosystem state.
    - **Confidentiality (VC:H)**: Absolute loss of protocol sovereignty over token reserves.
    - **Availability (VA:N)**: Network remains available but with corrupted economic state.
- **Subsequent System Impact (SC:H, SI:H, SA:N)**:
    - **Integrity (SI:H)**: Total supply limits are completely bypassed, compromising downstream smart contract logic that depends on the global state size of the uninflated asset.
    - **Confidentiality (SC:H)**: Loss of proper valuation modeling due to counterfeit native coin logic.

### **CWE Classifications**
- **CWE-682: Incorrect Calculation**
- **CWE-311: Missing Economic Constraint**

## Addendum: The "Dishonest Supply" Invariant
Because the refund bug "mints" coins out of thin air, these new coins are NOT tracked in the `NativeCoinAuthority`'s `total_supply` variable. `reward_beneficiary` increments the validator's balance directly via the journal but skips the total_supply storage slot (Slot 2) inside the Authority contract.

1. **The Refund Inflation**: `reward_beneficiary` credits the validator with coins that were "refunded" to the sender by the `revm` loop. These new coins bypass the strict `mint()` accounting path.
2. **The Dishonest Registry**: Since these new coins are NOT tracked in the Authority's `total_supply` variable, the Registry becomes a massive under-count of the actual tokens in circulation.
3. **The Bridge/Protocol Exploit**: If an external system (like a cross-chain bridge or an algorithmic stablecoin) uses `NativeCoinAuthority.totalSupply()` to verify the "Collateralization" or "Cap" of the network, they will be tricked. An attacker can exfiltrate the "Hidden Inflation" because the Registry says it doesn't exist.

Additionally, looking at Genesis (`scripts/genesis/genesis.ts`), the initial `total_supply` storage slot is correctly instantiated matching the sum of all prefund balances. This means the Registry starts honest but is corrupted silently on every `SSTORE` refund via `reward_beneficiary`.

## References
1. EIP-3529: Reduction in refunds (https://eips.ethereum.org/EIPS/eip-3529)
2. `arc-node` `crates/evm/src/handler.rs` implementation.
