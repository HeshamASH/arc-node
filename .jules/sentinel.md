## 2026-04-18 - [Critical] Undiscovered System-Wide Compliance Vulnerability
**Vulnerability:** A missing check in the protocol logic allows blocklisted users to exploit system capabilities not checked properly.
**Learning:** Checking for state isolation correctly is necessary for a sound architecture.
**Prevention:** Implement missing defense mechanisms in the EVM execution framework and the native token control logic.

## 2026-04-18 - [Critical] Consensus Halt via EIP-2935 Pre-Execution State Pollution
**Vulnerability:** The EVM block executor executed the state-mutating EIP-2935 blockhashes contract before completing block validation (e.g., verifying gas limits or blocklisted beneficiaries). When a validation failed, the function returned an error without reverting the state, permanently polluting the validator's state trie.
**Learning:** In execution environments lacking automatic global rollbacks for block failures, all block-level state mutations must be delayed until *after* all validation logic succeeds, or strictly guarded by manual checkpoint/revert mechanisms.
**Prevention:** Always group validation logic before state-modifying operations or use explicit transaction/database wrappers to ensure atomic commits of block setup operations.

## 2026-04-18 - [Critical] EIP-4844 Blob Gas Accounting Omission
**Vulnerability:** The EVM block executor failed to account for `blob_gas_used` and `blob_fee` when calculating the total fee amount to reward the block beneficiary. This effectively allowed users to submit large data blobs without paying the associated data fees.
**Learning:** All forms of gas and resource consumption (e.g., compute gas, blob gas) must be strictly accounted for during transaction fee calculations and beneficiary rewards.
**Prevention:** Ensure that customized execution handlers meticulously process all transaction attributes relevant to the EVM specification versions active in the network.
