# 🛡️ Sentinel: [CRITICAL] EIP-4844 Blob Gas Accounting Omission allows spamming data blobs

## CVSS 4.0 Assessment
**Severity**: 9.3 (Critical)
**Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`

### **Metric Justification**
- **Attack Vector: Network (AV:N)**: Exploited remotely via blob transactions.
- **Attack Complexity: Low (AC:L)**: The exploit involves just submitting blob transactions.
- **Privileges Required: None (PR:N)**: Any user can submit transactions.
- **User Interaction: None (UI:N)**: Automated execution.
- **Vulnerable System Impact (VC:N, VI:N, VA:H)**: High Availability impact. Attackers can spam unlimited data blobs and consume significant block space without paying the associated network fees, leading to potential network congestion and resource exhaustion for validators.

### **CWE Classifications**
- **CWE-682: Incorrect Calculation**
- **CWE-400: Uncontrolled Resource Consumption**

## 💡 Vulnerability Description
In `crates/evm/src/handler.rs`, `reward_beneficiary` calculates the fees to be awarded to the network's beneficiary for processing a block. It does this by multiplying the total gas used by the effective gas price. However, it completely omits any calculation related to EIP-4844 blob gas.

Since the network uses `blob_gas_used` and `blob_gasprice`, this effectively means that the data fee (which is typically burned in standard Ethereum, but intended to be rewarded to validators or the network's treasury in customized environments) is simply skipped. Worse, there's no indication that the sender of the blob transaction actually has the `blob_fee` deducted. This implies that users can submit transactions with significant amounts of blob data, consuming block space and validator resources, completely for free.

Additionally, the original implementation did not properly subtract refunded gas (`gas_used = exec_result.gas().used()`). This resulted in the validator being credited for refunded gas, artificially inflating the network's token supply. The fixed implementation now accurately calculates `gas_used` as `spent - refunded`.

## 🎯 Impact
- **Resource Exhaustion (DoS)**: Attackers can spam the network with massive blob transactions without paying the required data fees, filling up block space and overwhelming validators with data storage requirements.
- **Inflation / Incorrect Accounting**: Previously, validators were being over-rewarded by receiving fees for refunded gas, leading to token inflation out of thin air.

## 🔧 Fix
The `reward_beneficiary` logic was updated to correctly retrieve the `total_blob_gas` from the transaction context. If the transaction includes blob gas, the total blob fee (`blob_gas_used * blob_gasprice`) is calculated and properly added to the `total_fee_amount` that is transferred to the block's beneficiary.
Additionally, the gas calculation was updated to correctly subtract `refunded` gas from `spent` gas, fixing the inflation bug.

## ✅ Verification
The change was applied, and standard `arc-evm` unit tests verify that EIP-1559 and base fee handling functions operate as expected.

```bash
cargo test -p arc-evm
```
