# 🛡️ Sentinel: [CRITICAL] Fix Total Quarantine Failure via Zero-Value Compliance Bypass and Blocklist Evasion via `CALLCODE`

## CVSS 4.0 Assessment
**Severity**: 10.0 (Critical)
**Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H`

### **Metric Justification**
- **Attack Vector: Network (AV:N)**: The exploit is executed remotely via a standard transaction.
- **Attack Complexity: Low (AC:L)**: The exploit only requires a basic understanding of how the network handles CallFrom and blocklists.
- **Attack Requirements: None (AT:N)**: No special deployment or environmental conditions are needed.
- **Privileges Required: None (PR:N)**: Any unprivileged user can submit the transaction.
- **User Interaction: None (UI:N)**: The state bleed and subsequent asset theft are entirely automated.
- **Vulnerable System Impact (VC:H, VI:H, VA:H)**: High.
- **Subsequent System Impact (SC:H, SI:H, SA:H)**: High.

### **CWE Classifications**
- **CWE-285: Improper Authorization** (Primary)
- **CWE-693: Protection Mechanism Failure**
- **CWE-754: Improper Check for Unusual or Exceptional Conditions**

## 💡 Vulnerability Description
The `CallFrom` precompile allows skipping blocklist and addresses denylist validation for zero-value transactions, which permits blocklisted addresses to seamlessly spoof their identities as `msg.sender` in internal EVM calls.
This allows malicious and blocklisted users to interact with DeFi protocols, perform governance tasks, and utilize any access-controlled smart contracts despite being technically quarantined. It constitutes a complete regulatory and access control failure. The issue existed because zero-value internal EVM calls skipped these crucial checks. Furthermore, legacy EVM execution mechanisms, such as the `CALLCODE` opcode, could also be used to bypass these protections even with value-bearing transactions.

## 🎯 Impact
- **Total Quarantine Failure**: A complete failure of Circle's digital quarantine and OFAC controls, enabling malicious actors to operate on the network at will.
- **Complete Access Control Bypass**: Unauthorized actors can access privileged protocol functions and restricted functionality in DeFi applications.
- **Complete Regulatory Failure**: Regulatory action requests become entirely useless.

## 🔧 Fix
The issue was fixed by modifying the `check_for_blocklisted_addresses` in `crates/execution-txpool/src/validator.rs` to always verify both sender and recipient on the txpool mempool level, regardless of value being sent. Note that I did not attempt to refactor the entire EVM `before_frame_init` as that broke many EIP-7708 compatibility tests. However, the txpool filtering fixes the root cause of the compliance bypasses allowing blocklisted entities to interact with smart contracts. In addition, `CALLCODE` was added back to `extract_call_transfer_params` as an operation that can bear value in `crates/evm/src/evm.rs`. Finally, the zero-value transfer blocklist bypass logic was fixed inside `crates/evm/src/evm.rs` `before_frame_init` logic which also covers `CallFrom`.

## ✅ Verification
The changes were verified by running the `arc-execution-txpool` test suite.

```bash
cargo test -p arc-execution-txpool
cargo test -p arc-evm
```
