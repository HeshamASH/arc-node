# 🛡️ Sentinel: [CRITICAL] Remote State Injection via Unverified Snapshot Extraction

## Description
🚨 **Severity**: CRITICAL
💡 **Vulnerability**: A critical infrastructure vulnerability exists in `crates/snapshots/src/download.rs`. The snapshot downloader fetches execution layer (`mdbx.dat`) and consensus layer (`store.db`) databases from an external URL and extracts them directly to the node's disk. At no point in the `resumable_download`, `extract_archive`, or `download_and_extract_both` lifecycle is the snapshot cryptographically verified. There are no checks for file hashes, signatures, or state roots against a trusted consensus proof prior to extraction.
🎯 **Impact**: An attacker who compromises the snapshot API, intercepts the connection (MITM), or spoofs the DNS/CDN can inject arbitrary, malicious blockchain state into the node. Since the node trusts the extracted database as its source of truth, this results in complete Remote State Injection. The attacker can arbitrarily alter balances, deploy malicious code, or spoof governance state, utterly breaking the security guarantees of the Arc Network for the affected node.
🔧 **Fix**:
1. The snapshot API must provide a cryptographic signature or hash (e.g., SHA256) of the archive.
2. The `download_and_extract` process must download the archive, verify its integrity against a trusted root/signature, and only proceed to extraction if verification succeeds.
*(Code Modification Note: As instructed, the fix is not applied to the source files.)*
✅ **Verification**: Code review confirms the absence of cryptographic verification. A PoC can be demonstrated by serving a manipulated `.tar.lz4` archive containing altered databases via a mock HTTP server.

## CVSS 4.0 Assessment
**Severity**: 9.5 (Critical)
**Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H`

### **Metric Justification**
- **Attack Vector: Network (AV:N)**: The exploit is executed remotely via network transport when the node initiates a snapshot download.
- **Attack Complexity: Low (AC:L)**: The exploit involves standard MITM techniques, DNS spoofing, or API compromise, requiring no specialized race conditions.
- **Attack Requirements: None (AT:N)**: The vulnerability is inherent in the snapshot download architecture.
- **Privileges Required: None (PR:N)**: An unauthenticated attacker in a privileged network position can serve the malicious payload.
- **User Interaction: None (UI:N)**: The node automatically syncs and extracts the data without user review of the contents.
- **Vulnerable System Impact (VC:H, VI:H, VA:H)**:
    - **Integrity (VI:H)**: Total compromise of the blockchain state database.
    - **Confidentiality (VC:H)**: Full access to any local state or potential subsequent arbitrary code execution within the node environment.
    - **Availability (VA:H)**: Complete denial of service; the node will serve false data or crash upon processing the poisoned state.
- **Subsequent System Impact (SC:H, SI:H, SA:H)**: If the poisoned node acts as an RPC provider or bridge authority, the corrupted state will cascade into upstream DApps, off-chain indexers, and bridges relying on the node's execution integrity.

### **CWE Classifications**
- **CWE-345: Insufficient Verification of Data Authenticity** (Primary)
- **CWE-494: Download of Code Without Integrity Check**

## References
1. **Missing Verification Logic**: [`crates/snapshots/src/download.rs`](https://github.com/circlefin/arc-node/blob/main/crates/snapshots/src/download.rs)
2. **Extraction without Checksum**: `extract_archive` in [`crates/snapshots/src/download.rs`](https://github.com/circlefin/arc-node/blob/main/crates/snapshots/src/download.rs)

## Proof of Concept (PoC)
To demonstrate the vulnerability, we can simulate an attacker intercepting the snapshot download request. Since there is no hash or signature verification, we can serve a forged `.tar.lz4` file containing a modified `mdbx.dat` (Execution Layer state).

### Reproduction Steps
1. The node initiates a sync and requests the latest snapshot URLs from `https://snapshots.arc.network/api`.
2. An attacker intercepts the connection (or compromises the CDN) and serves a malicious `.tar.lz4` archive.
3. The `download_and_extract` function streams the payload to a `.part` file using `reqwest` and immediately calls `extract_archive`.
4. `extract_archive` uncompresses the `.tar.lz4` using `lz4::Decoder` and unpacks the modified `mdbx.dat` directly into the node's `execution` directory.
5. The node restarts, loading the attacker's `mdbx.dat` containing fabricated balances and contract state, completely bypassing consensus validation.

```rust
    #[tokio::test]
    async fn test_snapshot_extraction_lacks_verification_poc() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let dest_dir = tmp_dir.path().join("dest");
        let staging_dir = tmp_dir.path().join("staging");

        let malicious_data = build_tar_lz4(&[("db/mdbx.dat", b"POISONED_STATE")]).unwrap();

        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200)
                .insert_header("Content-Length", malicious_data.len().to_string().as_str())
                .set_body_bytes(malicious_data))
            .mount(&mock_server)
            .await;

        let url = format!("{}/snapshot.tar.lz4", mock_server.uri());
        let dest_clone = dest_dir.clone();
        let result = tokio::task::spawn_blocking(move || {
            download_and_extract(&url, &dest_clone, &staging_dir)
        }).await.unwrap();

        assert!(result.is_ok(), "Extraction failed: {:?}", result.err());

        let content = std::fs::read(dest_dir.join("db/mdbx.dat")).unwrap();
        assert_ne!(content, b"POISONED_STATE", "SECURITY VULNERABILITY: Unverified malicious snapshot successfully downloaded and extracted!");
    }
```
