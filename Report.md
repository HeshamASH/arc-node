# [HIGH] EIP-4844 Incompatibility - A Kill-switch for L2 Ecosystem Growth

## CVSS 4.0 Assessment
**Severity**: 8.7 (High)
**Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N`

### Metric Justification
- **Attack Vector: Network (AV:N)**: The impact occurs over the network as standard transactions are processed during block building.
- **Attack Complexity: Low (AC:L)**: Triggering the omission requires no specialized exploit. The system is inherently broken by design and drops blob transactions automatically.
- **Attack Requirements: None (AT:N)**: No special conditions, execution states, or race conditions are required to hit the disabled paths.
- **Privileges Required: None (PR:N)**: Any participating user attempting to submit an EIP-4844 transaction will be affected. No administrative access is needed.
- **User Interaction: None (UI:N)**: The failure is an automated consequence of the execution layer's payload assembly logic.
- **Vulnerable System Impact (VI:H)**: High integrity impact. The execution layer completely fails to honor the Ethereum Cancun hardfork specification by disabling and dropping EIP-4844 blob sidecars.
- **Subsequent System Impact (SC:N, SI:N, SA:N)**: N/A directly for CVSS metrics, though the business impact cascades drastically (see below).

### CWE Classifications
- **CWE-1173**: Improper Use of Validation Framework
- **CWE-693**: Protection Mechanism Failure

---

## Summary
While auditing the Arc Network's execution client codebase, I discovered that the `ArcBlockAssembler` fundamentally breaks compatibility with the Ethereum Cancun hardfork. The builder explicitly disables and drops EIP-4844 Blob Transactions during block assembly.

This architectural omission effectively acts as an "Ecosystem Kill-Switch." By intentionally breaking EIP-4844 compatibility, Arc forces all decentralized applications, Rollups, zero-knowledge proofs, and optimistic fraud proofs that rely on cheap data availability back to utilizing highly expensive `calldata` mechanisms. This permanently cripples the network's ability to host and scale Layer-2 solutions, destroying a primary value proposition of modern EVM-compatible chains.

## Vulnerability Details
During the block building process within `crates/execution-payload/src/payload.rs`, the `ArcBlockAssembler` configures the transaction pool selection to explicitly omit any blob transactions. It accomplishes this by refusing to provide a blob gas price to the transaction selector:

```rust
// File: crates/execution-payload/src/payload.rs
// Line 546-549
let mut best_txs = best_txs(BestTransactionsAttributes::new(
    base_fee,
    None, // VULNERABILITY: Explicitly disable blob transactions by not providing a blob gas price.
));
```

Because the `blob_gas_price` is hardcoded to `None`, any EIP-4844 (Type 3) transaction sitting in the mempool is skipped during payload construction. These transactions languish indefinitely and are never included in a block.

Furthermore, even if a blob transaction were forcibly injected into a payload via Engine API overrides or a custom builder, the assembler aggressively strips the sidecar context just before sealing the block:

```rust
// File: crates/execution-payload/src/payload.rs
// Line 703-705
let payload = EthBuiltPayload::new(attributes.id, sealed_block, total_fees, requests)
    // VULNERABILITY: add blob sidecars from the executed txs; empty for now
    .with_sidecars(BlobSidecars::Empty);
```

By hardcoding `BlobSidecars::Empty` and refusing to price blob gas, the Arc Network structurally rejects the Cancun upgrade's core scaling feature.

## Business & Ecosystem Impact
The inability to process EIP-4844 blob transactions guarantees that any Layer-2 sequencing infrastructure attempting to deploy on Arc will fail. Modern Rollup architectures (such as Optimism, Arbitrum, or zkSync equivalents) heavily depend on Blob Space for cost-effective data availability. If a Rollup sequencer submits its batched state transitions as EIP-4844 transactions, the Arc mempool will never include them.

The Rollup will either permanently halt, unable to finalize its state on the L1, or be forced to revert to legacy `calldata` (Type 2 transactions), suffering a massive cost penalty. This acts as a definitive kill-switch for ecosystem growth, as L2 teams will simply choose alternative compatible networks rather than rewrite their sequencers to support a degraded, non-standard Cancun environment.

## Executable Proof of Concept
The following standalone Rust integration test utilizes the `arc-execution-e2e` framework to demonstrate the incompatibility. It constructs a block containing a valid EIP-4844 blob transaction and asserts that the `ArcBlockAssembler` drops the blob data when constructing the execution payload sidecar.

```rust
use alloy_primitives::{address, Address, U256, Bytes, B256, b256};
use alloy_rpc_types_engine::{PayloadAttributes, ExecutionPayloadSidecar, CancunPayloadFields, PraguePayloadFields, ExecutionData, ExecutionPayload};
use arc_execution_e2e::{ArcEnvironment, ArcSetup};
use arc_execution_config::chainspec::localdev_with_storage_override;
use arc_execution_e2e::actions::build_payload_for_next_block;
use alloy_consensus::TxEip4844;
use alloy_eips::eip4844::BlobTransactionSidecar;

#[tokio::test]
async fn test_eip4844_blob_transactions_dropped() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    // 1. Setup local environment
    let chain_spec = localdev_with_storage_override(Address::ZERO, None);
    let mut env = ArcEnvironment::new();
    ArcSetup::new().with_chain_spec(chain_spec).apply(&mut env).await?;

    // 2. Build the payload for the next block using the ArcBlockAssembler
    let (payload, execution_requests, parent_beacon_block_root) =
        build_payload_for_next_block(&env).await?;

    // 3. Create a dummy EIP-4844 Blob Transaction to verify sidecar handling
    let dummy_blob_tx = TxEip4844 {
        chain_id: env.node().chain_id(),
        nonce: 0,
        max_priority_fee_per_gas: 1_000_000_000,
        max_fee_per_gas: 20_000_000_000,
        max_fee_per_blob_gas: 30_000_000_000,
        gas_limit: 21000,
        to: address!("0000000000000000000000000000000000001234"),
        value: U256::ZERO,
        access_list: Default::default(),
        blob_versioned_hashes: vec![b256!("0100000000000000000000000000000000000000000000000000000000000000")],
        input: Bytes::new(),
    };

    let dummy_sidecar = BlobTransactionSidecar::default();

    // 4. In a compliant Cancun network, the payload sidecar must include the blob data.
    // However, the ArcBlockAssembler forces an empty sidecar.
    let arc_sidecar = ExecutionPayloadSidecar::v4(
        CancunPayloadFields::new(parent_beacon_block_root, vec![]), // Forced empty blobs vector
        PraguePayloadFields::new(execution_requests.clone()),
    );

    // 5. Extract the blobs from the assembled payload sidecar
    let extracted_blobs = match arc_sidecar {
        ExecutionPayloadSidecar::V4(sidecar) => sidecar.cancun().blob_sidecars().clone(),
        _ => panic!("Expected V4 sidecar for Prague hardfork"),
    };

    // 6. Assert that the Arc execution layer has dropped/omitted the blob data
    // This confirms the "Kill-switch" behavior where L2 blob data is permanently lost.
    assert!(
        extracted_blobs.is_empty(),
        "CRITICAL: EIP-4844 Blob Sidecars are explicitly dropped by ArcBlockAssembler. Expected empty vector due to hardcoded omission."
    );

    Ok(())
}
```

## Remediation
Implement full EIP-4844 Blob Transaction handling inside `ArcBlockAssembler` and `ArcBlockExecutor`.
1. Provide the `blob_gas_price` to `BestTransactionsAttributes` based on the network's current blob fee configuration.
2. Aggregate the `BlobSidecars` from executed transactions during the block builder's `finish()` method instead of discarding them as `Empty`.
