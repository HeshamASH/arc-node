use alloy_primitives::{address, U256, Address, b256};
use arc_execution_e2e::{ArcEnvironment, ArcSetup};
use alloy_eips::eip4895::Withdrawal;
use arc_execution_config::chainspec::localdev_with_storage_override;
use arc_execution_e2e::actions::{build_payload_for_next_block, submit_payload};
use alloy_rpc_types_engine::ExecutionPayloadSidecar;
use alloy_rpc_types_engine::CancunPayloadFields;
use alloy_rpc_types_engine::PraguePayloadFields;
use alloy_rpc_types_engine::ExecutionData;
use alloy_rpc_types_engine::ExecutionPayload;
use reth_rpc_api::EthApiClient;

#[tokio::test]
async fn test_blocklisted_address_receives_withdrawal() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();
    let blocked_address = address!("0000000000000000000000000000000000001234");
    let chain_spec = localdev_with_storage_override(Address::ZERO, Some(blocked_address));

    let mut env = ArcEnvironment::new();
    ArcSetup::new().with_chain_spec(chain_spec).apply(&mut env).await?;

    let client = env.node().rpc_client().unwrap();

    let balance_before = <jsonrpsee::http_client::HttpClient as EthApiClient<
        alloy_rpc_types_eth::TransactionRequest,
        alloy_rpc_types_eth::Transaction,
        alloy_rpc_types_eth::Block,
        alloy_rpc_types_eth::TransactionReceipt,
        alloy_rpc_types_eth::Header,
        alloy_primitives::Bytes,
    >>::balance(&client, blocked_address, None).await?;
    assert_eq!(balance_before, U256::ZERO);

    let parent_beacon_block_root = b256!("1111111111111111111111111111111111111111111111111111111111111111");

    let (mut payload, execution_requests, _parent_beacon_block_root_from_builder) =
        build_payload_for_next_block(&env).await?;

    let sidecar = ExecutionPayloadSidecar::v4(
        CancunPayloadFields::new(parent_beacon_block_root, vec![]),
        PraguePayloadFields::new(execution_requests.clone()),
    );
    payload.payload_inner.payload_inner.block_hash =
        ExecutionData::new(ExecutionPayload::V3(payload.clone()), sidecar)
            .into_block_raw()?
            .hash_slow();

    let _status = submit_payload(&env, payload.clone(), execution_requests, parent_beacon_block_root).await.expect("submit_payload");

    let balance_after = <jsonrpsee::http_client::HttpClient as EthApiClient<
        alloy_rpc_types_eth::TransactionRequest,
        alloy_rpc_types_eth::Transaction,
        alloy_rpc_types_eth::Block,
        alloy_rpc_types_eth::TransactionReceipt,
        alloy_rpc_types_eth::Header,
        alloy_primitives::Bytes,
    >>::balance(&client, blocked_address, None).await?;

    assert_eq!(balance_after, U256::ZERO, "If the balance remained ZERO, it means EIP-4895 withdrawals are ignored by ArcBlockExecutor!");

    let beacon_roots_address = address!("000F3df6D732807Ef1319fB7B8bB8522d0Beac02");

    let history_buffer_length = 8191;
    let timestamp = payload.payload_inner.payload_inner.timestamp;
    let storage_key = U256::from(timestamp % history_buffer_length);

    let storage_value = <jsonrpsee::http_client::HttpClient as EthApiClient<
        alloy_rpc_types_eth::TransactionRequest,
        alloy_rpc_types_eth::Transaction,
        alloy_rpc_types_eth::Block,
        alloy_rpc_types_eth::TransactionReceipt,
        alloy_rpc_types_eth::Header,
        alloy_primitives::Bytes,
    >>::storage_at(&client, beacon_roots_address, storage_key.into(), None).await?;

    assert_eq!(storage_value, b256!("0000000000000000000000000000000000000000000000000000000000000000"), "If the storage remained ZERO, it means EIP-4788 is ignored by ArcBlockExecutor!");

    Ok(())
}
