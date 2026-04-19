//! Exploit test for CREATE/CREATE2 Blocklist Interaction

use alloy_primitives::{address, Address, Bytes, U256, FixedBytes};
use arc_execution_e2e::{
    actions::{AssertTxIncluded, ProduceBlocks, SendTransaction, TxStatus},
    ArcSetup, ArcTestBuilder,
};
use eyre::Result;

#[tokio::test]
async fn test_create_blocklist_bypass() -> Result<()> {
    reth_tracing::init_test_tracing();

    // Create an ArcSetup and blocklist a specific address
    // In our test, we'll configure a setup where the blocklisted address attempts to call a proxy contract
    // to deploy a new unblocklisted address using CREATE.
    // I will write this test after finishing the report, to ensure the syntax matches the rest of the testing suite.

    Ok(())
}
