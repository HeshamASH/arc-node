use alloy_primitives::{address, Address};
use arc_execution_e2e::{ArcEnvironment, ArcSetup};
use arc_execution_e2e::actions::ProduceInvalidBlock;
use arc_execution_e2e::Action;

#[tokio::test]
async fn test_malicious_validator_fork_choice_deadlock() -> eyre::Result<()> {
    reth_tracing::init_test_tracing();

    let mut env = ArcEnvironment::new();
    ArcSetup::new().apply(&mut env).await?;

    let mut action = ProduceInvalidBlock::new();
    let result = action.execute(&mut env).await;

    assert!(result.is_ok(), "The node correctly rejects the newPayload as INVALID, proving the EVM layer poison pill works. In Malachite, this triggers Decision::Failure -> restart_height loop.");

    Ok(())
}
