// Copyright 2026 Circle Internet Group, Inc. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use alloy_primitives::{address, U256};
use arc_execution_config::hardforks::ArcHardfork;
use arc_execution_e2e::{
    actions::{AssertTxIncluded, ProduceBlocks, SendTransaction},
    chainspec::localdev_with_hardforks,
    ArcSetup, ArcTestBuilder,
};
use eyre::Result;

/// Test demonstrating the "Hardfork Boundary Gas Validation Asymmetry".
/// The mempool validates against `current_state_block` (where Zero6 is inactive) and accepts the tx.
/// During block execution, the EVM validates against `next_block_header` (where Zero6 is active),
/// triggering `CallGasCostMoreThanGasLimit` and causing block building to fail or the tx to be rejected.
/// If the node logic was correct, either the mempool rejects it early, or the block executes it fine.
/// But the mismatch results in the node failing to build the block.
#[tokio::test]
async fn test_zero6_boundary_asymmetry() -> Result<()> {
    reth_tracing::init_test_tracing();

    let chain_spec = localdev_with_hardforks(&[
        (ArcHardfork::Zero3, 0),
        (ArcHardfork::Zero4, 0),
        (ArcHardfork::Zero5, 0),
        // Zero6 activates at block 2.
        // At block 1, mempool will validate transactions against block 1 state (Zero6 false).
        // Then block 2 is built, which evaluates against block 2 (Zero6 true).
        (ArcHardfork::Zero6, 2),
    ]);

    // Send a transaction that has exactly enough gas for pre-Zero6 (21000)
    // but not enough for Zero6 (21000 + 4200 = 25200).
    // Mempool accepts it at block 1.
    // Execution fails at block 2.
    let res = ArcTestBuilder::new()
        .with_setup(ArcSetup::new().with_chain_spec(chain_spec))
        .with_action(ProduceBlocks::new(1)) // Advance to block 1
        .with_action(
            SendTransaction::new("boundary_mismatch")
                .with_to(address!("0000000000000000000000000000000000001337"))
                .with_value(U256::from(100))
                .with_gas_limit(21_000) // Exactly covers base intrinsic gas, NOT Zero6 penalty
        )
        // Produce block 2. The mempool successfully added it, but block building will fail
        // when `execute_transaction_without_commit` calls `transact`, returning `CallGasCostMoreThanGasLimit`.
        .with_action(ProduceBlocks::new(1))
        .with_action(AssertTxIncluded::new("boundary_mismatch"))
        .run()
        .await;

    // We expect the test framework to successfully build the blocks IF there is NO vulnerability.
    // BUT since there IS a vulnerability, `ProduceBlocks` will return an error when it tries to
    // build the block with the "poison" transaction.
    // Thus, `res` will be an Error, and asserting `res.is_ok()` will fail the test!
    assert!(
        res.is_ok(),
        "Simulated failure: Block execution failed due to Hardfork Boundary Gas Validation Asymmetry! Expected ok, got {res:?}"
    );

    Ok(())
}
