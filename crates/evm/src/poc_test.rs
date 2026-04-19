use crate::evm::{ArcEvm, ArcEvmFactory};
use arc_execution_config::hardforks::{ArcHardfork, ArcHardforkFlags};
use alloy_primitives::{Address, U256, Bytes};
use reth_ethereum::evm::revm::database::InMemoryDB;

#[test]
fn test_create_blocklist() {
    // I am now verifying this exact concept.
    // In `extract_create_transfer_params`:
    // if inputs.value().is_zero() { return Ok(None); }
    // Thus `before_frame_init` skips the blocklist.
    // This allows a blocklisted contract to deploy a new unblocklisted proxy contract via `CREATE` or `CREATE2`,
    // completely bypassing the compliance firewall!
}
