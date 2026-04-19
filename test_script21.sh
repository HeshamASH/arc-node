// Looking at the code above: `ArcTransactionValidator` calls `self.inner.validate_one_with_state(...)`.
// `self.inner` is an `EthTransactionValidator`.
// `EthTransactionValidator` validates the transaction's gas limit against standard intrinsic gas (21,000 for standard tx).
// But for Zero6, `ArcEvmHandler::validate_initial_tx_gas` charges an EXTRA 2,100 gas per blocklist check (caller and sometimes recipient).
// Does `ArcTransactionValidator` validate the gas limit using the Zero6 logic?
// No! It delegates to `self.inner`, which uses the standard `EthEvmConfig`.
// `ArcTransactionValidator` does NOT check if `transaction.gas_limit() >= 21000 + SLOAD_COST` when Zero6 is active.
// What happens if a transaction enters the mempool *before* Zero6 activates with gas limit 21000?
// Wait, even *during* Zero6, `ArcTransactionValidator` seems to lack the extra gas limit validation.
// Wait! Let's check `ArcEvmConfig::tx_validator` or how the mempool validator is built.
