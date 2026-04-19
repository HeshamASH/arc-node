// When `ArcBlockExecutor::execute_transaction` returns `BlockExecutionError::Validation(InvalidTx { error })`, the block assembler marks the tx as invalid.
// Wait, `CallGasCostMoreThanGasLimit` is part of `InvalidTransaction`.
// Let's check `BlockValidationError::InvalidTx`.
