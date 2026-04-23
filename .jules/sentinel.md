## 2024-05-24 - [Investigation] Precompile Call Authentication & Block Assembly Validation
**Vulnerability:** None found in Precompile contexts. Discovered intentional validation bypasses in `apply_pre_execution_changes` during block assembly.
**Learning:**
1. **Subcall Interception Safety**: `ArcEvm` safely intercepts subcalls by looking up `call_inputs.target_address`. This implicitly neutralizes `DELEGATECALL` spoofing against precompiles like `CallFrom`, because `DELEGATECALL` sets `target_address` to the calling contract, causing the registry lookup to yield `None` and safely fallback to empty bytecode execution.
2. **Assembler Validation Bypass**: `ArcBlockExecutor::apply_pre_execution_changes` deliberately swallows `Err` variants emitted by `protocol_config::retrieve_reward_beneficiary(&mut self.evm)`. If the internal system call fails, it logs a warning and proceeds without validating the block's beneficiary.
**Prevention:** N/A. The fallback is an explicit architectural decision to prevent chain halting if `ProtocolConfig` is deprecated.
