## CVSS 4.0 Assessment
**Severity**: 10.0 (Critical)
**Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H`

### **Summary**
The Arc Network features a system-wide blocklist (`NativeCoinControl`) to enforce regulatory compliance. The execution layer enforces these checks in `before_frame_init` during EVM processing. However, a critical vulnerability exists where the blocklist checks are completely bypassed for zero-value `CREATE` and `CREATE2` frames. Because `before_frame_init` only enforces the blocklist if `!amount.is_zero()`, a blocklisted address can successfully deploy new smart contracts via zero-value internal calls (e.g., using a factory contract). The newly deployed contract receives a clean, non-blocklisted address, allowing the sanctioned entity to use it as a proxy to bypass all restrictions and interact with the network freely.

### **Vulnerability Details**
1. **Flawed Enforcement Logic**: In `crates/evm/src/evm.rs:491-511`, `before_frame_init` is responsible for checking the blocklist for nested frames:
```rust
    pub(crate) fn before_frame_init(
        &mut self,
        frame_input: &FrameInit,
    ) -> Result<BeforeFrameInitResult, ContextDbError<CTX>> {
        // Extract transfer parameters based on frame type
        let transfer_params = match &frame_input.frame_input {
            FrameInput::Empty => None,
            FrameInput::Create(inputs) => {
                self.extract_create_transfer_params(inputs, frame_input.depth)?
            }
            FrameInput::Call(inputs) => extract_call_transfer_params(inputs),
        };

        // Process transfer if present and non-zero
        match transfer_params {
            Some((from, to, amount)) if !amount.is_zero() => {
                self.check_blocklist_and_create_log(from, to, amount, frame_input)
            }
            _ => Ok(BeforeFrameInitResult::None), // <--- BYPASS
        }
    }
```
2. **CREATE Extraction**: The `extract_create_transfer_params` explicitly returns the caller and the newly created address, along with the value (`inputs.value()`).
3. **The Bypass**: If a blocklisted address (or a contract operating on its behalf) initiates a `CREATE` or `CREATE2` frame with `value = 0`, the `amount.is_zero()` condition is met. The `match` falls through to `_ => Ok(BeforeFrameInitResult::None)`, and the frame is executed without any blocklist checks. The blocklisted entity has successfully created a new, unblocklisted contract proxy.

### **Impact**
This represents a total failure of the network's compliance and security invariants. A blocklisted entity can indefinitely spawn new proxies to move assets, participate in governance, or interact with decentralized applications, rendering the blocklist completely ineffective.

### **Fix**
The `match` logic in `before_frame_init` must be updated to explicitly catch `CREATE` and `CREATE2` frames and enforce the blocklist check on the creator's address regardless of the `amount` attached.

```rust
        match transfer_params {
            Some((from, to, amount)) => {
                if !amount.is_zero() || matches!(frame_input.frame_input, FrameInput::Create(_)) {
                    self.check_blocklist_and_create_log(from, to, amount, frame_input)
                } else {
                    Ok(BeforeFrameInitResult::None)
                }
            }
            _ => Ok(BeforeFrameInitResult::None),
        }
```
*(Code Modification Note: As instructed, the fix is not applied to the source files.)*

### **Verification**
To verify, deploy a smart contract that acts as a factory using `CREATE`. Add an address to the blocklist. Have the blocklisted address invoke the factory with `value = 0`. The factory will successfully deploy a new contract on behalf of the blocklisted user, bypassing the compliance controls.

## Sentinel Additional Finding: EVM-SELFDESTRUCT Blocklist Bypass
During the investigation of the `before_frame_init` blocklist bypass, Sentinel has identified another critical instance of "Value Control" erroneously replacing "Entity Control" within the EVM execution layer.

In `crates/evm/src/opcode.rs`, the `arc_network_selfdestruct_impl` function is responsible for handling the `SELFDESTRUCT` opcode. However, the blocklist validation (`check_selfdestruct_accounts`) and zero-address validation are placed inside a `match` arm that requires `!balance.is_zero()`:

```rust
    let is_cold = match addr_balance.clone() {
        Some(balance) if !balance.is_zero() => { // <--- BYPASS for 0-value
            // Zero5: reject SELFDESTRUCT to zero address (prevents burn-like semantics)
            if matches!(log_mode, Some(TransferLogMode::Eip7708Transfer))
                && target == alloy_primitives::Address::ZERO
            {
                // ... Revert
            }

            // Checks the source and target account is valid or not.
            let Ok(is_target_cold) = check_selfdestruct_accounts(
                &mut context,
                addr,
                target,
                skip_cold_load,
                check_target_destructed,
            ) else {
                return;
            };

            is_target_cold
        }
        None => { // ... }
        _ => None, // <--- 0-balance falls through here, skipping ALL checks!
    };

    let res = match context
        .host
        .selfdestruct( ... ) // <--- Execution proceeds
```

Because of this shortcut, a blocklisted contract with a balance of `0` can successfully invoke `SELFDESTRUCT` targeting *any* address, completely bypassing the compliance checks. This allows sanctioned entities to clear state and potentially execute `CREATE2` and `SELFDESTRUCT` cycling attacks.

### **Fix for SELFDESTRUCT**
The `check_selfdestruct_accounts` function must be called unconditionally on the `SELFDESTRUCT` opcode, regardless of whether the contract currently holds any native coin balance.
