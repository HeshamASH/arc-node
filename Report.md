## 🛡️ Sentinel: [CRITICAL] Fix Blocklist Evasion via Spoofed Caller Context in SELFDESTRUCT

### **Severity**: 9.3 (Critical)
**Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:H/SI:N/SA:N`

### **Summary**
The Arc Network features a compliance blocklist mechanism designed to restrict transfers by sanctioned addresses. As part of this mechanism, `SELFDESTRUCT` instructions are heavily audited in `arc_network_selfdestruct_impl` (within `crates/evm/src/opcode.rs`). Specifically, the function checks both the source (the contract executing `SELFDESTRUCT`) and the target (the destination for the funds) against the `NativeCoinControl` blocklist.
However, it fails to evaluate the execution frame's `caller_address()` (i.e. `msg.sender`) against the blocklist. In standard EVM execution, this is usually identical to the EOA or contract initiating the sequence. However, within the Arc Network's unique subcall architecture—specifically via the `CallFrom` precompile—the `caller_address` can be artificially spoofed to bypass caller validations. A sanctioned user can route their transaction through an allowlisted caller proxy (like the `Multicall3From` contract), spoof a non-blocklisted proxy address as the caller, and successfully trigger a `SELFDESTRUCT` to move funds out of a non-blocklisted contract, entirely bypassing the compliance blocklist check on the true transaction originator.

### **Vulnerability Details**
In `crates/evm/src/opcode.rs`, the `arc_network_selfdestruct_impl` executes `check_selfdestruct_accounts` to enforce blocklist constraints:

```rust
// In `arc_network_selfdestruct_impl`
let addr = context.interpreter.input.target_address();
// ...
let Ok(is_target_cold) = check_selfdestruct_accounts(
    &mut context,
    addr, // Source address of the executing contract
    target, // Target destination address
    skip_cold_load,
    check_target_destructed,
) else {
    return;
};
```

And in `check_selfdestruct_accounts`:
```rust
// Check if either account is blocklisted
if is_blocklisted(context, target) || is_blocklisted(context, source) {
    // Revert logic...
}
```

This logic accurately verifies that neither the `target` nor the `source` (`addr` / `target_address`) are blocklisted. However, it explicitly omits a check against the `caller_address` (`msg.sender` context for the execution frame).

Because the `CallFrom` precompile (`crates/precompiles/src/call_from.rs`) intentionally allows allowlisted contracts to dispatch subcalls with an arbitrary, spoofed `caller_address`, an attacker can orchestrate a call sequence where the blocklisted true origin dictates the `target` but evades detection because the `SELFDESTRUCT` engine only validates `addr` and `target`.

### **Impact**
- **Total Compliance Bypass**: Sanctioned addresses can utilize proxies and the `CallFrom` precompile to successfully orchestrate `SELFDESTRUCT` transfers, evading the "Digital Quarantine" restrictions.
- **Regulatory Failure**: Failure to enforce the blocklist undermines the core value proposition and regulatory commitments of the Arc Network.

### **Proof of Concept**
A failing integration test demonstrating the issue can be structured by simulating an execution frame where the `caller_address` is blocklisted, but the `target_address` (the contract holding funds) and the `target` (the destination) are not blocklisted.

```rust
    #[test]
    fn test_selfdestruct_caller_bypass() {
        let mut env = HostTestEnv::new(EmptyDB::new());
        let amount = U256::from(42);

        let contract_address = address!("0x2222222222222222222222222222222222222222");
        let target_address = address!("0x3333333333333333333333333333333333333333");
        let caller_address = address!("0x1111111111111111111111111111111111111111");

        env.set_account_balance(contract_address, amount);

        let mut interpreter = Interpreter::<EthInterpreter>::default();
        interpreter.gas = Gas::new(1000000);
        interpreter.input.target_address = contract_address;
        interpreter.input.caller_address = caller_address;
        let _ = interpreter.stack.push(U256::from_be_slice(target_address.into_word().as_ref()));

        // Blocklist ONLY the caller
        env.set_blocklist(caller_address);

        env.host.journal_mut().load_account(native_coin_control::NATIVE_COIN_CONTROL_ADDRESS).unwrap();

        let context = InstructionContext {
            interpreter: &mut interpreter,
            host: &mut env.host,
        };
        arc_network_selfdestruct_impl(context, true, Some(TransferLogMode::Eip7708Transfer));

        let next_action = interpreter.take_next_action();
        let res = match next_action {
            InterpreterAction::Return(result, ..) => result,
            _ => panic!("Expected Return action"),
        };

        // The selfdestruct improperly succeeds because caller is ignored!
        assert_eq!(res.result, InstructionResult::SelfDestruct, "Caller bypass check");
    }
```

### **Recommended Fix**
Modify `check_selfdestruct_accounts` (or `arc_network_selfdestruct_impl`) to also evaluate `context.interpreter.input.caller_address()` against the blocklist, alongside `source` and `target`.

```diff
<<<<<<< SEARCH
    // Check if either account is blocklisted
    if is_blocklisted(context, target) || is_blocklisted(context, source) {
=======
    // Check if either account or the caller is blocklisted
    let caller = context.interpreter.input.caller_address();
    if is_blocklisted(context, target) || is_blocklisted(context, source) || is_blocklisted(context, caller) {
>>>>>>> REPLACE
```
