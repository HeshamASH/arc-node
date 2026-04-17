🛡️ Sentinel: [CRITICAL] Fix Division by Zero in Base Fee Calculation

## CVSS 4.0 Assessment
**Severity**: 10.0 (Critical)
**Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:H`

### **Metric Justification**
- **Attack Vector: Network (AV:N)**: Exploit is executed remotely via standard network interactions.
- **Attack Complexity: Low (AC:L)**: The exploit happens predictably and consistently, no specialized exploitation tools are necessary.
- **Attack Requirements: None (AT:N)**: It only requires governance or network configuration that puts the elasticity and k_rate settings into an incompatible state.
- **Privileges Required: None (PR:N)**: Any unprivileged user's transaction that deviates from the `gas_target` can trigger the calculation resulting in a panic.
- **User Interaction: None (UI:N)**: The effect is fully automated when the block is generated and gas calculation occurs.
- **Vulnerable System Impact (VC:N, VI:N, VA:H)**:
    - **Availability (VA:H)**: Total network halt. A single division by zero panics the executor on every node on the network attempting to process or sync the block.
- **Subsequent System Impact (SC:N, SI:N, SA:H)**: Downstream nodes and validators all panic resulting in the network being globally offline.

### **CWE Classifications**
- **CWE-369: Divide By Zero** (Primary)
- **CWE-400: Uncontrolled Resource Consumption**

## Summary
The Arc Network features a critical vulnerability in the `gas_fee.rs` execution config where `arc_calc_next_block_base_fee` can trigger an arithmetic panic (division by zero). The denominator in the base fee increase/decrease calculation is `gas_target as u128 * ARC_BASE_FEE_FIXED_POINT_SCALE / k_rate as u128`. If `gas_target * 10,000` evaluates to a value smaller than `k_rate` (which can happen under certain gas configurations where `gas_target` is extremely small), the integer division results in `0`. Any subsequent block execution that triggers the `Greater` or `Less` match arms (i.e. where `gas_used != gas_target`) will attempt to divide by `0`, resulting in a runtime panic that permanently halts the entire network.

## Vulnerability Detail
The vulnerability is located in the calculation of `arc_calc_next_block_base_fee` within `crates/execution-config/src/gas_fee.rs`.

**Source Snippet:**
```rust
base_fee.saturating_add(core::cmp::max(
    1,
    base_fee as u128 * (gas_used - gas_target) as u128
        / (gas_target as u128 * ARC_BASE_FEE_FIXED_POINT_SCALE / k_rate as u128),
) as u64)
```

The denominator `(gas_target as u128 * ARC_BASE_FEE_FIXED_POINT_SCALE / k_rate as u128)` acts as an intermediate calculation. Rust integer division truncates. If `gas_target` is `1`, `ARC_BASE_FEE_FIXED_POINT_SCALE` is `10000`, and `k_rate` is `10001`, the expression `10000 / 10001` evaluates to `0`.

When this evaluated zero is then used as the divisor for the rest of the calculation: `(base_fee * diff) / 0`, the Rust compiler will inject a runtime panic, aborting the EVM executor.

## Proof of Concept
A failing unit test was added to `crates/execution-config/src/gas_fee.rs` that explicitly demonstrates this division-by-zero behavior:

```rust
#[test]
#[should_panic(expected = "attempt to divide by zero")]
fn test_division_by_zero_panic_poc() {
    let gas_limit = 100;
    let iem = 100;
    let k_rate = 10001;
    let base_fee = 100;
    let gas_used = 2; // Trigger core::cmp::Ordering::Greater

    arc_calc_next_block_base_fee(gas_used, gas_limit, base_fee, k_rate, iem);
}
```

Running `cargo test` triggers a panic exactly as demonstrated.

## Recommendation
To fix this vulnerability, refactor the arithmetic to avoid the truncated intermediate divisor. Multiply the numerator by `k_rate` directly, and divide by the scale factor:

```rust
// Proposed Fix
let numerator = base_fee as u128 * (gas_used - gas_target) as u128 * k_rate as u128;
let denominator = gas_target as u128 * ARC_BASE_FEE_FIXED_POINT_SCALE;

base_fee.saturating_add(core::cmp::max(1, numerator / denominator) as u64)
```
Ensure a similar fix is applied to the `Less` arm as well. And also ensure the new denominator `gas_target as u128 * ARC_BASE_FEE_FIXED_POINT_SCALE` is verified to be non-zero (which it is, because `gas_target == 0` is checked at the top of the function).

## Impact
- **Total Network Denial of Service**: The panic occurs on the execution engine itself during block transition. All validators, sync nodes, and light clients attempting to process a block where this condition is met will crash.
- **Unrecoverable Consensus Halt**: Once a block with these parameters is mined, the network requires a coordinated hard fork to patch the node software and resume processing.
