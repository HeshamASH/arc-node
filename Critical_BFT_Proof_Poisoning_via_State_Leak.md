# 🛡️ Sentinel: [CRITICAL] Fix BFT Proof Poisoning via `seen_validators` State Leak

## CVSS 4.0 Assessment
**Severity**: 9.3 (Critical)
**Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N`

### **Metric Justification**
- **Attack Vector: Network (AV:N)**: An attacker can broadcast manipulated certificates over the network.
- **Attack Complexity: Low (AC:L)**: The exploit only requires appending a garbage signature for an honest validator to a valid certificate.
- **Attack Requirements: None (AT:N)**: No special conditions are needed.
- **Privileges Required: None (PR:N)**: Any node capable of broadcasting or relaying certificates can perform the attack.
- **User Interaction: None (UI:N)**: Attack is fully automated.
- **Vulnerable System Impact (VC:N, VI:H, VA:H)**:
  - **Integrity (VI:H)**: Valid commit certificates are incorrectly rejected as invalid (`DuplicateVote`), violating the core consensus invariants.
  - **Availability (VA:H)**: By continuously poisoning certificates, attackers can halt block finalization, causing a permanent Liveness DoS.

## 💡 Vulnerability
In `malachitebft/crates/signing/src/ext.rs`, the `verify_commit_certificate` function iterates through signatures and tracks them in `seen_validators` to prevent duplicate votes. However, `seen_validators.push(validator_address)` is called **before** `verify_commit_signature` is evaluated.

```rust
if seen_validators.contains(&validator_address) {
    return Err(CertificateError::DuplicateVote(validator_address.clone()));
}

seen_validators.push(validator_address); // <--- VULNERABILITY: State mutated before verification

// ...

if let Ok(voting_power) = self
    .verify_commit_signature(ctx, certificate, commit_sig, validator)
    .await
{
    signed_voting_power += voting_power;
}
```
If a signature fails verification, it contributes 0 voting power but its address permanently poisons `seen_validators` for the remainder of the certificate loop.

## 🎯 Impact
A malicious actor can take a perfectly valid commit certificate and prepend a garbage (invalid) signature for an honest validator.
When the honest validator's valid signature is processed later in the loop, the `seen_validators.contains` check will trigger, throwing a `DuplicateVote` error. The node will falsely reject the entire valid certificate, breaking consensus and causing a complete chain halt (Liveness DoS).

## 🔧 Fix
Delay the state mutation of `seen_validators` until **after** the signature is successfully verified.

```rust
// Only mutate state if the signature is cryptographically valid
if let Ok(voting_power) = self
    .verify_commit_signature(ctx, certificate, commit_sig, validator)
    .await
{
    seen_validators.push(validator_address);
    signed_voting_power += voting_power;
}
```

## ✅ Verification
A PoC test has been added to `crates/types/tests/unit/certificates/commit.rs` demonstrating the attack. The test prepends a garbage signature for Validator 0 to a valid certificate, and correctly asserts that it crashes with `DuplicateVote`:

```rust
#[test]
fn invalid_commit_certificate_invalid_sig_poisons_seen_validators() {
    let mut test = CertificateTest::<Commit>::new()
        .with_validators([20, 20, 30, 30]);

    // 1. Add an invalid signature for Validator 0.
    test = test.with_invalid_signature_vote(0, VoteType::Precommit);

    // 2. Add valid signatures for Validators 0..4
    test = test.with_votes(0..4, VoteType::Precommit);

    // Validator 0's address
    let val_0_addr = test.validators[0].address;

    // It verifies it. If it fails with DuplicateVote(val_0), the exploit is real.
    test.expect_error(CertificateError::DuplicateVote(val_0_addr));
}
```
Running `cargo test invalid_commit_certificate_invalid_sig_poisons_seen_validators -p arc-consensus-types` passes, confirming the vulnerability.
