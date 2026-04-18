🛡️ Sentinel: [CRITICAL] BFT Proof Poisoning via Signature Verification State Leak (NEW-17)

## CVSS 4.0 Assessment
**Severity**: 10.0 (Critical)
**Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:H/SC:H/SI:H/SA:H`

### **Metric Justification**
- **Attack Vector (AV:N)**: Exploitable remotely. A malicious proposer can broadcast a poisoned `CommitCertificate` over the P2P network to all honest nodes.
- **Attack Complexity (AC:L)**: The attacker simply intercepts or computes a valid `CommitCertificate` (which has 2/3+ valid signatures) and prepends a single byte-garbled signature to the front of the list, reusing the identity of an honest validator.
- **Attack Requirements (AT:N)**: The vulnerability is constantly exposed in the core BFT message validation handler.
- **Privileges Required (PR:N)**: No special privileges are required. While proposing a block typically requires being the elected leader for a round, P2P network flooding or gossip interception can propagate invalid certificates globally.
- **User Interaction (UI:N)**: Automated message validation triggers the exploit.
- **Integrity (VI:H)**: High. The core BFT invariant (2/3+ valid signatures = consensus) is completely broken. Valid consensus proofs are evaluated as invalid.
- **Availability (VA:H)**: High. The entire network grinds to a halt. When a valid round completes, but the certificate is poisoned in transit or via a malicious proposer, the honest nodes will reject the proof. They will time out, escalate to the next round, and the attacker can repeatedly poison the next round's certificates, leading to a permanent finality halt.
- **Subsequent System Impact (SC:H, SI:H, SA:H)**: A complete disruption of the Execution Layer and any protocols relying on Arc Network's finality guarantees.

### **CWE Classifications**
- **CWE-696**: Incorrect Behavior Order (State Leak on Error)
- **CWE-354**: Improper Validation of Array Index (or similar Unordered Set logic)
- **CWE-345**: Insufficient Verification of Data Authenticity

## Summary
The Arc Network uses the `malachitebft` core dependency for BFT consensus. When validating a block, nodes must verify that a block has achieved a `CommitCertificate` containing signatures from >= 2/3 of the total voting power.

A critical **State Leak on Error** vulnerability exists in `verify_commit_certificate()` (`crates/signing/src/ext.rs` inside the `malachitebft` dependency tree). The loop evaluating signatures eagerly adds the validator's address to a `seen_validators` local tracking set *before* fully validating that the signature is actually cryptographically valid. When an invalid signature is encountered, the code swallows the validation error without aborting, but the `seen_validators` state remains polluted.

An attacker can exploit this by "poisoning" a perfectly valid `CommitCertificate`. By prepending a single invalid, fake signature for an honest validator at the start of the list, the honest validator is added to `seen_validators`. When the loop reaches the *actual*, mathematically valid signature for that honest validator later in the list, the code hits the `seen_validators.contains()` guard and instantly aborts the entire certificate with `CertificateError::DuplicateVote`.

This allows an attacker to permanently stall consensus by intercepting valid commit certificates, poisoning them, and gossiping the poisoned variants, tricking all honest nodes into rejecting valid finality proofs.

## Vulnerability Details
The flaw lies in the sequencing of state mutation vs. cryptographic validation in the signature loop:

**Source**: `malachitebft/crates/signing/src/ext.rs`
```rust
    async fn verify_commit_certificate(...) -> Result<(), CertificateError<Ctx>> {
        let mut signed_voting_power = 0;
        let mut seen_validators = Vec::new();

        for commit_sig in &certificate.commit_signatures {
            let validator_address = &commit_sig.address;

            // 1. DUPLICATE CHECK
            if seen_validators.contains(&validator_address) {
                return Err(CertificateError::DuplicateVote(validator_address.clone()));
            }

            // 2. STATE POLLUTION: Added before verification!
            seen_validators.push(validator_address);

            let validator = validator_set.get_by_address(validator_address)?;

            // 3. ERROR SWALLOWING: Invalid signatures are ignored,
            // but `seen_validators` is permanently polluted!
            if let Ok(voting_power) = self
                .verify_commit_signature(ctx, certificate, commit_sig, validator)
                .await
            {
                signed_voting_power += voting_power;
            }
        }
        // ... (Check if signed_voting_power >= 2/3)
    }
```

### Exploit Sequence
1. The network legitimately reaches consensus on Block N. A `CommitCertificate` is generated containing valid signatures from Validators A, B, C, and D.
2. Attacker Malice creates a fake `CommitSignature` for Validator D. The signature is mathematically invalid.
3. Malice injects this fake signature at the *front* of the `commit_signatures` array.
4. Honest Node receives the certificate.
5. Loop iteration 1: Fake signature for D is processed. `seen_validators.push(D)` occurs. `verify_commit_signature` fails (invalid crypto). Error is swallowed. `signed_voting_power` is unaffected.
6. Loop iterations 2-4: Valid signatures for A, B, C are processed. `seen_validators.push(A/B/C)`.
7. Loop iteration 5: The *Real*, mathematically valid signature for Validator D is processed.
8. The guard `if seen_validators.contains(D)` evaluates to `true`.
9. The function immediately returns `Err(DuplicateVote)`. The perfectly valid certificate is rejected.

## Proof of Concept
A failing unit test `test_poc_new17_bft_proof_poisoning_duplicate_vote` was successfully added to `crates/types/tests/unit/certificates/commit.rs`. It programmatically constructs a valid 4-validator certificate, prepends a fake signature for Validator 0, and asserts that the verification incorrectly throws a `DuplicateVote` error instead of validating the remaining valid quorum.

## Recommended Mitigation
Do not mutate the `seen_validators` state array until *after* the signature has been cryptographically verified. If a signature is invalid, it should either be ignored (without polluting the state) or preferably, it should abort the entire certificate verification immediately to enforce strict proof hygiene.

```rust
// Proposed Fix
for commit_sig in &certificate.commit_signatures {
    let validator_address = &commit_sig.address;

    let validator = validator_set.get_by_address(validator_address)?;

    // VERIFY FIRST
    if let Ok(voting_power) = self
        .verify_commit_signature(ctx, certificate, commit_sig, validator)
        .await
    {
        // MUTATE STATE SECOND
        if seen_validators.contains(&validator_address) {
            return Err(CertificateError::DuplicateVote(validator_address.clone()));
        }
        seen_validators.push(validator_address);
        signed_voting_power += voting_power;
    } else {
        // Optional: return Err(InvalidSignature) to enforce strict hygiene
    }
}
```

## Impact
- **Total Loss of Liveness (DoS)**: Attackers can permanently halt the chain by repeatedly poisoning certificates during P2P gossip or when proposing.
- **BFT Safety Guarantee Collapse**: The network's foundational logic for determining what is 'valid' can be inverted by inserting garbage bytes.