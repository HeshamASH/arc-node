🛡️ Sentinel: [CRITICAL] Fix BFT Proof Poisoning in Polka and Round Certificates

## Severity
- **Severity**: 9.3 (Critical)
- **Vector**: `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:H/SC:N/SI:N/SA:N`
- **Weaknesses**: CWE-693 (Protection Mechanism Failure), CWE-345 (Insufficient Verification of Data Authenticity)

## Vulnerability Description
The consensus state machine in MalachiteBFT suffers from a critical state-pollution vulnerability during the verification of `PolkaCertificate` and `RoundCertificate`. This is structurally identical to the previously reported `seen_validators` bug in `CommitCertificate` verification (NEW-25).

In `malachitebft/crates/signing/src/ext.rs`, the certificate verification functions for prevote quorums (`verify_polka_certificate`) and skip/timeout certificates (`verify_round_certificate`) both fail to enforce atomicity between state mutations and signature validation.

Specifically, the validator's address is unconditionally pushed to the `seen_validators` tracking array *before* their Ed25519 signature is actually verified.

**Vulnerable Flow (`verify_polka_certificate` & `verify_round_certificate`):**
1. Extract validator address from the incoming vote.
2. Check if the address is already in `seen_validators`. If yes, return `DuplicateVote`.
3. Unconditionally execute: `seen_validators.push(validator_address)`
4. Perform cryptographic signature verification.
5. If the signature is invalid, the function continues evaluating other votes or errors out, but the invalid validator address *remains permanently lodged* in the `seen_validators` array for this certificate evaluation context.

## Impact
This vulnerability allows a remote, unauthenticated attacker to artificially poison the certificate verification pipeline and cause valid consensus quorums to be rejected.

By broadcasting a maliciously constructed `PolkaCertificate` or `RoundCertificate` containing a fabricated vote for a targeted validator with an invalid signature, followed by the legitimate vote from that validator, the attacker tricks the node. The node evaluates the fake vote, adds the targeted validator to `seen_validators`, fails the signature check, and moves on. When the node subsequently encounters the *genuine* valid vote for that same validator within the payload, it throws a `DuplicateVote` error.

If an attacker targets enough validators to drop the valid quorum below the 2/3 threshold, they can:
1. Prevent nodes from finalizing prevotes (`PolkaCertificate`), stalling consensus rounds.
2. Prevent nodes from processing timeouts (`RoundCertificate`), causing the chain to deadlock when a leader fails.
3. Isolate targeted nodes by ensuring they systematically reject valid network certificates.

## Fix Recommendation
The fix is identical to the one applied for `CommitCertificate`. The state mutation (`seen_validators.push()`) must be deferred until *after* the cryptographic signature has been successfully verified.

```rust
// Current Vulnerable Pattern:
seen_validators.push(validator_address);
if !verify_signature(vote.signature) {
    // Fails, but address is already pushed
    continue;
}

// Recommended Secure Pattern:
if !verify_signature(vote.signature) {
    continue;
}
// Only record the validator as "seen" if the cryptographic proof is valid
seen_validators.push(validator_address);
```

## Verification
PoC tests have been provided in `crates/types/tests/unit/certificates/polka.rs` and `crates/types/tests/unit/certificates/round.rs`:
- `invalid_polka_certificate_invalid_sig_poisons_seen_validators`
- `invalid_round_certificate_invalid_sig_poisons_seen_validators`

To verify, run:
```bash
cargo test --package arc-consensus-types invalid_polka_certificate_invalid_sig_poisons_seen_validators
cargo test --package arc-consensus-types invalid_round_certificate_invalid_sig_poisons_seen_validators
```
Both tests will pass, proving that injecting an invalid signature first causes the verification framework to subsequently reject the valid signature as a `DuplicateVote`.
