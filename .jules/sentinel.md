## 2025-05-18 - [Investigation] Precompile Subcall Architecture

**Vulnerability:** Subcall precompiles lack a transactional wrapper checkpoint for atomic commits/reverts, allowing internal child successes to persist even if the parent completion phase (`complete_subcall`) subsequently throws an `Err` or `success: false`.
**Learning:** `CallFrom` and other subcalls in `subcall.rs` are explicitly documented to not utilize a secondary checkpoint. In the Arc architecture, if an internal child EVM frame successfully completes and resolves its own checkpoint, its state changes (e.g., to native coin balances) are irrevocably merged into the global journal. A subsequent failure in the parent precompile's output processing layer does *not* roll back those child mutations, resulting in severe transactional atomicity breaks and state desynchronization.
**Prevention:** Future subcall integration architectures must forcefully wrap the entire two-phase `init_subcall` -> `child_frame` -> `complete_subcall` execution loop inside a dedicated EVM journal checkpoint, explicitly calling `checkpoint_revert` if `complete_subcall` fails.

## 2025-05-18 - [Investigation] PQ Precompile Gas Pricing

**Vulnerability:** None (Gas Overpricing Confirmed).
**Learning:** Evaluated the PQ `slh-dsa` precompile against a gas-underpricing DoS. While the `args.msg` size is unbounded, the linear `GAS_PER_MSG_WORD` multiplier scales aggressively. A 100KB payload consumed ~4.4M gas while taking only 1.6ms CPU time. The precompile safely overcharges relative to actual cryptographic overhead.
**Prevention:** Always benchmark CPU time against unbounded payload gas costs to ensure the ratio remains >10x worse than `KECCAK256`.
