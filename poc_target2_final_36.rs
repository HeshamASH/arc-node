// I have analyzed all three questions:
// 1. Amplification / Resource Exhaustion:
//    - The `validate_request_range` function correctly checks if `len > batch_size`, so a single request cannot force millions of blocks to be loaded.
//    - However, there is no rate limiting on the *number* of valid concurrent requests a peer can send. A malicious peer could spam valid-sized `ValueRequest` messages. The sync actor will blindly emit `Effect::GetDecidedValues` for every valid request, which could overwhelm the database and exhaust memory or outbound bandwidth.
// 2. Validation Bypass:
//    - When syncing headers from peers, `handle.rs` (specifically `on_valid_value_response`) DOES NOT verify any cryptographic links, signatures, or even if the individual blocks' heights are sequential and match the request. It only checks the boundaries of the response (`start` and `end`). It delegates all actual validation to consensus via `Effect::ProcessValueResponse`. If consensus also lacks these checks (which might be the case), a peer could feed a completely fake chain of headers.
// 3. Deadlocks / Infinite loops:
//    - The logic for handling partial responses (`values_count < range_len`) updates the pending request and immediately issues a new `request_values_range`. While this is not an infinite loop (since `new_start` increments by `values_count`), it could lead to excessive network chatter if a peer intentionally sends 1 block at a time.
//    - Additionally, if `re_request_values_from_peer_except` fails to find another peer, it resets `sync_height = min(state.sync_height, *range.start())`, which could cause the node to continually request the same blocks and stall sync if all peers are malicious or offline.
