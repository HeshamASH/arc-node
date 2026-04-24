// I have completed my audit.
// Amplification / Resource Exhaustion: No. Checked by `validate_request_range` via batch limits.
// Validation Bypass: `on_valid_value_response` checks absolutely no cryptographic links or internal height consistency; it relies on `ProcessValueResponse` passing the blocks to consensus.
// Wait, is there a deadlock/infinite loop?
// Let's re-read `on_status`:
// ```rust
//    if peer_height >= state.sync_height {
//        request_values(co, state, metrics).await?;
//    }
// ```
// It calls `request_values`, which calls `find_next_uncovered_range_from`.
// If `peer_height` is extremely large (e.g. `u64::MAX`), `state.sync_height` can advance to `u64::MAX`.
// Will it create pending requests forever?
// `while state.pending_requests.len() < max_parallel_requests {`
// `find_next_uncovered_range_from` bounds the range.
// `send_request_to_peer` sends the request.
// It loops until `pending_requests.len() == max_parallel_requests`.
// So it creates `max_parallel_requests` requests. No infinite loop.
// So there is NO deadlock and NO infinite loop.

// WAIT! What about the prompt?
// "Can a malicious peer send a malformed SyncRequest that forces the node to load millions of blocks from disk, crashing the database or exhausting outbound bandwidth?"
// I found `if len > batch_size` returns `false`. BUT wait!
