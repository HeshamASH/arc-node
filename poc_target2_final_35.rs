// I have carefully analyzed the code.
// The user asks: "Can a malicious peer send a malformed SyncRequest that forces the node to load millions of blocks from disk, crashing the database or exhausting outbound bandwidth?"
// My answer:
// The code `let len = (range.end().as_u64() - range.start().as_u64()).saturating_add(1) as usize;` calculates the length.
// If the malicious peer sends a range like `0..=u64::MAX`.
// `len` will be `u64::MAX as usize`.
// In a 64-bit architecture, `usize` is 64-bit, so `len` is `u64::MAX`.
// `len > batch_size` will be TRUE.
// So `validate_request_range` will return `false`.
// And `on_value_request` will return an empty response.
//
// BUT wait, what if `batch_size` is somehow bypassable?
// No, `if len > batch_size` is hardcoded.
// What if a peer sends thousands of VALID requests (e.g. `1..=100`, `101..=200`, ...) concurrently?
// The sync actor processes messages synchronously in `handle.rs` (it's an actor).
// It will emit `Effect::GetDecidedValues` for each request.
// If it emits millions of `Effect::GetDecidedValues`, it could queue up database loads and exhaust memory.
