// I should formulate this into a vulnerability report.
// Is there anything else?
// Let's re-read `clamp_request_range`:
// ```rust
//    let start = *range.start();
//    let end = min(*range.end(), tip_height);
//    start..=end
// ```
// And `validate_request_range` checks `if range.start() > &tip_height { return false; }`
// So `start <= tip_height` is guaranteed.
// And `start <= end` is guaranteed.
// So `clamp_request_range` will never panic.
