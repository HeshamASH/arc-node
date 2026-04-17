## 2025-04-17 - 🛡️ Sentinel: Arithmetic Panic in Arc Base Fee Processing
**Vulnerability:** A zero-denominator evaluation in `arc_calc_next_block_base_fee` allows a division by zero panic, completely halting all nodes processing the block state.
**Learning:** Rust's integer division truncates. Intermediate division in a denominator block `(gas_target * SCALE / k_rate)` can easily floor to zero when constants or protocol configurations are scaled. This kind of calculation requires rearranging the arithmetic order to preserve precision and prevent division by zero.
**Prevention:** Avoid performing division operations in denominators. Reorder arithmetic so multiplication happens first in a large numerator, followed by a single division with a safely bounded denominator.
