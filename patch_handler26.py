import re

with open("crates/evm/src/handler.rs", "r") as f:
    content = f.read()

target = """        let max_refund = gas_used / 5;
        let applied_refund = std::cmp::min(gas_refunded as u64, max_refund);

        // Let's actually understand why the balance_increase is 560000."""
replacement = """        let max_refund = gas_used / 5;
        let _applied_refund = std::cmp::min(gas_refunded as u64, max_refund);

        // Let's actually understand why the balance_increase is 560000."""

content = content.replace(target, replacement)

with open("crates/evm/src/handler.rs", "w") as f:
    f.write(content)
