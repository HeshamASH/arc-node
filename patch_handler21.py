import re

with open("crates/evm/src/handler.rs", "r") as f:
    content = f.read()

target = """        let expected_billable_gas = gas_used - (gas_used / 5);"""
replacement = """        let max_refund = gas_used / 5;
        let applied_refund = std::cmp::min(gas_refunded as u64, max_refund);
        let expected_billable_gas = gas_used - applied_refund;"""

content = content.replace(target, replacement)

with open("crates/evm/src/handler.rs", "w") as f:
    f.write(content)
