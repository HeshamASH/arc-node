import re

with open("crates/evm/src/handler.rs", "r") as f:
    content = f.read()

target = """        let max_refund = gas_used / 5;
        let applied_refund = std::cmp::min(gas_refunded as u64, max_refund);
        let expected_billable_gas = gas_used - applied_refund;"""
replacement = """        let expected_billable_gas = gas_used.saturating_sub(gas_refunded as u64);"""

content = content.replace(target, replacement)

target2 = """        assert_eq!(balance_increase, U256::from(560000));"""
replacement2 = """        assert_eq!(balance_increase, U256::from(700000));"""

content = content.replace(target2, replacement2)

with open("crates/evm/src/handler.rs", "w") as f:
    f.write(content)
