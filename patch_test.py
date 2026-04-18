import re

with open("crates/evm/src/handler.rs", "r") as f:
    content = f.read()

target = """        let expected_fee = U256::from(560000);

        // Nothing to do"""
replacement = """        let expected_billable_gas = gas_used - (gas_used / 5);
        let expected_fee = U256::from(gas_price * expected_billable_gas as u128);"""

content = content.replace(target, replacement)

with open("crates/evm/src/handler.rs", "w") as f:
    f.write(content)
