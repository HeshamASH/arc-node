import re

with open("crates/evm/src/handler.rs", "r") as f:
    content = f.read()

target = """        let expected_fee = U256::from(gas_price * expected_billable_gas as u128);"""
replacement = """        // Nothing here"""

content = content.replace(target, replacement)

with open("crates/evm/src/handler.rs", "w") as f:
    f.write(content)
