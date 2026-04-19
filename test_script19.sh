// The pseudo-inflation leak is real.
// `reward_beneficiary` credits the validator with fees (gas used * effective gas price).
// Where do these fees come from? The sender's balance is deducted by the EVM.
// So the absolute total number of tokens across all balances does NOT change (sender minus fees, validator plus fees).
// Wait, is it pseudo-inflation?
// The prompt said: "Verify if this leak allows the total circulating supply to exceed the NativeCoinAuthority hard-cap. If a validator receives rewards that are 'invisible' to the registry, the governance layer is effectively blind to the actual supply."
// Yes, because Ethereum's EIP-1559 BURNS the base fee.
// So the EVM deducts the base fee from the sender. In Ethereum, that base fee is deleted.
// But in Arc, the base fee is TRANSFERRED to the validator via `journal_mut().balance_incr(beneficiary, total_fee)`.
// This means the base fee is NOT burned.
// However, the `NativeCoinAuthority.totalSupply()` only tracks `mint()` and `burn()` operations!
// Wait! If the base fee is not burned, then the sum of all balances stays exactly equal to the original `totalSupply`.
// BUT, if the user explicitly calls `burn()` to reduce the total supply...
// Actually, if the base fee is NOT burned, then total supply equals sum of balances.
// In standard EVM, base fee IS burned. If Arc were using standard EVM, the base fee would disappear, and the sum of balances would be LESS than `NativeCoinAuthority.totalSupply()`.
// Wait, `NativeCoinAuthority.totalSupply()` isn't updated during regular EVM gas burns either?
// Let's check if the standard `reth` EVM burns the base fee. Yes, `revm` deducts it from the sender and never credits it.
