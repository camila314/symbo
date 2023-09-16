// Convert hex string to u64
pub fn hex_to_u64(hex: &str) -> Option<u64> {
	u64::from_str_radix(hex.strip_prefix("0x").unwrap_or("j"), 16).ok()
}

