pub fn printHexString(input: &[u8]) -> String {
    return input.iter().map(|byte| format!("{:02X}", byte)).collect();
}
