// secret value masking

/// mask a secret value for display
/// shows first 2 and last 2 chars: "sk****rd"
/// for short secrets (< 6 chars): replaces all with "x"
pub fn mask_secret(secret: &[u8]) -> String {
    let s = String::from_utf8_lossy(secret);
    if s.len() < 6 {
        "x".repeat(s.len())
    } else {
        let chars: Vec<char> = s.chars().collect();
        let first: String = chars[..2].iter().collect();
        let last: String = chars[chars.len() - 2..].iter().collect();
        let middle = "*".repeat(chars.len() - 4);
        format!("{first}{middle}{last}")
    }
}
