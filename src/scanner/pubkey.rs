// public key detection (false positive avoidance)
// PEM/PGP public key blocks and OpenSSH public keys are NOT secrets.
// base64 content inside these blocks often triggers token rules (e.g. "EAA" -> facebook-access-token).

/// stateful tracker for multi-line PEM/PGP public key blocks.
/// feed each line sequentially; returns true while inside a public key block.
pub struct PubKeyBlockTracker {
    in_block: bool,
}

impl Default for PubKeyBlockTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl PubKeyBlockTracker {
    pub fn new() -> Self {
        Self { in_block: false }
    }

    /// feed a line and update state. returns true if line is inside a public key block
    /// (including the BEGIN/END markers themselves).
    pub fn feed_line(&mut self, line: &[u8]) -> bool {
        let trimmed = trim_bytes(line);

        if self.in_block {
            // check for end marker
            if is_pem_public_key_footer(trimmed) || is_pgp_public_key_footer(trimmed) {
                self.in_block = false;
                return true; // the END line itself is still public key material
            }
            return true;
        }

        // check for begin marker
        if is_pem_public_key_header(trimmed) || is_pgp_public_key_header(trimmed) {
            self.in_block = true;
            return true;
        }

        false
    }
}

/// check if a line is a PEM public key header.
/// matches: BEGIN PUBLIC KEY, BEGIN RSA PUBLIC KEY, BEGIN SSH2 PUBLIC KEY,
/// BEGIN EC PUBLIC KEY, and similar patterns.
/// does NOT match private key headers.
pub fn is_pem_public_key_header(line: &[u8]) -> bool {
    let trimmed = trim_bytes(line);
    // must start with -----BEGIN
    if !starts_with_ci(trimmed, b"-----BEGIN ") {
        return false;
    }
    // must NOT contain PRIVATE (case-insensitive)
    if contains_ci(trimmed, b"PRIVATE") {
        return false;
    }
    // must contain PUBLIC KEY
    if !contains_ci(trimmed, b"PUBLIC KEY") {
        return false;
    }
    // must end with dashes (at least 4)
    trimmed.len() >= 4 && trimmed[trimmed.len() - 4..].iter().all(|&b| b == b'-')
}

/// check if a line is a PEM public key footer
pub fn is_pem_public_key_footer(line: &[u8]) -> bool {
    let trimmed = trim_bytes(line);
    if !starts_with_ci(trimmed, b"-----END ") {
        return false;
    }
    if contains_ci(trimmed, b"PRIVATE") {
        return false;
    }
    if !contains_ci(trimmed, b"PUBLIC KEY") {
        return false;
    }
    trimmed.len() >= 4 && trimmed[trimmed.len() - 4..].iter().all(|&b| b == b'-')
}

/// check if a line is a PGP public key block header
pub fn is_pgp_public_key_header(line: &[u8]) -> bool {
    let trimmed = trim_bytes(line);
    starts_with_ci(trimmed, b"-----BEGIN PGP PUBLIC KEY BLOCK-----")
}

/// check if a line is a PGP public key block footer
pub fn is_pgp_public_key_footer(line: &[u8]) -> bool {
    let trimmed = trim_bytes(line);
    starts_with_ci(trimmed, b"-----END PGP PUBLIC KEY BLOCK-----")
}

/// openssh public key prefixes
const OPENSSH_PREFIXES: &[&[u8]] = &[
    b"ssh-rsa ",
    b"ssh-ed25519 ",
    b"ssh-dss ",
    b"ecdsa-sha2-nistp256 ",
    b"ecdsa-sha2-nistp384 ",
    b"ecdsa-sha2-nistp521 ",
    b"sk-ssh-ed25519@openssh.com ",
    b"sk-ecdsa-sha2-nistp256@openssh.com ",
];

/// check if a line is an OpenSSH public key (single-line format).
/// format: <algorithm> <base64-data> [comment]
/// base64 data for SSH keys always starts with AAAA (RFC 4253).
pub fn is_openssh_public_key(line: &[u8]) -> bool {
    let trimmed = trim_bytes(line);
    for prefix in OPENSSH_PREFIXES {
        if trimmed.len() > prefix.len() && trimmed.starts_with(prefix) {
            let rest = &trimmed[prefix.len()..];
            // base64 data should start with AAAA
            if rest.starts_with(b"AAAA") {
                return true;
            }
        }
    }
    false
}

/// case-insensitive starts_with for byte slices
fn starts_with_ci(haystack: &[u8], needle: &[u8]) -> bool {
    if haystack.len() < needle.len() {
        return false;
    }
    haystack[..needle.len()].eq_ignore_ascii_case(needle)
}

/// case-insensitive contains for byte slices
fn contains_ci(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

/// trim leading/trailing ascii whitespace from a byte slice
fn trim_bytes(data: &[u8]) -> &[u8] {
    let start = data
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(data.len());
    let end = data
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(start, |p| p + 1);
    &data[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- PEM public key header detection --

    #[test]
    fn pem_public_key_pkcs8() {
        assert!(is_pem_public_key_header(b"-----BEGIN PUBLIC KEY-----"));
    }

    #[test]
    fn pem_public_key_rsa() {
        assert!(is_pem_public_key_header(b"-----BEGIN RSA PUBLIC KEY-----"));
    }

    #[test]
    fn pem_public_key_ssh2() {
        assert!(is_pem_public_key_header(b"-----BEGIN SSH2 PUBLIC KEY----"));
    }

    #[test]
    fn pem_public_key_ec() {
        assert!(is_pem_public_key_header(b"-----BEGIN EC PUBLIC KEY-----"));
    }

    #[test]
    fn pem_private_key_not_matched() {
        assert!(!is_pem_public_key_header(
            b"-----BEGIN RSA PRIVATE KEY-----"
        ));
        assert!(!is_pem_public_key_header(b"-----BEGIN PRIVATE KEY-----"));
        assert!(!is_pem_public_key_header(b"-----BEGIN EC PRIVATE KEY-----"));
    }

    #[test]
    fn pem_public_key_footer() {
        assert!(is_pem_public_key_footer(b"-----END PUBLIC KEY-----"));
        assert!(is_pem_public_key_footer(b"-----END RSA PUBLIC KEY-----"));
    }

    #[test]
    fn pem_private_key_footer_not_matched() {
        assert!(!is_pem_public_key_footer(b"-----END RSA PRIVATE KEY-----"));
    }

    // -- PGP public key block detection --

    #[test]
    fn pgp_public_key_header() {
        assert!(is_pgp_public_key_header(
            b"-----BEGIN PGP PUBLIC KEY BLOCK-----"
        ));
    }

    #[test]
    fn pgp_public_key_footer() {
        assert!(is_pgp_public_key_footer(
            b"-----END PGP PUBLIC KEY BLOCK-----"
        ));
    }

    #[test]
    fn pgp_private_key_not_matched() {
        assert!(!is_pgp_public_key_header(
            b"-----BEGIN PGP PRIVATE KEY BLOCK-----"
        ));
    }

    // -- OpenSSH public key detection --

    #[test]
    fn openssh_rsa() {
        assert!(is_openssh_public_key(
            b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC3F user@host"
        ));
    }

    #[test]
    fn openssh_ed25519() {
        assert!(is_openssh_public_key(
            b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbcdef user@host"
        ));
    }

    #[test]
    fn openssh_ecdsa() {
        assert!(is_openssh_public_key(
            b"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAy user@host"
        ));
    }

    #[test]
    fn openssh_sk_ed25519() {
        assert!(is_openssh_public_key(
            b"sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5 user@host"
        ));
    }

    #[test]
    fn openssh_without_aaaa_not_matched() {
        // base64 must start with AAAA for valid SSH keys
        assert!(!is_openssh_public_key(b"ssh-rsa BBBBB3NzaC1yc2 user@host"));
    }

    #[test]
    fn not_openssh_random_line() {
        assert!(!is_openssh_public_key(
            b"some random line with ssh-rsa in it"
        ));
    }

    // -- PubKeyBlockTracker --

    #[test]
    fn tracker_pem_public_key_block() {
        let mut tracker = PubKeyBlockTracker::new();
        assert!(!tracker.feed_line(b"some preamble"));
        assert!(tracker.feed_line(b"-----BEGIN PUBLIC KEY-----"));
        assert!(tracker.feed_line(b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"));
        assert!(tracker.feed_line(b"EAAm/3TyBqMZ0qs3O5EAA")); // contains EAA
        assert!(tracker.feed_line(b"-----END PUBLIC KEY-----"));
        assert!(!tracker.feed_line(b"after block"));
    }

    #[test]
    fn tracker_pgp_public_key_block() {
        let mut tracker = PubKeyBlockTracker::new();
        assert!(tracker.feed_line(b"-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assert!(tracker.feed_line(b"mQENBGXYz8kBCAC7"));
        assert!(tracker.feed_line(b"-----END PGP PUBLIC KEY BLOCK-----"));
        assert!(!tracker.feed_line(b"after"));
    }

    #[test]
    fn tracker_private_key_not_tracked() {
        let mut tracker = PubKeyBlockTracker::new();
        assert!(!tracker.feed_line(b"-----BEGIN RSA PRIVATE KEY-----"));
        assert!(!tracker.feed_line(b"MIIEpAIBAAKCAQEA..."));
        assert!(!tracker.feed_line(b"-----END RSA PRIVATE KEY-----"));
    }

    // -- helper tests --

    #[test]
    fn trim_bytes_basic() {
        assert_eq!(trim_bytes(b"  hello  "), b"hello");
        assert_eq!(trim_bytes(b"\t\n test \r\n"), b"test");
        assert_eq!(trim_bytes(b"no trim"), b"no trim");
        assert_eq!(trim_bytes(b""), b"");
    }

    #[test]
    fn starts_with_ci_basic() {
        assert!(starts_with_ci(
            b"-----BEGIN PUBLIC KEY-----",
            b"-----BEGIN "
        ));
        assert!(starts_with_ci(
            b"-----begin public key-----",
            b"-----BEGIN "
        ));
        assert!(!starts_with_ci(b"short", b"longer than haystack"));
    }

    #[test]
    fn contains_ci_basic() {
        assert!(contains_ci(
            b"-----BEGIN RSA PUBLIC KEY-----",
            b"PUBLIC KEY"
        ));
        assert!(contains_ci(
            b"-----begin rsa public key-----",
            b"PUBLIC KEY"
        ));
        assert!(!contains_ci(b"no match here", b"PUBLIC KEY"));
    }
}
