//! Bech32m encoding (BIP-350 checksum) for ZCrypt addresses and bearer coins.
//!
//! The canonical `bech32` crate enforces BIP-173's ≤1023-character limit, which a
//! ~1249-byte ZCrypt address (post-quantum ML-KEM key + spend key) exceeds. We use
//! the *same* charset and *same* bech32m checksum polynomial, only lifting the
//! length restriction. The 6-character checksum still catches typos; its formal
//! "detects ≤4 errors" guarantee holds up to 1023 chars, so beyond that treat it
//! as strong-but-not-guaranteed error detection (random corruption is still caught
//! with probability ≈ 1 − 2⁻³⁰). `tests::matches_reference_crate` cross-checks our
//! output byte-for-byte against the audited `bech32` crate on inputs it accepts.

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
const BECH32M_CONST: u32 = 0x2bc8_30a3;

fn polymod(values: &[u8]) -> u32 {
    let mut chk: u32 = 1;
    for &v in values {
        let top = (chk >> 25) as u8;
        chk = ((chk & 0x01ff_ffff) << 5) ^ (v as u32);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut v: Vec<u8> = hrp.bytes().map(|c| c >> 5).collect();
    v.push(0);
    v.extend(hrp.bytes().map(|c| c & 31));
    v
}

fn create_checksum(hrp: &str, data5: &[u8]) -> [u8; 6] {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data5);
    values.extend_from_slice(&[0u8; 6]);
    let pm = polymod(&values) ^ BECH32M_CONST;
    core::array::from_fn(|i| ((pm >> (5 * (5 - i))) & 31) as u8)
}

fn verify_checksum(hrp: &str, data5_with_chk: &[u8]) -> bool {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data5_with_chk);
    polymod(&values) == BECH32M_CONST
}

/// Regroup a byte stream between bit widths (8↔5). `pad` appends the final partial
/// group when encoding; on decode it must be zero-padding only.
fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let maxv = (1u32 << to) - 1;
    let mut out = Vec::new();
    for &value in data {
        if (value as u32) >> from != 0 {
            return None;
        }
        acc = (acc << from) | value as u32;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & maxv) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & maxv) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & maxv) != 0 {
        return None;
    }
    Some(out)
}

/// Encode `data` as `<hrp>1<data><checksum>` using the bech32m checksum.
pub fn encode(hrp: &str, data: &[u8]) -> String {
    let data5 = convert_bits(data, 8, 5, true).expect("8->5 with padding never fails");
    let chk = create_checksum(hrp, &data5);
    let mut s = String::with_capacity(hrp.len() + 1 + data5.len() + 6);
    s.push_str(hrp);
    s.push('1');
    for &d in data5.iter().chain(chk.iter()) {
        s.push(CHARSET[d as usize] as char);
    }
    s
}

/// Decode a bech32m string, verifying the checksum. Returns `(hrp, data)`.
pub fn decode(s: &str) -> Option<(String, Vec<u8>)> {
    let s = s.trim();
    // Reject mixed case (bech32 requires uniform case); normalize to lower.
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        return None;
    }
    let lower = s.to_ascii_lowercase();
    let pos = lower.rfind('1')?;
    if pos < 1 || pos + 7 > lower.len() {
        return None; // need non-empty hrp + ≥6 checksum chars
    }
    let hrp = &lower[..pos];
    let mut data5 = Vec::with_capacity(lower.len() - pos - 1);
    for c in lower[pos + 1..].bytes() {
        let idx = CHARSET.iter().position(|&x| x == c)?;
        data5.push(idx as u8);
    }
    if !verify_checksum(hrp, &data5) {
        return None;
    }
    let payload = &data5[..data5.len() - 6];
    let data = convert_bits(payload, 5, 8, false)?;
    Some((hrp.to_string(), data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_various_lengths() {
        for len in [0usize, 1, 32, 56, 100, 625, 1249, 2000] {
            let data: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
            let s = encode("zc", &data);
            assert!(s.starts_with("zc1"));
            let (hrp, back) = decode(&s).expect("decode");
            assert_eq!(hrp, "zc");
            assert_eq!(back, data, "roundtrip len {len}");
        }
    }

    #[test]
    fn checksum_catches_single_typo() {
        let data: Vec<u8> = (0..80).map(|i| i as u8).collect();
        let s = encode("zc", &data);
        let mut chars: Vec<char> = s.chars().collect();
        let mid = chars.len() / 2;
        chars[mid] = if chars[mid] == 'q' { 'p' } else { 'q' };
        let bad: String = chars.into_iter().collect();
        assert!(decode(&bad).is_none());
    }

    #[test]
    fn matches_reference_crate() {
        // On inputs the audited `bech32` crate accepts (≤1023 chars), our output
        // must be byte-identical — proving we implement standard bech32m.
        use bech32::{Bech32m, Hrp};
        for len in [1usize, 20, 56, 100, 300] {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let ours = encode("zcb", &data);
            let theirs = bech32::encode::<Bech32m>(Hrp::parse("zcb").unwrap(), &data).unwrap();
            assert_eq!(ours, theirs, "mismatch at len {len}");
        }
    }
}
