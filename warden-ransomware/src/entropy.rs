/// Shannon entropy of a byte slice, in bits per byte (0.0 .. 8.0).
///
/// Encrypted or compressed data looks close to uniformly random, so it sits
/// near 7.9-8.0. Plain text sits around 3.5-5.5, most structured binary
/// formats (office docs, images, video) somewhere in between depending on
/// their own internal compression.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeros_have_zero_entropy() {
        let data = vec![0u8; 4096];
        assert_eq!(shannon_entropy(&data), 0.0);
    }

    #[test]
    fn uniform_random_bytes_are_near_max_entropy() {
        let mut state: u64 = 0x243F6A8885A308D3;
        let mut data = vec![0u8; 65536];
        for b in data.iter_mut() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *b = (state & 0xFF) as u8;
        }
        let e = shannon_entropy(&data);
        assert!(e > 7.9, "expected near-max entropy, got {e}");
    }

    #[test]
    fn ascii_text_has_moderate_entropy() {
        let data = "the quick brown fox jumps over the lazy dog ".repeat(200);
        let e = shannon_entropy(data.as_bytes());
        assert!(e > 3.0 && e < 4.5, "expected moderate entropy, got {e}");
    }
}
