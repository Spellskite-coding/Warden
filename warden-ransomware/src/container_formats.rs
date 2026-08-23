/// Magic-byte prefixes of common legitimate compressed/container formats
/// that a workstation's `Documents` legitimately holds: `.docx`/`.xlsx`/
/// `.pptx`/`.odt`/`.jar` are all ZIP containers, so bulk-editing a folder
/// of office documents (a mail-merge macro, a batch report generator)
/// produces exactly the same near-8.0-bits/byte entropy signature the
/// burst heuristic otherwise treats as ransomware ciphertext - a
/// realistic false positive, not a contrived edge case, since Office's
/// own file formats compress internally.
///
/// Genuine ransomware output has no reason to preserve these headers: it
/// overwrites a file with its own ciphertext blob, not something that
/// still starts with a valid ZIP/PDF/JPEG/etc. signature - so checking
/// for one is a real distinguishing signal, not just security theater.
/// A sample this test still classifies as suspicious (no recognized
/// header) is scored purely on entropy exactly as before; this only ever
/// makes the detector *more* lenient, never less.
const KNOWN_CONTAINER_MAGIC: &[&[u8]] = &[
    b"PK\x03\x04", // ZIP-based: docx/xlsx/pptx/odt/ods/odp/jar/apk/epub
    b"PK\x05\x06", // empty ZIP archive
    b"PK\x07\x08", // spanned ZIP archive
    b"\x1f\x8b",   // gzip
    b"BZh",        // bzip2
    b"\xFD7zXZ\x00", // xz
    b"7z\xBC\xAF\x27\x1C", // 7-zip
    b"Rar!\x1a\x07", // rar
    b"%PDF",       // PDF
    b"\xFF\xD8\xFF", // JPEG
    b"\x89PNG\r\n\x1a\n", // PNG
];

/// Whether `sample` (the file's first chunk, as already read for entropy
/// scoring - see `fanotify_monitor::sample_entropy_via_fd`) starts with a
/// recognized container/compressed format signature. Every signature
/// here is well under the first chunk's size, so sampling less than the
/// full file from offset 0 doesn't affect this check.
pub fn is_known_container_format(sample: &[u8]) -> bool {
    KNOWN_CONTAINER_MAGIC.iter().any(|magic| sample.starts_with(magic))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_zip_based_office_documents() {
        let mut docx = b"PK\x03\x04".to_vec();
        docx.extend_from_slice(&[0u8; 100]);
        assert!(is_known_container_format(&docx));
    }

    #[test]
    fn recognizes_pdf() {
        assert!(is_known_container_format(b"%PDF-1.7\n..."));
    }

    #[test]
    fn does_not_flag_random_ciphertext_as_a_container() {
        let ciphertext = [0xA3u8, 0x7Fu8, 0x01u8, 0x9Cu8, 0x44u8, 0x88u8, 0x12u8, 0xEEu8];
        assert!(!is_known_container_format(&ciphertext));
    }

    #[test]
    fn empty_sample_is_not_a_container() {
        assert!(!is_known_container_format(&[]));
    }
}
