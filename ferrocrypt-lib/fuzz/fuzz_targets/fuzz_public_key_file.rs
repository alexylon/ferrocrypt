#![no_main]

//! Fuzzes the `public.key` content grammar over arbitrary bytes
//! (`FORMAT.md` §7).
//!
//! This target covers the file-level checks around the recipient-string
//! decoder: key-kind routing, UTF-8, the optional trailing `LF`, other
//! ASCII whitespace, and the X25519 type and length. The bounded
//! filesystem read remains with the on-disk reader and is outside this
//! content-parser target.
//!
//! Accepted content, after removing the permitted trailing `LF`, must
//! parse through the public recipient-string API and re-encode
//! byte-for-byte. This pins the canonical form across both input
//! surfaces.

use ferrocrypt::PublicKey;
use ferrocrypt::fuzz_exports::parse_public_key_file_bytes;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if parse_public_key_file_bytes(data).is_err() {
        return;
    }
    let contents = std::str::from_utf8(data).expect("accepted content is valid UTF-8");
    let recipient = contents.strip_suffix('\n').unwrap_or(contents);
    let key = PublicKey::from_recipient_string(recipient)
        .expect("accepted content must parse as a recipient string");
    assert_eq!(
        key.to_recipient_string()
            .expect("re-encoding an accepted key must succeed"),
        recipient,
        "accepted content must be the canonical recipient string",
    );
});
