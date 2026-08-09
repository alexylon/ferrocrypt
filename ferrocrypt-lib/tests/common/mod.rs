//! Test support helpers for `integration_tests.rs`.
//!
//! `passphrase_auto` and `recipient_auto` wrap the public [`Encryptor`] /
//! [`Decryptor`] API with magic-byte direction detection (via
//! `probe_recipient_mode`: encrypt if the input is plaintext, decrypt if it
//! starts with the FerroCrypt magic) and inject the test-fast Argon2id
//! parameters from `ferrocrypt-test-support` so the test suite doesn't burn
//! seconds per derivation. `generate_key_pair` is the matching keygen wrapper.
//!
//! Each integration-test binary compiles this module separately; when a
//! binary only imports a subset of the helpers the rest would trip
//! `dead_code`, so the module-level allow keeps that quiet without
//! weakening the lint for the binaries themselves.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use ferrocrypt::{
    CryptoError, Decryptor, Encryptor, KdfLimit, KeyGenOutcome, Passphrase, PrivateKey,
    ProgressEvent, PublicKey, probe_recipient_mode,
};
use ferrocrypt_test_support::{fast_keypair_generator, fast_passphrase_encryptor};

pub fn passphrase_auto(
    input: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    passphrase: &str,
    save_as: Option<&Path>,
    kdf_limit: Option<&KdfLimit>,
    on_event: impl Fn(&ProgressEvent),
) -> Result<PathBuf, CryptoError> {
    let input = input.as_ref();
    let output_dir = output_dir.as_ref();
    if !input.exists() {
        return Err(CryptoError::InputPath);
    }
    if probe_recipient_mode(input)?.is_some() {
        match Decryptor::open(input)? {
            Decryptor::Passphrase(mut d) => {
                if let Some(limit) = kdf_limit {
                    d = d.kdf_limit(*limit);
                }
                d.decrypt(Passphrase::new(passphrase), output_dir, on_event)
                    .map(|o| o.output_path)
            }
            Decryptor::PrivateKey(_) => Err(CryptoError::NoSupportedRecipient),
            _ => Err(CryptoError::NoSupportedRecipient),
        }
    } else {
        let mut encryptor = fast_passphrase_encryptor(Passphrase::new(passphrase));
        if let Some(s) = save_as {
            encryptor = encryptor.save_as(s);
        }
        encryptor
            .write(input, output_dir, on_event)
            .map(|o| o.output_path)
    }
}

pub fn recipient_auto(
    input: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    key_file: impl AsRef<Path>,
    passphrase: &str,
    save_as: Option<&Path>,
    kdf_limit: Option<&KdfLimit>,
    on_event: impl Fn(&ProgressEvent),
) -> Result<PathBuf, CryptoError> {
    let input = input.as_ref();
    let output_dir = output_dir.as_ref();
    let key_file = key_file.as_ref();
    if !input.exists() {
        return Err(CryptoError::InputPath);
    }
    if probe_recipient_mode(input)?.is_some() {
        match Decryptor::open(input)? {
            Decryptor::PrivateKey(mut d) => {
                if let Some(limit) = kdf_limit {
                    d = d.kdf_limit(*limit);
                }
                d.decrypt(
                    PrivateKey::from_key_file(key_file),
                    Passphrase::new(passphrase),
                    output_dir,
                    on_event,
                )
                .map(|o| o.output_path)
            }
            Decryptor::Passphrase(_) => Err(CryptoError::NoSupportedRecipient),
            _ => Err(CryptoError::NoSupportedRecipient),
        }
    } else {
        let mut encryptor = Encryptor::with_public_key(PublicKey::from_key_file(key_file));
        if let Some(s) = save_as {
            encryptor = encryptor.save_as(s);
        }
        encryptor
            .write(input, output_dir, on_event)
            .map(|o| o.output_path)
    }
}

pub fn generate_key_pair(
    passphrase: &str,
    output_dir: impl AsRef<Path>,
    on_event: impl Fn(&ProgressEvent),
) -> Result<KeyGenOutcome, CryptoError> {
    fast_keypair_generator(Passphrase::new(passphrase)).write(output_dir, on_event)
}
