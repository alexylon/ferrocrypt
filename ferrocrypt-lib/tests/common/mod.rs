//! Test support helpers for `integration_tests.rs`.
//!
//! Pre-restructure the library exposed `symmetric_auto` / `hybrid_auto`
//! convenience wrappers that detected direction from magic bytes. The
//! post-refactor public API split that into [`Encryptor`] / [`Decryptor`];
//! these file-private helpers preserve the old call shape so the existing
//! integration test call sites don't need to churn while still exercising
//! the new public surface end-to-end.
//!
//! Each integration-test binary compiles this module separately; when a
//! binary only imports a subset of the helpers the rest would trip
//! `dead_code`, so the module-level allow keeps that quiet without
//! weakening the lint for the binaries themselves.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use ferrocrypt::secrecy::SecretString;
use ferrocrypt::{
    CryptoError, Decryptor, Encryptor, KdfLimit, KeyGenOutcome, PrivateKey, ProgressEvent,
    PublicKey, detect_encryption_mode, generate_key_pair as lib_generate_key_pair,
};

pub fn symmetric_auto(
    input: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    passphrase: &SecretString,
    save_as: Option<&Path>,
    kdf_limit: Option<&KdfLimit>,
    on_event: impl Fn(&ProgressEvent),
) -> Result<PathBuf, CryptoError> {
    let input = input.as_ref();
    let output_dir = output_dir.as_ref();
    if !input.exists() {
        return Err(CryptoError::InputPath);
    }
    if detect_encryption_mode(input)?.is_some() {
        match Decryptor::open(input)? {
            Decryptor::Passphrase(mut d) => {
                if let Some(limit) = kdf_limit {
                    d = d.kdf_limit(*limit);
                }
                d.decrypt(passphrase.clone(), output_dir, on_event)
                    .map(|o| o.output_path)
            }
            Decryptor::Recipient(_) => Err(CryptoError::NoSupportedRecipient),
            _ => Err(CryptoError::NoSupportedRecipient),
        }
    } else {
        let mut encryptor = Encryptor::with_passphrase(passphrase.clone());
        if let Some(s) = save_as {
            encryptor = encryptor.save_as(s);
        }
        encryptor
            .write(input, output_dir, on_event)
            .map(|o| o.output_path)
    }
}

pub fn hybrid_auto(
    input: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    key_file: impl AsRef<Path>,
    passphrase: &SecretString,
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
    if detect_encryption_mode(input)?.is_some() {
        match Decryptor::open(input)? {
            Decryptor::Recipient(mut d) => {
                if let Some(limit) = kdf_limit {
                    d = d.kdf_limit(*limit);
                }
                d.decrypt(
                    PrivateKey::from_key_file(key_file),
                    passphrase.clone(),
                    output_dir,
                    on_event,
                )
                .map(|o| o.output_path)
            }
            Decryptor::Passphrase(_) => Err(CryptoError::NoSupportedRecipient),
            _ => Err(CryptoError::NoSupportedRecipient),
        }
    } else {
        let mut encryptor = Encryptor::with_recipient(PublicKey::from_key_file(key_file));
        if let Some(s) = save_as {
            encryptor = encryptor.save_as(s);
        }
        encryptor
            .write(input, output_dir, on_event)
            .map(|o| o.output_path)
    }
}

pub fn generate_key_pair(
    passphrase: &SecretString,
    output_dir: impl AsRef<Path>,
    on_event: impl Fn(&ProgressEvent),
) -> Result<KeyGenOutcome, CryptoError> {
    lib_generate_key_pair(output_dir, passphrase.clone(), on_event)
}
