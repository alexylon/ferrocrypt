//! Test support helpers shared between `integration_tests.rs` and
//! `compatibility_tests.rs`.
//!
//! The pre-0.3.0 library exposed `symmetric_auto` / `hybrid_auto`
//! convenience wrappers that detected direction from magic bytes. The
//! post-refactor public API dropped them in favor of explicit config
//! constructors; these file-private helpers preserve the old call shape
//! so the existing integration + compatibility test call sites don't
//! need to churn for the API reshape while still exercising the new
//! public surface end-to-end.
//!
//! Validation order mirrors the library's explicit operation functions
//! (`validate_passphrase` before `validate_input_path` for symmetric;
//! `validate_input_path` only for hybrid). The input-exists pre-check is
//! necessary in the helpers because `detect_encryption_mode` on a
//! nonexistent file surfaces as `Io(NotFound)` instead of `InputPath`.
//!
//! Each integration-test binary compiles this module separately; when a
//! binary only imports a subset of the helpers the rest would trip
//! `dead_code`, so the module-level allow keeps that quiet without
//! weakening the lint for the binaries themselves.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use ferrocrypt::secrecy::{ExposeSecret, SecretString};
use ferrocrypt::{
    CryptoError, HybridDecryptConfig, HybridEncryptConfig, KdfLimit, KeyGenConfig, KeyGenOutcome,
    PrivateKey, ProgressEvent, PublicKey, SymmetricDecryptConfig, SymmetricEncryptConfig,
    detect_encryption_mode, generate_key_pair as lib_generate_key_pair,
    hybrid_decrypt as lib_hybrid_decrypt, hybrid_encrypt as lib_hybrid_encrypt,
    symmetric_decrypt as lib_symmetric_decrypt, symmetric_encrypt as lib_symmetric_encrypt,
};

pub fn symmetric_auto(
    input: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    passphrase: &SecretString,
    save_as: Option<&Path>,
    kdf_limit: Option<&KdfLimit>,
    on_event: impl Fn(&ProgressEvent),
) -> Result<PathBuf, CryptoError> {
    if passphrase.expose_secret().is_empty() {
        return Err(CryptoError::InvalidInput(
            "Passphrase must not be empty".to_string(),
        ));
    }
    let input = input.as_ref();
    let output_dir = output_dir.as_ref();
    if !input.exists() {
        return Err(CryptoError::InputPath);
    }
    if detect_encryption_mode(input)?.is_some() {
        let mut config = SymmetricDecryptConfig::new(input, output_dir, passphrase.clone());
        if let Some(limit) = kdf_limit {
            config = config.kdf_limit(*limit);
        }
        lib_symmetric_decrypt(config, on_event).map(|o| o.output_path)
    } else {
        let mut config = SymmetricEncryptConfig::new(input, output_dir, passphrase.clone());
        if let Some(s) = save_as {
            config = config.save_as(s);
        }
        lib_symmetric_encrypt(config, on_event).map(|o| o.output_path)
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
        let mut config = HybridDecryptConfig::new(
            input,
            output_dir,
            PrivateKey::from_key_file(key_file),
            passphrase.clone(),
        );
        if let Some(limit) = kdf_limit {
            config = config.kdf_limit(*limit);
        }
        lib_hybrid_decrypt(config, on_event).map(|o| o.output_path)
    } else {
        let mut config =
            HybridEncryptConfig::new(input, output_dir, PublicKey::from_key_file(key_file));
        if let Some(s) = save_as {
            config = config.save_as(s);
        }
        lib_hybrid_encrypt(config, on_event).map(|o| o.output_path)
    }
}

pub fn generate_key_pair(
    passphrase: &SecretString,
    output_dir: impl AsRef<Path>,
    on_event: impl Fn(&ProgressEvent),
) -> Result<KeyGenOutcome, CryptoError> {
    lib_generate_key_pair(KeyGenConfig::new(output_dir, passphrase.clone()), on_event)
}
