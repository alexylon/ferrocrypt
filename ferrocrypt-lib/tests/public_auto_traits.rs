//! Compile-time pin: every exported type stays `Send + Sync`.
//!
//! The compiler grants and withdraws these auto-traits silently from a
//! type's contents, and callers (the desktop app among them) move
//! operations onto worker threads, so thread portability is part of the
//! public contract. Several exported types wrap private enums that are
//! documented to grow — a future variant holding a thread-bound value
//! (for example a hardware-key handle) would strip `Send`/`Sync` from
//! the wrapper without any library test failing. This file is an
//! external-style consumer: if an exported type loses either trait, the
//! test suite stops compiling and the loss becomes a deliberate
//! decision. Thread-bound sources belong behind a separate API type.

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn public_api_is_send_and_sync() {
    assert_send_sync::<ferrocrypt::Encryptor>();
    assert_send_sync::<ferrocrypt::Decryptor>();
    assert_send_sync::<ferrocrypt::PassphraseDecryptor>();
    assert_send_sync::<ferrocrypt::PrivateKeyDecryptor>();
    assert_send_sync::<ferrocrypt::KeyPairGenerator>();
    assert_send_sync::<ferrocrypt::PublicKey>();
    assert_send_sync::<ferrocrypt::PrivateKey>();
    assert_send_sync::<ferrocrypt::CryptoError>();
    assert_send_sync::<ferrocrypt::FormatDefect>();
    assert_send_sync::<ferrocrypt::UnsupportedVersion>();
    assert_send_sync::<ferrocrypt::InvalidKdfParams>();
    assert_send_sync::<ferrocrypt::EncryptOutcome>();
    assert_send_sync::<ferrocrypt::DecryptOutcome>();
    assert_send_sync::<ferrocrypt::KeyGenOutcome>();
    assert_send_sync::<ferrocrypt::ProgressEvent>();
    assert_send_sync::<ferrocrypt::UnauthenticatedRecipientMode>();
    assert_send_sync::<ferrocrypt::AuthenticatedRecipientMode>();
    assert_send_sync::<ferrocrypt::AuthenticatedRecipientModeKind>();
    assert_send_sync::<ferrocrypt::KdfParams>();
    assert_send_sync::<ferrocrypt::KdfLimit>();
    assert_send_sync::<ferrocrypt::ArchiveLimits>();
    assert_send_sync::<ferrocrypt::HeaderReadLimits>();
    assert_send_sync::<ferrocrypt::KeyReadLimits>();
    assert_send_sync::<ferrocrypt::MixingPolicy>();
    assert_send_sync::<ferrocrypt::IncompleteOutputPolicy>();
}
