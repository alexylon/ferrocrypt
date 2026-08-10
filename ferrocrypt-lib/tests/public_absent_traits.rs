//! Compile-time pin: secret-bearing types implement neither `Clone` nor
//! `Display`.
//!
//! `Passphrase` names both absences in its rustdoc as the reason a
//! passphrase cannot leak through formatting and each operation consumes
//! a value built for it; `PrivateKey` states the `Clone` absence because
//! it holds a `Passphrase`. Nothing enforces an absence: the compiler
//! cannot, and `cargo semver-checks` lints only `copy_impl_added`. So a
//! later `#[derive(Clone)]`, or a `Display` impl added for a prompt,
//! would compile, pass the whole suite, and void the guarantee silently.
//! The `Copy` positions recorded in AGENTS.md need no pin here for the
//! opposite reason: that lint already covers them. Mirrors
//! `public_auto_traits.rs`, which pins the traits that must stay.
//!
//! `Probe<T>` answers each question two ways. The inherent method applies
//! only when `T` satisfies the bound; otherwise the blanket trait method
//! answers instead. Inherent methods take precedence, so the result is
//! `true` exactly when the impl exists.

use std::fmt::Display;
use std::marker::PhantomData;

use ferrocrypt::{Passphrase, PrivateKey};

struct Probe<T>(PhantomData<T>);

trait CloneFallback {
    fn implements_clone(&self) -> bool {
        false
    }
}
impl<T> CloneFallback for Probe<T> {}
impl<T: Clone> Probe<T> {
    fn implements_clone(&self) -> bool {
        true
    }
}

trait DisplayFallback {
    fn implements_display(&self) -> bool {
        false
    }
}
impl<T> DisplayFallback for Probe<T> {}
impl<T: Display> Probe<T> {
    fn implements_display(&self) -> bool {
        true
    }
}

#[test]
fn secret_types_implement_neither_clone_nor_display() {
    // Positive controls. Without them a probe that answered `false` for
    // every type would let the assertions below pass while measuring
    // nothing.
    assert!(Probe::<String>(PhantomData).implements_clone());
    assert!(Probe::<String>(PhantomData).implements_display());

    assert!(
        !Probe::<Passphrase>(PhantomData).implements_clone(),
        "Passphrase gained a Clone impl: a credential can now be duplicated \
         into an operation that was not given one"
    );
    assert!(
        !Probe::<Passphrase>(PhantomData).implements_display(),
        "Passphrase gained a Display impl: the text can now reach a log, an \
         error message, or the UI through `{{}}`"
    );
    assert!(
        !Probe::<PrivateKey>(PhantomData).implements_clone(),
        "PrivateKey gained a Clone impl: the passphrase it holds can now be \
         duplicated"
    );
}
