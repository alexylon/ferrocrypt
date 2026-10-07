//! Checks that `Passphrase` implements neither `Clone` nor `Display`, and
//! `PrivateKey` does not implement `Clone`.
//!
//! Ordinary type checking does not reject these accidental trait additions,
//! and `cargo semver-checks` checks `Copy` additions (`copy_impl_added`), not
//! these `Clone` or `Display` additions. These assertions therefore enforce
//! the documented absences. The `Copy` positions need no equivalent test
//! because that lint covers them. `public_auto_traits.rs` checks the traits
//! exported types must retain.
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
