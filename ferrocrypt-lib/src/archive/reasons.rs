//! Stable reason fragments for the three archive rejection variants:
//! [`crate::CryptoError::MalformedArchive`],
//! [`crate::CryptoError::UnsafeArchivePath`], and
//! [`crate::CryptoError::InvalidArchiveTree`].
//!
//! Every crate-owned archive reason belongs in this registry. The declaration
//! macro validates each fragment against the display policy at compile time,
//! and each group's `ALL` lets the error-message test sweep the complete set.
//! The groups differ only in their validator: a malformed-archive message is
//! wholly library-owned and must fit the status line, while the two
//! path-bearing messages append an entry path and cannot.

use crate::error::{archive_path_reason_is_valid, malformed_archive_reason_is_valid};

macro_rules! reasons {
    ($check:path => $all:ident { $($name:ident = $value:literal;)+ }) => {
        $(
            // The check runs inside the constant's own initializer rather than
            // in a separate anonymous item, because the dead-code pass of the
            // minimum supported Rust version does not count a use there.
            pub(crate) const $name: &str = {
                assert!($check($value));
                $value
            };
        )+

        #[cfg(test)]
        pub(crate) const $all: &[&str] = &[$($name),+];
    };
}

reasons! {
    malformed_archive_reason_is_valid => MALFORMED_ALL {
        ARCHIVE_EXT_PLATFORM_LIMIT = "archive extension exceeds platform limits";
        ARCHIVE_EXT_REGION_TRUNCATED = "archive extension region truncated";
        BAD_MAGIC = "bad magic";
        TOTAL_FILE_BYTES_MISMATCH = "declared total does not match the entry sizes";
        DIRECTORY_SIZE_NONZERO = "directory entry has non-zero size";
        ENTRY_COUNT_PLATFORM_LIMIT = "entry count exceeds platform limits";
        ENTRY_EXT_WIRE_FIELD = "entry extension does not fit its wire field";
        ENTRY_EXT_PLATFORM_LIMIT = "entry extension exceeds platform limits";
        ENTRY_FLAGS_NONZERO = "entry has non-zero reserved flags";
        ENTRY_MODE_UNSUPPORTED = "entry mode contains unsupported bits";
        ENTRY_MODE_WIRE_FIELD = "entry mode does not fit its wire field";
        ENTRY_PATH_WIRE_FIELD = "entry path does not fit its wire field";
        ENTRY_PATH_EMPTY = "entry path is empty";
        ENTRY_PATH_INVALID_UTF8 = "entry path is not valid UTF-8";
        FILE_CONTENT_TRUNCATED = "file content shorter than the declared size";
        FIXED_HEADER_TRUNCATED = "fixed header truncated";
        HEADER_FLAGS_NONZERO = "header has non-zero flags";
        MALFORMED_MANIFEST = "manifest does not match the header";
        MANIFEST_PLATFORM_LIMIT = "manifest length exceeds platform limits";
        ZERO_MANIFEST_LEN = "manifest length is zero";
        MANIFEST_LEN_OVERFLOW = "manifest length overflow";
        MANIFEST_REGION_TRUNCATED = "manifest region truncated";
        NO_ENTRIES = "no entries declared";
        RESERVED_VERSION_ZERO = "reserved version 0x00";
        TOTAL_ENTRY_EXT_BYTES_OVERFLOW = "total entry-extension bytes overflow";
        TOTAL_FILE_BYTES_OVERFLOW = "total file bytes overflow";
        TRAILING_FILE_CONTENT = "trailing data after the file contents";
        UNSUPPORTED_ENTRY_KIND = "unsupported entry kind";
    }
}

// `COMPONENT_TOO_LONG` embeds `path::FCA_COMPONENT_MAX_BYTES`; the unit test
// `path::tests::component_cap_reason_matches_constant` pins the number to that
// constant so the two cannot drift.
reasons! {
    archive_path_reason_is_valid => UNSAFE_PATH_ALL {
        PATH_ABSOLUTE = "absolute";
        COMPONENT_ENDS_WITH_DOT = "component ends with dot";
        COMPONENT_ENDS_WITH_SPACE = "component ends with space";
        COMPONENT_TOO_LONG = "component exceeds 244 bytes";
        COMPONENT_CONTROL_BYTE = "contains ASCII control byte";
        COMPONENT_FORMAT_CONTROL = "contains a control, text-direction, or line-break character";
        COMPONENT_RESERVED_CHARACTER = "contains a Windows-reserved character";
        PATH_CONTAINS_BACKSLASH = "contains backslash";
        PATH_CONTAINS_NUL = "contains NUL byte";
        COMPONENT_FORBIDDEN = "forbidden component";
        PATH_NON_NORMAL_COMPONENT = "non-normal host path component";
        PATH_REPEATED_SLASHES = "repeated slash separators";
        PATH_TRAILING_SLASH = "trailing slash";
        COMPONENT_RESERVED_DEVICE_NAME = "Windows-reserved device name";
    }
}

reasons! {
    archive_path_reason_is_valid => INVALID_TREE_ALL {
        TREE_CHILD_UNDER_FILE = "child under a file path";
        TREE_DUPLICATE_ENTRY = "duplicate entry";
        TREE_DUPLICATE_ASCII_CASE = "duplicate entry differing only in letter case";
        TREE_DUPLICATE_UNICODE_FORM = "duplicate entry differing only in Unicode form";
        TREE_MULTIPLE_ROOTS = "multiple top-level roots";
        TREE_PARENT_MISSING = "parent directory is missing";
        TREE_ROOT_MISSING = "root entry is missing";
        TREE_ROOT_FILE_HAS_CHILDREN = "root file has child entries";
    }
}
