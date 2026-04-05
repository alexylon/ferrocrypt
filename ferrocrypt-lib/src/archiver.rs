use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path};

use crate::CryptoError;
use crate::common::normalize_paths;

/// Rejects paths that could escape the output directory (path traversal).
pub(crate) fn validate_archive_path(path: &Path) -> Result<(), CryptoError> {
    for component in path.components() {
        match component {
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(CryptoError::Message(format!(
                    "Unsafe path in archive: {}",
                    path.display()
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Archives a file or directory into a TAR stream written to `writer`.
/// Returns a tuple of the file stem (base name without extension for files,
/// directory name for directories) and the writer, so the caller can finalize it.
pub fn archive<W: Write>(
    input_path: impl AsRef<Path>,
    writer: W,
) -> Result<(String, W), CryptoError> {
    let input_path = input_path.as_ref();
    let mut builder = tar::Builder::new(writer);

    let stem = if input_path.is_file() {
        let file_name = input_path
            .file_name()
            .ok_or_else(|| CryptoError::Message("Cannot get file name".to_string()))?;
        let file_name_str = file_name
            .to_str()
            .ok_or_else(|| CryptoError::Message("Cannot convert file name to &str".to_string()))?;

        let metadata = fs::metadata(input_path)?;
        let mut header = tar::Header::new_gnu();
        header.set_size(metadata.len());
        header.set_mode(0o755);
        header.set_cksum();
        let mut file = File::open(input_path)?;
        builder.append_data(&mut header, file_name_str, &mut file)?;

        input_path
            .file_stem()
            .ok_or_else(|| CryptoError::Message("Cannot get file stem".to_string()))?
            .to_str()
            .ok_or_else(|| CryptoError::Message("Cannot convert file stem to &str".to_string()))?
            .to_string()
    } else {
        let dir_name = input_path
            .file_name()
            .ok_or_else(|| CryptoError::InputPath("Input file or folder missing".to_string()))?
            .to_str()
            .ok_or_else(|| {
                CryptoError::Message("Cannot convert directory name to &str".to_string())
            })?;

        builder.append_dir_all(dir_name, input_path)?;
        dir_name.to_string()
    };

    let writer = builder.into_inner()?;
    Ok((stem, writer))
}

/// Extracts a TAR archive from `reader` into the specified directory.
/// Checks that the output path does not already exist before extracting.
/// Returns the output path as a string.
pub fn unarchive<R: Read>(reader: R, output_dir: &str) -> Result<String, CryptoError> {
    let mut archive = tar::Archive::new(reader);
    let mut first_entry_root: Option<String> = None;
    let mut checked_roots: Vec<String> = Vec::new();

    for entry_result in archive.entries()? {
        let mut entry = entry_result?;
        let path = entry.path()?.to_path_buf();
        validate_archive_path(&path)?;

        let first_component = path
            .components()
            .next()
            .ok_or_else(|| CryptoError::Message("Empty archive entry".to_string()))?;
        let root_name = first_component
            .as_os_str()
            .to_str()
            .ok_or_else(|| CryptoError::Message("Invalid path in archive".to_string()))?
            .to_string();

        if !checked_roots.contains(&root_name) {
            let full_path = normalize_paths(&format!("{}{}", output_dir, root_name), "").0;
            if Path::new(&full_path).exists() {
                return Err(CryptoError::Message(format!(
                    "Output already exists: {}\n",
                    full_path
                )));
            }
            if first_entry_root.is_none() {
                first_entry_root = Some(full_path);
            }
            checked_roots.push(root_name);
        }

        let full_path = Path::new(output_dir).join(&path);
        let entry_type = entry.header().entry_type();

        if entry_type.is_dir() {
            fs::create_dir_all(&full_path)?;
        } else if entry_type.is_file() {
            if let Some(parent) = full_path.parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent)?;
                }
            }
            let mut outfile = File::create(&full_path)?;
            io::copy(&mut entry, &mut outfile)?;
        }
    }

    first_entry_root.ok_or_else(|| CryptoError::Message("Empty archive".to_string()))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Cursor;

    use crate::archiver::{archive, unarchive};

    #[test]
    fn archive_and_unarchive_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let input_file = tmp.path().join("hello.txt");
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();
        fs::write(&input_file, "file content here").unwrap();

        let mut buf = Vec::new();
        let (stem, _) = archive(&input_file, &mut buf).unwrap();
        assert_eq!(stem, "hello");

        let output_dir = format!("{}/", extract_dir.display());
        let output = unarchive(Cursor::new(buf), &output_dir).unwrap();
        assert!(!output.is_empty());

        let restored = fs::read_to_string(extract_dir.join("hello.txt")).unwrap();
        assert_eq!(restored, "file content here");
    }

    #[test]
    fn archive_and_unarchive_directory() {
        let tmp = tempfile::TempDir::new().unwrap();
        let input_dir = tmp.path().join("mydir");
        let sub_dir = input_dir.join("sub");
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&sub_dir).unwrap();
        fs::create_dir_all(&extract_dir).unwrap();

        fs::write(input_dir.join("a.txt"), "file a").unwrap();
        fs::write(sub_dir.join("b.txt"), "file b").unwrap();

        let mut buf = Vec::new();
        let (stem, _) = archive(&input_dir, &mut buf).unwrap();
        assert_eq!(stem, "mydir");

        let output_dir = format!("{}/", extract_dir.display());
        let output = unarchive(Cursor::new(buf), &output_dir).unwrap();
        assert!(!output.is_empty());

        let restored_a = fs::read_to_string(extract_dir.join("mydir/a.txt")).unwrap();
        assert_eq!(restored_a, "file a");
        let restored_b = fs::read_to_string(extract_dir.join("mydir/sub/b.txt")).unwrap();
        assert_eq!(restored_b, "file b");
    }

    #[test]
    fn archive_empty_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let input_file = tmp.path().join("empty.txt");
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();
        fs::write(&input_file, "").unwrap();

        let mut buf = Vec::new();
        let (stem, _) = archive(&input_file, &mut buf).unwrap();
        assert_eq!(stem, "empty");

        let output_dir = format!("{}/", extract_dir.display());
        unarchive(Cursor::new(buf), &output_dir).unwrap();
        let restored = fs::read_to_string(extract_dir.join("empty.txt")).unwrap();
        assert_eq!(restored, "");
    }

    #[test]
    fn validate_rejects_path_traversal() {
        use crate::archiver::validate_archive_path;
        use std::path::Path;

        assert!(validate_archive_path(Path::new("safe.txt")).is_ok());
        assert!(validate_archive_path(Path::new("dir/file.txt")).is_ok());
        assert!(validate_archive_path(Path::new("../escape.txt")).is_err());
        assert!(validate_archive_path(Path::new("dir/../../escape.txt")).is_err());
        assert!(validate_archive_path(Path::new("/etc/passwd")).is_err());
    }

    #[test]
    fn unarchive_rejects_second_root_that_conflicts() {
        // Craft a TAR with two top-level roots: "innocent/" and "victim.txt".
        // Pre-create "victim.txt" in the extract dir to prove the second root
        // is checked and the extraction is refused.
        let tmp = tempfile::TempDir::new().unwrap();
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();
        fs::write(extract_dir.join("victim.txt"), "original").unwrap();

        let mut buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut buf);

            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, "innocent/", &[] as &[u8])
                .unwrap();

            let data = b"malicious payload";
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "victim.txt", &data[..])
                .unwrap();

            builder.finish().unwrap();
        }

        let output_dir = format!("{}/", extract_dir.display());
        let err = unarchive(Cursor::new(buf), &output_dir).unwrap_err();
        assert!(
            err.to_string().contains("Output already exists"),
            "expected conflict error, got: {err}"
        );

        // Verify the original file was NOT overwritten
        let content = fs::read_to_string(extract_dir.join("victim.txt")).unwrap();
        assert_eq!(content, "original");
    }

    #[test]
    fn archive_binary_content() {
        let tmp = tempfile::TempDir::new().unwrap();
        let input_file = tmp.path().join("data.bin");
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        let binary_data: Vec<u8> = (0..=255).collect();
        fs::write(&input_file, &binary_data).unwrap();

        let mut buf = Vec::new();
        let (_, _) = archive(&input_file, &mut buf).unwrap();

        let output_dir = format!("{}/", extract_dir.display());
        unarchive(Cursor::new(buf), &output_dir).unwrap();

        let restored = fs::read(extract_dir.join("data.bin")).unwrap();
        assert_eq!(restored, binary_data);
    }
}
