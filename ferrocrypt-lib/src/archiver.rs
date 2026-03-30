use std::borrow::Cow;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;

use walkdir::WalkDir;
use zip::result::ZipError;
use zip::write::FileOptions;

use crate::CryptoError;
use crate::common::{get_file_stem_to_string, normalize_paths};

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use crate::archiver::{archive, unarchive};

    /// The unarchive function concatenates output_dir with the zip entry path
    /// without inserting a separator, so a trailing slash is required (matching
    /// how the public API normalizes paths before calling archiver functions).
    fn dir_with_slash(dir: &std::path::Path) -> String {
        format!("{}/", dir.display())
    }

    #[test]
    fn archive_and_unarchive_file() {
        let tmp = TempDir::new().unwrap();
        let input_file = tmp.path().join("hello.txt");
        let archive_dir = tmp.path().join("zipped");
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&archive_dir).unwrap();
        fs::create_dir_all(&extract_dir).unwrap();

        fs::write(&input_file, "file content here").unwrap();

        let stem = archive(&input_file, &archive_dir).unwrap();
        assert_eq!(stem, "hello");
        assert!(archive_dir.join("hello.zip").exists());

        let output =
            unarchive(archive_dir.join("hello.zip"), &dir_with_slash(&extract_dir)).unwrap();
        assert!(!output.is_empty());

        let restored = fs::read_to_string(extract_dir.join("hello.txt")).unwrap();
        assert_eq!(restored, "file content here");
    }

    #[test]
    fn archive_and_unarchive_directory() {
        let tmp = TempDir::new().unwrap();
        let input_dir = tmp.path().join("mydir");
        let sub_dir = input_dir.join("sub");
        let archive_dir = tmp.path().join("zipped");
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&sub_dir).unwrap();
        fs::create_dir_all(&archive_dir).unwrap();
        fs::create_dir_all(&extract_dir).unwrap();

        fs::write(input_dir.join("a.txt"), "file a").unwrap();
        fs::write(sub_dir.join("b.txt"), "file b").unwrap();

        let stem = archive(&input_dir, &archive_dir).unwrap();
        assert_eq!(stem, "mydir");
        assert!(archive_dir.join("mydir.zip").exists());

        let output =
            unarchive(archive_dir.join("mydir.zip"), &dir_with_slash(&extract_dir)).unwrap();
        assert!(!output.is_empty());

        let restored_a = fs::read_to_string(extract_dir.join("mydir/a.txt")).unwrap();
        assert_eq!(restored_a, "file a");
        let restored_b = fs::read_to_string(extract_dir.join("mydir/sub/b.txt")).unwrap();
        assert_eq!(restored_b, "file b");
    }

    #[test]
    fn archive_empty_file() {
        let tmp = TempDir::new().unwrap();
        let input_file = tmp.path().join("empty.txt");
        let archive_dir = tmp.path().join("zipped");
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&archive_dir).unwrap();
        fs::create_dir_all(&extract_dir).unwrap();

        fs::write(&input_file, "").unwrap();

        let stem = archive(&input_file, &archive_dir).unwrap();
        assert_eq!(stem, "empty");

        unarchive(archive_dir.join("empty.zip"), &dir_with_slash(&extract_dir)).unwrap();
        let restored = fs::read_to_string(extract_dir.join("empty.txt")).unwrap();
        assert_eq!(restored, "");
    }

    #[test]
    fn archive_binary_content() {
        let tmp = TempDir::new().unwrap();
        let input_file = tmp.path().join("data.bin");
        let archive_dir = tmp.path().join("zipped");
        let extract_dir = tmp.path().join("extracted");
        fs::create_dir_all(&archive_dir).unwrap();
        fs::create_dir_all(&extract_dir).unwrap();

        let binary_data: Vec<u8> = (0..=255).collect();
        fs::write(&input_file, &binary_data).unwrap();

        archive(&input_file, &archive_dir).unwrap();
        unarchive(archive_dir.join("data.zip"), &dir_with_slash(&extract_dir)).unwrap();

        let restored = fs::read(extract_dir.join("data.bin")).unwrap();
        assert_eq!(restored, binary_data);
    }
}

/// Archives a file or directory into a ZIP archive.
pub fn archive(
    input_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
) -> Result<String, CryptoError> {
    if input_path.as_ref().is_file() {
        archive_file(input_path, output_dir)
    } else {
        archive_dir(input_path, output_dir)
    }
}

fn archive_file(
    input_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
) -> Result<String, CryptoError> {
    let input_path = input_path.as_ref();
    let output_dir = output_dir.as_ref();

    let file_name_extension = input_path
        .file_name()
        .ok_or_else(|| ZipError::InvalidArchive(Cow::from("Cannot get file name")))?
        .to_str()
        .ok_or_else(|| ZipError::InvalidArchive(Cow::from("Cannot convert file name to &str")))?;

    let file_stem = &get_file_stem_to_string(input_path)?;

    println!(
        "Adding file {:?} as {:?}/{} ...",
        input_path,
        output_dir.join(file_stem),
        file_name_extension
    );

    let output_file = File::create(output_dir.join(format!("{}.zip", file_stem)))?;
    let mut zip = zip::ZipWriter::new(output_file);

    let options: FileOptions<()> = FileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .large_file(true)
        .unix_permissions(0o755); // sets options for the zip file

    let mut buffer = Vec::new();

    zip.start_file(file_name_extension, options)?;

    let mut f = File::open(input_path)?;

    f.read_to_end(&mut buffer)?;
    zip.write_all(&buffer)?;
    buffer.clear();

    zip.finish()?;

    Ok(file_stem.to_string())
}

fn archive_dir(
    input_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
) -> Result<String, CryptoError> {
    let input_path = input_path.as_ref();
    let output_dir = output_dir.as_ref();

    let dir_name = input_path
        .file_name()
        .ok_or_else(|| CryptoError::InputPath("Input file or folder missing".to_string()))?
        .to_str()
        .ok_or_else(|| {
            ZipError::InvalidArchive(Cow::from("Cannot convert directory name to &str"))
        })?;

    let output_zip_path = output_dir.join(format!("{}.zip", dir_name));
    let file = File::create(output_zip_path)?;
    let mut zip = zip::ZipWriter::new(file);
    let options: FileOptions<()> = FileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .large_file(true)
        .unix_permissions(0o755);
    let walkdir = WalkDir::new(input_path);
    let mut buffer = Vec::new();

    for entry in walkdir {
        let entry = entry?;
        let path = entry.path();
        let name = path
            .strip_prefix(input_path)
            .map_err(|err| CryptoError::Message(format!("StripPrefixError: {:?}", err)))?;
        let path_str = path
            .to_str()
            .ok_or_else(|| ZipError::InvalidArchive(Cow::from("Cannot convert path to &str")))?;
        let normalized_path_str = &normalize_paths(path_str, "").0;
        let name_str = name
            .to_str()
            .ok_or_else(|| ZipError::InvalidArchive(Cow::from("Cannot convert name to &str")))?;
        let output_path_str = format!("{}/{}", dir_name, name_str);
        let normalized_output_path_str = &normalize_paths(&output_path_str, "").0;

        if path.is_file() {
            println!(
                "Adding file {} as {} ...",
                normalized_path_str, normalized_output_path_str
            );
            zip.start_file(&output_path_str, options)?;
            let mut f = File::open(path)?;

            f.read_to_end(&mut buffer)?;
            zip.write_all(&buffer)?;
            buffer.clear();
        } else if !output_path_str.is_empty() {
            println!(
                "Adding dir {} as {} ...",
                normalized_path_str, normalized_output_path_str
            );
            zip.add_directory(&output_path_str, options)?;
        }
    }

    zip.finish()?;

    Ok(dir_name.to_string())
}

/// Extracts a ZIP archive to a specified directory.
pub fn unarchive(
    input_path: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
) -> Result<String, CryptoError> {
    let output_dir = output_dir.as_ref();
    let file = File::open(input_path.as_ref())?;
    let mut archive = zip::ZipArchive::new(file)?;

    let first_entry = archive.by_index(0)?;
    let first_name = first_entry
        .enclosed_name()
        .ok_or_else(|| CryptoError::Message("Invalid archive entry".to_string()))?;
    let first_name_str = first_name
        .to_str()
        .ok_or_else(|| ZipError::InvalidArchive(Cow::from("Cannot convert path to &str")))?;
    let output_path = normalize_paths(&format!("{}{}", output_dir.display(), first_name_str), "").0;
    let output_path_check = Path::new(&output_path);
    if output_path_check.exists() {
        return Err(CryptoError::Message(format!(
            "Output already exists: {}",
            output_path
        )));
    }
    drop(first_entry);

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = match file.enclosed_name() {
            Some(path) => path,
            None => continue,
        };
        let outpath_str = outpath
            .to_str()
            .ok_or_else(|| ZipError::InvalidArchive(Cow::from("Cannot convert path to &str")))?;
        let outpath_full_str =
            normalize_paths(&format!("{}{}", output_dir.display(), outpath_str), "").0;
        let outpath_full = Path::new(&outpath_full_str);

        {
            let comment = file.comment();
            if !comment.is_empty() {
                println!("File {} comment: {}", i, comment);
            }
        }

        if (*file.name()).ends_with('/') {
            println!("Extracting dir to \"{}\" ...", &outpath_full_str);
            fs::create_dir_all(outpath_full)?;
        } else {
            println!(
                "Extracting file to \"{}\" ({} bytes) ...",
                &outpath_full_str,
                file.size()
            );
            if let Some(p) = outpath_full.parent() {
                if !p.exists() {
                    fs::create_dir_all(p)?;
                }
            }
            let mut outfile = File::create(outpath_full)?;
            io::copy(&mut file, &mut outfile)?;
        }
    }

    Ok(output_path)
}
