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
    use crate::archiver::{archive, unarchive};

    const SRC_FILEPATH: &str = "src/test_files/test-file.txt";
    const SRC_DIRPATH: &str = "src/test_files/test-folder";
    const DEST_DIRPATH: &str = "src/dest/";
    const SRC_FILEPATH_ZIPPED: &str = "src/dest/test-file.zip";
    const SRC_DIRPATH_ZIPPED: &str = "src/dest/test-folder.zip";

    #[test]
    fn archive_file_test() {
        match archive(SRC_FILEPATH, DEST_DIRPATH) {
            Ok(_) => println!("Zipped {}", SRC_FILEPATH),
            Err(e) => println!("Error: {:?}", e),
        }
    }

    #[test]
    fn unarchive_file_test() {
        match unarchive(SRC_FILEPATH_ZIPPED, DEST_DIRPATH) {
            Ok(_) => println!("Unzipped: {}", SRC_FILEPATH_ZIPPED),
            Err(e) => println!("Error: {:?}", e),
        }
    }

    #[test]
    fn archive_dir_test() {
        match archive(SRC_DIRPATH, DEST_DIRPATH) {
            Ok(_) => println!("Zipped {}", SRC_DIRPATH),
            Err(e) => println!("Error: {:?}", e),
        }
    }

    #[test]
    fn unarchive_dir_test() {
        match unarchive(SRC_DIRPATH_ZIPPED, DEST_DIRPATH) {
            Ok(_) => println!("Unzipped: {}", SRC_DIRPATH_ZIPPED),
            Err(e) => println!("Error: {:?}", e),
        }
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
    let iterator = walkdir.into_iter().filter_map(|e| e.ok());
    let mut buffer = Vec::new();

    for entry in iterator {
        let path = entry.path();
        match path.strip_prefix(input_path) {
            Ok(name) => {
                let path_str = path.to_str().ok_or_else(|| {
                    ZipError::InvalidArchive(Cow::from("Cannot convert path to &str"))
                })?;
                let normalized_path_str = &normalize_paths(path_str, "").0;
                let name_str = name.to_str().ok_or_else(|| {
                    ZipError::InvalidArchive(Cow::from("Cannot convert name to &str"))
                })?;
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
            Err(err) => println!("StripPrefixError: {:?}", err),
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
    let mut output_path = String::new();

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
        if i == 0 {
            output_path = outpath_full_str.clone();
        }
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
