use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use memmap2::MmapOptions;

const MMAP_THRESHOLD: u64 = 1_048_576;

pub enum FileContent {
    Small(Vec<u8>),
    Mapped(memmap2::Mmap),
    Streaming(Vec<u8>),
}

impl AsRef<[u8]> for FileContent {
    fn as_ref(&self) -> &[u8] {
        match self {
            FileContent::Small(v) | FileContent::Streaming(v) => v,
            FileContent::Mapped(m) => m,
        }
    }
}

#[must_use]
pub fn is_binary(content: &[u8]) -> bool {
    if let Some(kind) = infer::get(content) {
        let mime = kind.mime_type();
        if mime.starts_with("image/")
            || mime.starts_with("video/")
            || mime.starts_with("audio/")
            || mime.starts_with("application/zip")
            || mime.starts_with("application/gzip")
            || mime.starts_with("application/pdf")
            || mime.starts_with("application/x-executable")
        {
            return true;
        }
    }

    content.iter().take(8192).any(|&b| b == 0)
}

fn is_binary_quick(path: &Path) -> bool {
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    let mut buf = [0u8; 512];
    let n = file.read(&mut buf).unwrap_or(0);
    if n == 0 {
        return false;
    }
    is_binary(&buf[..n])
}

pub fn read_file_content(
    path: &Path,
    max_size: u64,
    streaming_threshold: u64,
) -> Option<FileContent> {
    let metadata = path.metadata().ok()?;
    let size = metadata.len();

    if size > max_size {
        return None;
    }

    if is_binary_quick(path) {
        return None;
    }

    if size > streaming_threshold {
        let file = File::open(path).ok()?;
        let reader = BufReader::new(file);
        let mut content = Vec::new();
        for l in reader.lines() {
            let Ok(l) = l else { break };
            content.extend_from_slice(l.as_bytes());
            content.push(b'\n');
        }
        return Some(FileContent::Streaming(content));
    }

    if size > MMAP_THRESHOLD {
        let file = File::open(path).ok()?;
        // SAFETY: File is opened read-only and not modified during scan
        let mmap = unsafe { MmapOptions::new().map(&file).ok()? };
        return Some(FileContent::Mapped(mmap));
    }

    std::fs::read(path).ok().map(FileContent::Small)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_is_binary_text() {
        assert!(!is_binary(b"Hello, world!\nThis is text.\n"));
    }

    #[test]
    fn test_is_binary_null_bytes() {
        assert!(is_binary(b"Hello\x00World"));
    }

    #[test]
    fn test_is_binary_empty() {
        assert!(!is_binary(b""));
    }

    #[test]
    fn test_read_file_content_small() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("small.txt");
        fs::write(&path, "hello world").unwrap();
        let content = read_file_content(&path, 10 * 1024 * 1024, 5 * 1024 * 1024);
        assert!(content.is_some());
        assert_eq!(content.unwrap().as_ref(), b"hello world");
    }

    #[test]
    fn test_read_file_content_exceeds_max_size() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("large.txt");
        fs::write(&path, "x".repeat(1000)).unwrap();
        // max_size = 500 bytes
        let content = read_file_content(&path, 500, 5 * 1024 * 1024);
        assert!(content.is_none());
    }

    #[test]
    fn test_read_file_content_nonexistent() {
        let content = read_file_content(
            Path::new("/nonexistent/file.txt"),
            10 * 1024 * 1024,
            5 * 1024 * 1024,
        );
        assert!(content.is_none());
    }

    #[test]
    fn test_read_file_content_binary_skipped() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("binary.dat");
        let mut data = vec![0u8; 512];
        data[0] = 0x89; // PNG magic-ish
        data[1] = 0x50;
        data[2] = 0x4E;
        data[3] = 0x47;
        fs::write(&path, &data).unwrap();
        let content = read_file_content(&path, 10 * 1024 * 1024, 5 * 1024 * 1024);
        assert!(content.is_none());
    }

    #[test]
    fn test_read_file_content_mmap_threshold() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("mmap.txt");
        // Create file larger than MMAP_THRESHOLD (1MB)
        let data = "a".repeat(1_100_000);
        fs::write(&path, &data).unwrap();
        let content = read_file_content(&path, 10 * 1024 * 1024, 50 * 1024 * 1024);
        assert!(content.is_some());
        let c = content.unwrap();
        assert!(matches!(c, FileContent::Mapped(_)));
        assert_eq!(c.as_ref().len(), 1_100_000);
    }

    #[test]
    fn test_read_file_content_streaming() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("stream.txt");
        // streaming_threshold = 500 bytes, file is 1000
        let data = "line\n".repeat(200);
        fs::write(&path, &data).unwrap();
        let content = read_file_content(&path, 10 * 1024 * 1024, 500);
        assert!(content.is_some());
        let c = content.unwrap();
        assert!(matches!(c, FileContent::Streaming(_)));
    }

    #[test]
    fn test_file_content_as_ref() {
        let small = FileContent::Small(b"hello".to_vec());
        assert_eq!(small.as_ref(), b"hello");

        let streaming = FileContent::Streaming(b"world".to_vec());
        assert_eq!(streaming.as_ref(), b"world");
    }
}
