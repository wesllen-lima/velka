use std::fs::File;
use std::path::Path;

use memmap2::MmapOptions;

const MMAP_THRESHOLD: u64 = 1_048_576;

pub enum FileContent {
    Small(Vec<u8>),
    Mapped(memmap2::Mmap),
}

impl AsRef<[u8]> for FileContent {
    fn as_ref(&self) -> &[u8] {
        match self {
            FileContent::Small(v) => v,
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

pub fn read_file_content(path: &Path, max_size: u64) -> Option<FileContent> {
    let metadata = path.metadata().ok()?;
    let size = metadata.len();

    if size > max_size {
        return None;
    }

    if size > MMAP_THRESHOLD {
        let file = File::open(path).ok()?;
        // SAFETY: File is opened read-only and not modified during scan
        let mmap = unsafe { MmapOptions::new().map(&file).ok()? };
        return Some(FileContent::Mapped(mmap));
    }

    std::fs::read(path).ok().map(FileContent::Small)
}
